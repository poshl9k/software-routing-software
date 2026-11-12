#!/bin/bash
# Install the vs_master master portal on a dedicated Debian 13 VPS (ADR-0035).
# Invoked by get-master.sh from the pinned release bundle; artifacts live next
# to this script. Idempotent: reruns update artifacts and restart units.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
APP_USER=vs-master-web
APP_GROUP=vs-master-web
BASE=/var/lib/vs-router/master
ETC=/etc/vs-router
VENV=/opt/vs-master/venv

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
# The bundle ships the exact commit it was built from; print it so an operator
# (and the deploy log) can tell which code is on the host.
if [ -f "$SCRIPT_DIR/REVISION" ]; then
    echo "vs-master bundle commit: $(cat "$SCRIPT_DIR/REVISION")"
fi
if [ -e "$BASE/vs-master.db" ] && \
    { [ ! -f "$ETC/master.env" ] || ! grep -q '^VS_ROUTER_SECRET_KEY=' "$ETC/master.env"; }; then
    echo "existing master DB requires its original key in $ETC/master.env; refusing to replace it" >&2
    exit 1
fi

# Keep the master runtime separate from the panel's system Python.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-venv ca-certificates acl curl >/dev/null

if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/vs-router --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$BASE" "$BASE/ui"
install -d -m 0700 -o "$APP_USER" -g "$APP_GROUP" "$BASE/backups"
# The panel's parent data directory may be 0770 vs-router-web. Grant only
# traversal to this separate user; do not expose panel DBs or change its group.
setfacl -m "u:$APP_USER:--x" "$(dirname "$BASE")"
runuser -u "$APP_USER" -- test -w "$BASE"
install -d -m 0755 -o root -g root /opt/vs-master
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --require-hashes -r "$SCRIPT_DIR/requirements-runtime.txt"
"$VENV/bin/python" -m pip install --no-deps --force-reinstall \
    "$SCRIPT_DIR"/vs_router_backend-*-py3-none-any.whl

# Master-only secret: do not change the panel's environment or encryption key.
if [ ! -d "$ETC" ]; then install -d -m 0700 -o root -g root "$ETC"; fi
touch "$ETC/master.env"; chmod 0600 "$ETC/master.env"
if ! grep -q '^VS_ROUTER_SECRET_KEY=' "$ETC/master.env" 2>/dev/null; then
    echo "VS_ROUTER_SECRET_KEY=$(python3 -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')" >> "$ETC/master.env"
fi

# Migrations run as root; hand the DB to the service user afterwards.
if [ -f "$BASE/vs-master.db" ]; then
    backup="$BASE/backups/preinstall-$(date -u +%Y%m%dT%H%M%SZ)-$$.db"
    "$VENV/bin/python" - "$BASE/vs-master.db" "$backup" <<'PY'
import os
import sqlite3
import sys

source = sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True)
temporary = sys.argv[2] + '.tmp'
try:
    target = sqlite3.connect(temporary)
    try:
        source.backup(target)
        if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('pre-migration SQLite backup failed integrity check')
    finally:
        target.close()
    os.chmod(temporary, 0o600)
    os.replace(temporary, sys.argv[2])
finally:
    source.close()
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
    chown "$APP_USER":"$APP_GROUP" "$backup"
    echo "pre-migration master DB backup: $backup"
fi
VS_MASTER_DATABASE_URL="sqlite:///$BASE/vs-master.db" \
    "$VENV/bin/python" -m alembic -c "$SCRIPT_DIR/alembic-master/alembic.ini" upgrade head
for db_file in "$BASE/vs-master.db" "$BASE/vs-master.db-wal" "$BASE/vs-master.db-shm"; do
    [ -e "$db_file" ] || continue
    chown "$APP_USER":"$APP_GROUP" "$db_file"
    chmod 0660 "$db_file"
done

rm -rf "$BASE/ui"
cp -a "$SCRIPT_DIR/ui" "$BASE/ui"
chown -R "$APP_USER":"$APP_GROUP" "$BASE/ui"

install -m 0644 "$SCRIPT_DIR/vs-master-web.service" /etc/systemd/system/vs-master-web.service
install -m 0644 "$SCRIPT_DIR/vs-master-worker.service" /etc/systemd/system/vs-master-worker.service
install -m 0644 "$SCRIPT_DIR/vs-master-bot.service" /etc/systemd/system/vs-master-bot.service
install -m 0644 "$SCRIPT_DIR/vs-master-backup.service" /etc/systemd/system/vs-master-backup.service
install -m 0644 "$SCRIPT_DIR/vs-master-backup.timer" /etc/systemd/system/vs-master-backup.timer
systemctl daemon-reload
systemctl enable --now vs-master-web.service
systemctl restart vs-master-web.service
systemctl enable --now vs-master-worker.service
systemctl restart vs-master-worker.service
systemctl enable vs-master-bot.service
if [ "${VS_MASTER_SKIP_ACTIVE_BOT_RESTART:-0}" = 1 ] && \
    systemctl is-active --quiet vs-master-bot.service; then
    echo "vs-master-bot is already active; restart skipped by operator"
else
    systemctl restart vs-master-bot.service
fi
systemctl enable --now vs-master-backup.timer

# This host may already serve the panel. Never replace or reload its Caddyfile.
# The supplied fragment is an example: adapt hostnames, merge and validate it
# separately after inspecting the running reverse proxy.
install -m 0644 "$SCRIPT_DIR/caddy-master.conf" "$BASE/caddy-master.example"

systemctl is-active --quiet vs-master-web.service || { journalctl -u vs-master-web -n 20 --no-pager; exit 1; }
systemctl is-active --quiet vs-master-worker.service || { journalctl -u vs-master-worker -n 20 --no-pager; exit 1; }
systemctl is-active --quiet vs-master-bot.service || { journalctl -u vs-master-bot -n 20 --no-pager; exit 1; }
ready=0
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1:8440/health >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" = 1 ] || { journalctl -u vs-master-web -n 20 --no-pager; exit 1; }
echo "vs-master installed; probe: curl http://127.0.0.1:8440/health"
echo "Caddy was not modified; review $BASE/caddy-master.example before publishing"
