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

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

# Debian 13 ships neither pip by default nor (always) bash tooling deps.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-pip ca-certificates >/dev/null

# Runtime deps pinned in requirements-runtime.txt (hash-verified), then the wheel --no-deps.
# Debian ships some deps (typing_extensions...) as apt packages without RECORD;
# pip must overwrite them instead of refusing.
pip install --break-system-packages --ignore-installed typing_extensions \
    -r "$SCRIPT_DIR/requirements-runtime.txt"
pip install --break-system-packages --no-deps --force-reinstall \
    "$SCRIPT_DIR"/vs_router_backend-*-py3-none-any.whl

if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/vs-router --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$BASE" "$BASE/ui"

# Application secret: generate once, never overwrite.
install -d -m 0700 root:root "$ETC"
touch "$ETC/secrets.env"; chmod 0600 "$ETC/secrets.env"
if ! grep -q '^VS_ROUTER_SECRET_KEY=' "$ETC/secrets.env" 2>/dev/null; then
    echo "VS_ROUTER_SECRET_KEY=$(python3 -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')" >> "$ETC/secrets.env"
fi

# Migrations run as root; hand the DB to the service user afterwards.
VS_MASTER_DATABASE_URL="sqlite:///$BASE/vs-master.db" \
    python3 -m alembic -c "$SCRIPT_DIR/alembic-master/alembic.ini" upgrade head
chown "$APP_USER":"$APP_GROUP" "$BASE/vs-master.db"
chmod 0660 "$BASE/vs-master.db"

rm -rf "$BASE/ui"
cp -a "$SCRIPT_DIR/ui" "$BASE/ui"
chown -R "$APP_USER":"$APP_GROUP" "$BASE/ui"

install -m 0644 "$SCRIPT_DIR/vs-master-web.service" /etc/systemd/system/vs-master-web.service
systemctl daemon-reload
systemctl enable --now vs-master-web.service
systemctl restart vs-master-web.service

# Publication: standalone Caddy outside any apply cycle (ADR-0035 D8).
if ! command -v caddy >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq caddy
fi
install -m 0644 "$SCRIPT_DIR/caddy-master.conf" /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy 2>/dev/null || systemctl restart caddy

systemctl is-active --quiet vs-master-web.service || { journalctl -u vs-master-web -n 20 --no-pager; exit 1; }
echo "vs-master installed; probe: curl http://127.0.0.1:8440/health"
