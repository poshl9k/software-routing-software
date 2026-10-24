#!/bin/bash
# Install the vs_master master portal on a dedicated Debian 13 VPS (ADR-0035).
# Run AS ROOT on the master host, with the artifacts staged next to this script:
#   vs_router_backend-<ver>-py3-none-any.whl, alembic-master/, ui/ (frontend-master dist),
#   vs-master-web.service, caddy.conf fragment rendered by the caller.
# The script is idempotent: reruns update artifacts and restart the unit.
set -euo pipefail

APP_USER=vs-master-web
APP_GROUP=vs-master-web
BASE=/var/lib/vs-router/master
ETC=/etc/vs-router

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

# Runtime deps pinned in requirements-runtime.txt (hash-verified), then the wheel --no-deps.
pip install --break-system-packages -r /root/vs-master-deploy/requirements-runtime.txt
pip install --break-system-packages --no-deps --force-reinstall \
    /root/vs-master-deploy/vs_router_backend-*-py3-none-any.whl

if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/vs-router --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$BASE" "$BASE/ui"

# Application secret: generate once, never overwrite.
if [ ! -s "$ETC/secrets.env" ] || ! grep -q '^VS_ROUTER_SECRET_KEY=' "$ETC/secrets.env" 2>/dev/null; then
    install -d -m 0700 root:root "$ETC"
    touch "$ETC/secrets.env"; chmod 0600 "$ETC/secrets.env"
    if ! grep -q '^VS_ROUTER_SECRET_KEY=' "$ETC/secrets.env"; then
        echo "VS_ROUTER_SECRET_KEY=$(python3 -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')" >> "$ETC/secrets.env"
    fi
fi

pip install --break-system-packages --no-deps --force-reinstall \
    /root/vs-master-deploy/vs_router_backend-*-py3-none-any.whl

# Migrations run as root; hand the DB to the service user afterwards.
VS_MASTER_DATABASE_URL="sqlite:///$BASE/vs-master.db" \
    python3 -m alembic -c /root/vs-master-deploy/alembic-master/alembic.ini upgrade head
chown "$APP_USER":"$APP_GROUP" "$BASE/vs-master.db" 2>/dev/null || true
chmod 0660 "$BASE/vs-master.db"

rm -rf "$BASE/ui"
cp -a /root/vs-master-deploy/ui "$BASE/ui"
chown -R "$APP_USER":"$APP_GROUP" "$BASE/ui"

install -m 0644 /root/vs-master-deploy/vs-master-web.service /etc/systemd/system/vs-master-web.service
systemctl daemon-reload
systemctl enable --now vs-master-web.service
systemctl restart vs-master-web.service

echo "vs-master installed; probe: curl http://127.0.0.1:8440/health"
