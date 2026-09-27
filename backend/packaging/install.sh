#!/bin/sh
# Install after installing the Python package and its system dependencies.
# Requires: kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor
# (validators: nft -c, unbound-checkconf, kea-dhcp4 -t must be on PATH).
# Tunnel templates start wg-go/awg-go with the interface name; ExecStartPost
# feeds setconf only after UAPI is ready. Install both binaries in /usr/local/bin
# (wireguard-go may be symlinked as wg-go), and wg/awg tools on PATH.
# Caddy must include caddy-l4 and caddy-dns/cloudflare; its service must run
# `caddy run --config /etc/caddy/caddy.json` (JSON, never Caddyfile).
# Set VS_ROUTER_SECRET_KEY in the web API and agent service environments using a protected
# EnvironmentFile; never put the encryption key into generated bundles.
set -eu
install -d -m 0750 /etc/caddy/vs-router
chown root:caddy /etc/caddy/vs-router
install -d -m 0700 /etc/vs-router/wireguard
install -d -m 0755 /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/vs-router.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/caddy run --config /etc/caddy/caddy.json
ExecReload=
ExecReload=/usr/bin/caddy reload --config /etc/caddy/caddy.json
EOF
id vs-router-web >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vs-router --shell /usr/sbin/nologin vs-router-web
install -d -m 0770 /etc/vs-router /etc/vs-router/applied /etc/vs-router/confirmed
chgrp vs-router-web /etc/vs-router /etc/vs-router/applied /etc/vs-router/confirmed
install -d -m 0770 /run/vs-router
chgrp vs-router-web /run/vs-router
install -d -m 0770 -o vs-router-web -g vs-router-web /run/vs-router/web /var/lib/vs-router
packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -m 0644 "$packaging_dir"/*.service "$packaging_dir"/*.timer /etc/systemd/system/
install -m 0644 "$packaging_dir/vs-router.conf" /etc/tmpfiles.d/vs-router.conf
# Web DB must be writable by both the web user (owner) and the agent (group).
DB=/var/lib/vs-router/vs-router.db
if [ ! -f "$DB" ]; then
    install -m 0660 -o vs-router-web -g vs-router-web /dev/null "$DB"
    cd "$(dirname -- "$packaging_dir")"
    python3 -m alembic -n vsrouter upgrade head 2>/dev/null || \
      VS_ROUTER_DATABASE_URL="sqlite:///$DB" python3 -m alembic upgrade head
    chown vs-router-web:vs-router-web "$DB"
    chmod 0660 "$DB"
fi
# AppArmor: allow kea-dhcp4 to read our staged configs during validation.
if command -v apparmor_parser >/dev/null 2>&1 && [ -f /etc/apparmor.d/usr.sbin.kea-dhcp4 ]; then
    local_profile=/etc/apparmor.d/local/usr.sbin.kea-dhcp4
    grep -qs "/run/vs-router/\*\*" "$local_profile" 2>/dev/null || echo "/run/vs-router/** r," >> "$local_profile"
    include_line=$(grep -c "include <local/usr.sbin.kea-dhcp4>" /etc/apparmor.d/usr.sbin.kea-dhcp4 || true)
    if [ "${include_line:-0}" = "0" ]; then
        sed -i "s|#include <local/usr.sbin.kea-dhcp4>|include <local/usr.sbin.kea-dhcp4>|" /etc/apparmor.d/usr.sbin.kea-dhcp4
    fi
    apparmor_parser -r /etc/apparmor.d/usr.sbin.kea-dhcp4 2>/dev/null || true
fi
# Unbound rereads the include as its unprivileged service user on HUP.
# Allow traversal only; other generated files retain their private modes.
chmod o+x /etc/vs-router /etc/vs-router/applied
if [ -d /etc/unbound ]; then
    install -d -m 0755 /etc/unbound/unbound.conf.d
    printf '%s\n' 'include: "/etc/vs-router/applied/unbound.conf"' > /etc/unbound/unbound.conf.d/vs-router.conf
    chmod 0644 /etc/unbound/unbound.conf.d/vs-router.conf
    if [ -f /etc/vs-router/applied/unbound.conf ]; then
        chmod 0644 /etc/vs-router/applied/unbound.conf
    fi
fi
# Allow the included configuration through Unbound's optional AppArmor profile.
if command -v apparmor_parser >/dev/null 2>&1 && [ -f /etc/apparmor.d/usr.sbin.unbound ]; then
    install -d /etc/apparmor.d/local
    local_profile=/etc/apparmor.d/local/usr.sbin.unbound
    grep -qsF '/etc/vs-router/applied/unbound.conf r,' "$local_profile" 2>/dev/null || \
        echo '/etc/vs-router/applied/unbound.conf r,' >> "$local_profile"
    apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound
fi
# Web UI static bundle: deploy ../frontend/dist (sibling of backend/) when present.
# Panel runs API-only if the UI is not built yet (no crash on missing assets).
UI_SRC=$(dirname -- "$packaging_dir")/../frontend/dist
if [ -d "$UI_SRC" ] && [ -f "$UI_SRC/index.html" ]; then
    install -d -m 0755 /var/lib/vs-router/ui
    rm -rf /var/lib/vs-router/ui.new
    cp -a "$UI_SRC" /var/lib/vs-router/ui.new
    rm -rf /var/lib/vs-router/ui
    mv /var/lib/vs-router/ui.new /var/lib/vs-router/ui
    chmod -R a+rX /var/lib/vs-router/ui
fi
# Lab-only TCP bridge to the unix socket. Not for production: in production the
# panel is reached over HTTPS through Caddy. Enable manually when needed:
#   systemctl enable --now vs-router-web-tcp.service
systemctl enable vs-router-bootrestore.service 2>/dev/null || true
systemctl daemon-reload
