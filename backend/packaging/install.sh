#!/bin/sh
# Install after installing the Python package and its system dependencies.
# Requires: kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor
# (validators: nft -c, unbound-checkconf, kea-dhcp4 -t must be on PATH).
set -eu
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
systemctl daemon-reload
