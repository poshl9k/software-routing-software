#!/bin/sh
# Install after installing the Python package and its system dependencies.
# Requires: kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor
# (validators: nft -c, unbound-checkconf, kea-dhcp4 -t must be on PATH).
# Tunnel templates start wg-go/awg-go with the interface name; ExecStartPost
# feeds setconf only after UAPI is ready. Install both binaries in /usr/local/bin
# (wireguard-go may be symlinked as wg-go), and wg/awg tools on PATH.
# AmneziaWG must be 3.1+ (obfuscation parameters Jc/Jmin/Jmax/S1/S2/H1-H4 and
# client profile compatibility are validated against 3.1).
# Caddy must include caddy-l4 and caddy-dns/cloudflare; its service must run
# `caddy run --config /etc/caddy/caddy.json` (JSON, never Caddyfile).
# Set VS_ROUTER_SECRET_KEY in the web API and agent service environments using a protected
# EnvironmentFile; never put the encryption key into generated bundles.
set -eu
umask 022
# Listener remains closed until the agent has installed the interface firewall.
systemctl mask ssh.service ssh.socket
systemctl stop ssh.service ssh.socket
install -d -m 0700 /etc/vs-router-ssh /var/lib/vs-router-ssh /run/vs-router-ssh
install -d -m 0755 /etc/systemd/system/ssh.service.d
cat > /etc/systemd/system/ssh.service.d/vs-router.conf <<'EOF'
[Unit]
Requires=vs-router-bootrestore.service
After=vs-router-bootrestore.service vs-router-ssh-guard.service
BindsTo=vs-router-ssh-guard.service
ConditionPathExists=/run/vs-router-ssh/ready
[Service]
ExecStart=
ExecStart=/usr/sbin/sshd -D -f /etc/vs-router-ssh/sshd_config
ExecStartPre=
ExecStartPre=/usr/sbin/sshd -t -f /etc/vs-router-ssh/sshd_config
ExecReload=
ExecReload=/usr/sbin/sshd -t -f /etc/vs-router-ssh/sshd_config
ExecReload=/bin/kill -HUP $MAINPID
KillMode=control-group
EOF
# Caddy built from source (xcaddy) ships no user/group and no distro unit —
# create them; the binary lives wherever PATH resolves it (usually /usr/local/bin).
getent group caddy >/dev/null 2>&1 || groupadd --system caddy
id caddy >/dev/null 2>&1 || useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
CADDY_BIN=$(command -v caddy || echo /usr/local/bin/caddy)
packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -m 0750 /etc/caddy/vs-router
chown root:caddy /etc/caddy/vs-router
install -d -m 0700 /etc/vs-router/wireguard
install -d -m 0755 /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/vs-router.conf <<EOF
[Service]
ExecStart=
ExecStart=${CADDY_BIN} run --config /etc/caddy/caddy.json
ExecReload=
ExecReload=${CADDY_BIN} reload --config /etc/caddy/caddy.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF
# Self-built caddy has no distro service file; the override above only patches
# an existing unit and cannot create one.
if ! systemctl list-unit-files caddy.service --no-legend 2>/dev/null | grep -q .; then
    install -m 0644 "$packaging_dir/caddy.service" /etc/systemd/system/caddy.service
fi
# A running Caddy is required before the first apply (reload targets it).
if [ ! -f /etc/caddy/caddy.json ]; then
    printf '{"apps":{}}\n' > /etc/caddy/caddy.json
    chown root:caddy /etc/caddy/caddy.json
    chmod 0644 /etc/caddy/caddy.json
fi
systemctl daemon-reload
systemctl enable caddy
systemctl restart caddy
systemctl is-active --quiet caddy
id vs-router-web >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vs-router --shell /usr/sbin/nologin vs-router-web
# ADR-0014 / lab-37 defect 4: the TProxy DNS contour runs two Unbound processes
# under dedicated, fixed numeric UIDs. Provision both system accounts here
# (install-time, idempotent) so the agent's split units never reference a UID
# that does not exist — lab-37 failed with systemd `217/USER` because the
# accounts were absent. The UIDs are pinned and must stay equal to
# generators.tproxy_dns.TPROXY_SELECTED_UID / TPROXY_ORDINARY_UID. The split
# configs are staged 0600 and re-owned to these UIDs by each unit's privileged
# ExecStartPre (agent/unbound_service.py); /etc/vs-router and .../applied keep
# the o+x traversal bit set below so a resolver can reach its own config.
# >>> resolver-uids
provision_resolver_user() {
    name=$1 uid=$2
    if id -u "$name" >/dev/null 2>&1; then
        [ "$(id -u "$name")" = "$uid" ] || {
            echo "ERROR: ${name} exists with UID $(id -u "$name"), expected ${uid}" >&2
            exit 1
        }
    else
        useradd --system --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin --uid "$uid" "$name"
    fi
}
provision_resolver_user vs-router-unbound-selected 29092
provision_resolver_user vs-router-unbound-ordinary 29093
# <<< resolver-uids
# Caddy proxies the restricted web Unix socket, never a TCP bridge.
usermod -a -G vs-router-web caddy
install -d -m 0755 /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/management.conf <<'EOF'
[Unit]
Requires=vs-router-bootrestore.service
After=vs-router-bootrestore.service
[Service]
ExecStartPre=+/usr/bin/python3 -m vs_router.agent.management_console --check
EOF

# Warn when the installed AmneziaWG is older than the validated 3.1 line.
if command -v awg >/dev/null 2>&1 && ! awg --version 2>/dev/null | grep -q "v3\.[1-9]"; then
    echo "WARNING: amneziawg-tools 3.1+ expected (obfuscation params validated on 3.1); found:" \
        "$(awg --version 2>/dev/null | head -1)" >&2
fi
install -d -m 0770 /etc/vs-router /etc/vs-router/applied /etc/vs-router/confirmed
chgrp vs-router-web /etc/vs-router /etc/vs-router/applied /etc/vs-router/confirmed
install -d -m 0770 /run/vs-router
chgrp vs-router-web /run/vs-router
install -d -m 0770 -o vs-router-web -g vs-router-web /run/vs-router/web /var/lib/vs-router
packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -m 0644 "$packaging_dir"/*.service "$packaging_dir"/*.timer /etc/systemd/system/
install -m 0644 "$packaging_dir/vs-router.conf" /etc/tmpfiles.d/vs-router.conf
install -m 0644 "$packaging_dir/90-vs-router-forward.conf" /etc/sysctl.d/90-vs-router-forward.conf
sysctl -w net.ipv4.ip_forward=1
systemctl daemon-reload
# Web DB must be writable by both the web user (owner) and the agent (group).
DB=/var/lib/vs-router/vs-router.db
if [ ! -f "$DB" ]; then
    install -m 0660 -o vs-router-web -g vs-router-web /dev/null "$DB"
fi
# Always migrate the installed DB, including reruns. Stop writers first.
systemctl stop vs-router-web.service vs-router-agent.service
VS_ROUTER_DATABASE_URL="sqlite:///$DB" python3 -m alembic -c "$packaging_dir/../alembic.ini" upgrade head
chown vs-router-web:vs-router-web "$DB"
chmod 0660 "$DB"
# AppArmor: allow kea-dhcp4 to read our staged configs during validation.
if command -v apparmor_parser >/dev/null 2>&1 && [ -f /etc/apparmor.d/usr.sbin.kea-dhcp4 ]; then
    local_profile=/etc/apparmor.d/local/usr.sbin.kea-dhcp4
    grep -qs "/run/vs-router/\*\*" "$local_profile" 2>/dev/null || echo "/run/vs-router/** r," >> "$local_profile"
    include_line=$(grep -c "include <local/usr.sbin.kea-dhcp4>" /etc/apparmor.d/usr.sbin.kea-dhcp4 || true)
    if [ "${include_line:-0}" = "0" ]; then
        sed -i "s|#include <local/usr.sbin.kea-dhcp4>|include <local/usr.sbin.kea-dhcp4>|" /etc/apparmor.d/usr.sbin.kea-dhcp4
    fi
    apparmor_parser -r /etc/apparmor.d/usr.sbin.kea-dhcp4
fi
# Unbound rereads the include as its unprivileged service user on HUP.
# Allow traversal only; other generated files retain their private modes.
chmod o+x /etc/vs-router /etc/vs-router/applied
if [ -d /etc/unbound ]; then
    install -d -m 0755 /etc/unbound/unbound.conf.d
    if [ -f /etc/vs-router/applied/unbound.conf ]; then
        printf '%s\n' 'include: "/etc/vs-router/applied/unbound.conf"' > /etc/unbound/unbound.conf.d/vs-router.conf
        chmod 0644 /etc/unbound/unbound.conf.d/vs-router.conf
        chmod 0644 /etc/vs-router/applied/unbound.conf
    fi
fi
# Allow the included configuration through Unbound's optional AppArmor profile.
# Debian's usr.sbin.unbound confines /usr/sbin/unbound to /etc/unbound/**; the
# TProxy DNS contour (ADR-0014) reads generated split configs under
# /etc/vs-router/applied/, so the local override must grant the whole directory,
# not a single file. The stock profile already includes
# `#include <local/usr.sbin.unbound>` (an active AppArmor directive), so the
# local file must exist for the profile to reload at all: create it, add the
# directory rule once (idempotently), and reload.
if command -v apparmor_parser >/dev/null 2>&1 && [ -f /etc/apparmor.d/usr.sbin.unbound ]; then
    install -d /etc/apparmor.d/local
    local_profile=/etc/apparmor.d/local/usr.sbin.unbound
    touch "$local_profile"
    grep -qsF '/etc/vs-router/applied/** r,' "$local_profile" 2>/dev/null || \
        echo '/etc/vs-router/applied/** r,' >> "$local_profile"
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
# Record the installed release identity (pinned commit + semver) for
# GET /api/release. The commit comes from git when present, else a REVISION
# file vendored into the ISO; it stays "unknown" when neither exists.
repo_root=$(dirname -- "$packaging_dir")/..
semver=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$repo_root/backend/pyproject.toml" 2>/dev/null | head -n1)
commit=""
if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --verify -q HEAD >/dev/null 2>&1; then
    commit=$(git -C "$repo_root" rev-parse HEAD)
elif [ -f "$repo_root/REVISION" ]; then
    commit=$(tr -d '[:space:]' < "$repo_root/REVISION")
fi
[ -n "$commit" ] || commit=unknown
[ -n "$semver" ] || semver=unknown
printf '{"commit":"%s","semver":"%s","installed_at":"%s","source":"%s"}\n' \
    "$commit" "$semver" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${VS_ROUTER_RELEASE_SOURCE:-unknown}" \
    > /etc/vs-router/version.json
chmod 0644 /etc/vs-router/version.json
systemctl enable vs-router-bootrestore.service vs-router-tproxy-postboot.service
systemctl daemon-reload
systemctl restart vs-router-agent.service vs-router-web.service
systemctl is-active --quiet vs-router-agent.service
systemctl is-active --quiet vs-router-web.service
