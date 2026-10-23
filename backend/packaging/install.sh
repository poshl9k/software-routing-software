#!/bin/sh
# Install after installing the Python package and its system dependencies.
# Requires: unbound nftables apparmor ppp (validators: nft -c, unbound-checkconf).
# Kea is OPTIONAL: a host without kea-dhcp4 has no DHCP section and no `kea`
# apply phase (the panel profile installs none, ADR-0021), and everything Kea
# related below is skipped instead of failing the install.
# Tunnel templates start wg-go/awg-go with the interface name; ExecStartPost
# feeds setconf only after UAPI is ready. Install both binaries in /usr/local/bin
# (wireguard-go may be symlinked as wg-go), and wg/awg tools on PATH.
# AmneziaWG must be 3.1+ (obfuscation parameters Jc/Jmin/Jmax/S1/S2/H1-H4 and
# client profile compatibility are validated against 3.1).
# Caddy must include caddy-l4 and caddy-dns/cloudflare; its service must run
# `caddy run --config /etc/caddy/caddy.json` (JSON, never Caddyfile).
# Provision the shared web/agent encryption key once in a protected EnvironmentFile;
# never rotate it on updates or put it into generated bundles.
set -eu
umask 022
# The product profile decides what this host owns (ADR-0021, ADR-0026), so it is
# resolved before anything is written: a panel host must not receive the router's
# local console unit, and must not get the getty mask that goes with it.
PROFILE=${VS_ROUTER_PROFILE:-router}
case "$PROFILE" in
    router|panel) ;;
    *) echo "ERROR: VS_ROUTER_PROFILE must be router or panel, got '$PROFILE'" >&2; exit 1 ;;
esac
command -v pppd >/dev/null 2>&1 || { echo 'ERROR: Debian ppp package is required' >&2; exit 1; }
# Both ISO and online installs enter here, as do updates. A non-empty key file
# must survive byte-for-byte: replacing it would orphan all encrypted secrets.
(
    # Keep key material out of even an explicitly enabled shell trace. The
    # subshell restores the caller's trace setting and discards the variable.
    set +x
    if [ ! -s /etc/vs-router/secrets.env ]; then
        install -d -m 0700 /etc/vs-router
        secret_key=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
        [ -n "$secret_key" ] || { echo 'ERROR: secret-encryption key generator returned no key' >&2; exit 1; }
        # Generate successfully before creating anything; publish atomically so
        # a failed generator or write never leaves a new empty/partial key file.
        secret_file=$(mktemp /etc/vs-router/.secrets.env.XXXXXXXXXX)
        trap 'rm -f "$secret_file"' EXIT
        install -m 0600 -o root -g root /dev/null "$secret_file"
        printf 'VS_ROUTER_SECRET_KEY=%s\n' "$secret_key" > "$secret_file"
        mv -f "$secret_file" /etc/vs-router/secrets.env
        echo 'Secret-encryption key: created'
    else
        echo 'Secret-encryption key: kept existing'
    fi
)
# Listener remains closed until the agent has installed the interface firewall.
# The ISO/bootstrap path masks SSH and repoints sshd at /etc/vs-router-ssh with a
# /run marker that only an apply creates. A remote (online) install over SSH must
# touch NONE of that, or the operator is locked out of a box with no local
# console (ADR-0017): VS_ROUTER_KEEP_SSH=1 skips both.
# The directories exist regardless of mode: unit sandboxing (ProtectSystem with
# ReadWritePaths) refuses to start when a listed path is missing.
install -d -m 0700 /etc/vs-router-ssh /var/lib/vs-router-ssh /run/vs-router-ssh
if [ "${VS_ROUTER_KEEP_SSH:-0}" = "1" ]; then
    echo 'VS_ROUTER_KEEP_SSH=1: leaving sshd and its units untouched'
    # Tell the agent (which starts further down) to leave SSH alone: it reads
    # this marker before the management record exists.
    install -d -m 0755 /etc/vs-router
    : > /etc/vs-router/online-install
else
    systemctl mask ssh.service ssh.socket
    systemctl stop ssh.service ssh.socket
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
fi
# Caddy built from source (xcaddy) ships no user/group and no distro unit —
# create them; the binary lives wherever PATH resolves it (usually /usr/local/bin).
getent group caddy >/dev/null 2>&1 || groupadd --system caddy
id caddy >/dev/null 2>&1 || useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
CADDY_BIN=$(command -v caddy || echo /usr/local/bin/caddy)
packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Verify and repair the pinned engine pair on fresh install and update.
bash "$packaging_dir/install-singbox.sh"
install -d -m 0750 /etc/caddy/vs-router
chown root:caddy /etc/caddy/vs-router
install -d -m 0700 /etc/vs-router/wireguard
install -d -m 0755 /etc/systemd/system/caddy.service.d
# systemd cannot remove vendor After=/Wants= via drop-ins; install exact
# Debian unit copies with network-online.target replaced by network.target.
# Only meaningful on a host that has the Kea units at all.
if command -v kea-dhcp4 >/dev/null 2>&1; then
    /usr/bin/python3 "$(dirname "$0")/kea-network-order.py"
fi
cat > /etc/systemd/system/caddy.service.d/vs-router.conf <<EOF
[Unit]
After=
After=network.target
Wants=
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
# pppd reads these as root. Keep credentials private even on an installer rerun.
install -d -o root -g root -m 0755 /etc/ppp/peers
for peer in /etc/ppp/peers/vs-router-*; do
    [ ! -L "$peer" ] || { echo "ERROR: PPPoE peer is a symlink: $peer" >&2; exit 1; }
    [ -f "$peer" ] || continue
    chown root:root "$peer"
    chmod 0600 "$peer"
done
for secrets in /etc/ppp/chap-secrets /etc/ppp/pap-secrets; do
    [ ! -L "$secrets" ] || { echo "ERROR: PPP secrets file is a symlink: $secrets" >&2; exit 1; }
    [ -f "$secrets" ] || continue
    chown root:root "$secrets"
    chmod 0600 "$secrets"
done
install -d -m 0770 /run/vs-router
chgrp vs-router-web /run/vs-router
install -d -m 0770 -o vs-router-web -g vs-router-web /run/vs-router/web /var/lib/vs-router
for unit in "$packaging_dir"/*.service "$packaging_dir"/*.timer; do
    base=$(basename -- "$unit")
    case "$PROFILE:$base" in
        panel:vs-router-console.service) continue ;;
    esac
    install -m 0644 "$unit" /etc/systemd/system/"$base"
done
if [ "$PROFILE" = panel ]; then
    # ADR-0021: the panel owns no local console. A host reinstalled as a panel
    # would otherwise keep the router's leftovers — the console unit would come
    # back on boot and the physical login would stay masked.
    rm -f /etc/systemd/system/vs-router-console.service
    systemctl unmask getty@tty1.service >/dev/null 2>&1 || true
fi
install -d -m 0755 /usr/local/libexec/vs-router
install -m 0644 "$packaging_dir/reconcile-networkd-boot.py" /usr/local/libexec/vs-router/reconcile-networkd-boot.py
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
# GET /api/release, plus the product profile this host runs (ADR-0026). The
# commit comes from git when present, else a REVISION file vendored into the
# ISO; the semver falls back to the installed wheel's metadata, so a host
# installed from a copied packaging directory can still say what it runs.
repo_root=$(dirname -- "$packaging_dir")/..
semver=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$repo_root/backend/pyproject.toml" 2>/dev/null | head -n1)
commit=""
if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --verify -q HEAD >/dev/null 2>&1; then
    commit=$(git -C "$repo_root" rev-parse HEAD)
elif [ -f "$repo_root/REVISION" ]; then
    commit=$(tr -d '[:space:]' < "$repo_root/REVISION")
fi
if [ -z "$semver" ]; then
    semver=$(python3 -c "import importlib.metadata as m; print(m.version('vs-router-backend'))" 2>/dev/null || true)
fi
source=${VS_ROUTER_RELEASE_SOURCE:-}
if [ -z "$source" ]; then
    if [ -n "$commit" ]; then source=git
    elif [ -n "$semver" ]; then source=wheel
    else source=unknown
    fi
fi
[ -n "$commit" ] || commit=unknown
[ -n "$semver" ] || semver=unknown
printf '{"commit":"%s","semver":"%s","profile":"%s","installed_at":"%s","source":"%s"}\n' \
    "$commit" "$semver" "$PROFILE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$source" \
    > /etc/vs-router/version.json
chmod 0644 /etc/vs-router/version.json
# The product identity is installer-owned and never switched from the panel
# (ADR-0026). Failing to record it must not fail the install — the host then
# falls back to capability rules — but it must never pass silently.
if ! python3 -m vs_router.profile write "$PROFILE"; then
    echo "WARNING: could not record the product profile ('$PROFILE'); this host will decide by capability only" >&2
fi
# Kea control channel: the agent reloads DHCP through localhost HTTP, so the
# credential file and a running control agent are prerequisites of the first
# apply. Missing either used to surface as a bare agent.apply_failed.
install -d -m 0755 /etc/systemd/system/vs-router-web.service.d
if command -v kea-dhcp4 >/dev/null 2>&1; then
    if [ ! -s /etc/kea/kea-api-password ]; then
        install -m 0600 /dev/null /etc/kea/kea-api-password
        python3 -c 'import secrets; from pathlib import Path; Path("/etc/kea/kea-api-password").write_text(secrets.token_urlsafe(32) + "\n")'
    fi
    chmod 0640 /etc/kea/kea-api-password
    chown root:_kea /etc/kea/kea-api-password
    # The base units must not name /etc/kea: a ReadWritePaths target that does
    # not exist fails the unit with 226/NAMESPACE at start. Add it per host,
    # only where the directory is really there.
    for unit in vs-router-agent vs-router-bootrestore; do
        install -d -m 0755 "/etc/systemd/system/$unit.service.d"
        cat > "/etc/systemd/system/$unit.service.d/kea.conf" <<'EOF'
[Service]
ReadWritePaths=/etc/kea
EOF
    done
    # PID 1 reads the restricted source; the web service gets a private copy so
    # the leases view never needs the password in unit text or argv.
    cat > /etc/systemd/system/vs-router-web.service.d/kea-api.conf <<'EOF'
[Service]
LoadCredential=kea-api-password:/etc/kea/kea-api-password
ExecStartPre=/usr/bin/test -s %d/kea-api-password
Environment=VS_ROUTER_KEA_API_USER=kea-api
Environment=VS_ROUTER_KEA_API_PASSWORD_FILE=%d/kea-api-password
EOF
    # The distro default config binds every interface and would hand out leases
    # on this host's uplink, so seed a serve-nothing config until the panel
    # writes its own at the first apply. Never overwrite one the panel owns.
    if [ ! -f /etc/vs-router/applied/kea.json ]; then
        printf '%s\n' '{"Dhcp4": {"interfaces-config": {"interfaces": []},' \
            ' "lease-database": {"type": "memfile", "persist": true,' \
            ' "name": "/var/lib/kea/kea-leases4.csv"}, "valid-lifetime": 3600,' \
            ' "subnet4": []}}' > /etc/kea/kea-dhcp4.conf
        chmod 0640 /etc/kea/kea-dhcp4.conf
        chown root:_kea /etc/kea/kea-dhcp4.conf
    fi
else
    # No DHCP server on this host (the panel profile installs none, ADR-0021).
    # Leftovers are not harmless: the web drop-in demands the Kea credential
    # (ExecStartPre, so vs-router-web would not start), and the ReadWritePaths
    # drop-ins name a directory that no longer exists (the unit then dies with
    # 226/NAMESPACE before it runs).
    rm -f /etc/systemd/system/vs-router-web.service.d/kea-api.conf \
        /etc/systemd/system/vs-router-agent.service.d/kea.conf \
        /etc/systemd/system/vs-router-bootrestore.service.d/kea.conf
fi
systemctl enable vs-router-bootrestore.service vs-router-tproxy-postboot.service vs-router-pppoe-postboot.service
# Everything this product runs has to be enabled, or a reboot leaves the host with
# a tunnel and no panel. Observed on a panel installed over SSH: web and agent
# carried WantedBy=multi-user.target but had no enable symlink, because only the
# ISO path (bootstrap.sh) enabled them. Each unit is enabled only if this build
# installed it, so a profile that does not ship one does not fail the install.
for unit in vs-router-web.service vs-router-agent.service \
            vs-router-rollback.timer vs-router-ddns.timer vs-router-source-update.timer; do
    [ -f "/etc/systemd/system/$unit" ] || continue
    systemctl enable "$unit"
done
if [ "$PROFILE" = router ]; then
    # Replace the physical tty1 login on the next boot, not the active installer
    # session: stopping getty here would kill an operator running bootstrap on
    # tty1. SSH units are managed separately; this only affects the local VGA
    # console, which the panel profile does not own (ADR-0021).
    systemctl mask getty@tty1.service
    systemctl enable vs-router-console.service
else
    systemctl disable vs-router-console.service >/dev/null 2>&1 || true
fi
systemctl daemon-reload
systemctl restart vs-router-agent.service vs-router-web.service
# Kea may be inactive on a fresh machine; its control agent must be up before the
# panel can reload DHCP, so start it now and do not fail the install on it. A host
# without kea-dhcp4 installs no DHCP server at all (ADR-0021), so it is not warned
# about a service it is not supposed to have: that warning fired on every panel
# install and told the operator the panel was missing something it does not use.
if command -v kea-dhcp4 >/dev/null 2>&1; then
    systemctl restart kea-ctrl-agent kea-dhcp4-server 2>/dev/null || \
        echo 'WARNING: kea services did not start; DHCP reload will fail at apply' >&2
else
    echo 'No kea-dhcp4 on this host: no DHCP phase, and no kea services to start'
fi
systemctl is-active --quiet vs-router-agent.service
systemctl is-active --quiet vs-router-web.service
# Portal publication hooks (phase 5, ADR-0032)
id vs-router-portal >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vs-router/portal --shell /usr/sbin/nologin vs-router-portal
usermod -a -G vs-router-portal vs-router-web || true
install -d -m 0770 -o vs-router-portal -g vs-router-portal /var/lib/vs-router/portal /run/vs-router/portal
install -d -m 0770 -o vs-router-web -g vs-router-portal /run/vs-router/web
install -m 0640 -o vs-router-web -g vs-router-portal /etc/vs-router/portal-internal.secret 2>/dev/null || install -m 0640 -o root -g root /dev/null /etc/vs-router/portal-internal.secret
chown vs-router-web:vs-router-portal /etc/vs-router/portal-internal.secret 2>/dev/null || true
chmod 0640 /etc/vs-router/portal-internal.secret 2>/dev/null || true
systemctl daemon-reload
[ -f /etc/systemd/system/vs-router-portal.service ] && systemctl enable vs-router-portal.service
[ -f /etc/systemd/system/vs-router-web-internal.service ] && systemctl enable vs-router-web-internal.service
