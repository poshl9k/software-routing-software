#!/bin/sh
# Give a host that has Kea the control channel the panel expects.
#
# The panel reloads DHCP through the Kea control agent over localhost HTTP, and the
# agent's syntax check runs against its staged configuration. Both need state that
# only exists if the installer provisioned it: the API password, the ReadWritePaths
# drop-ins (base units must not name /etc/kea, see the unit comment), the web
# credential drop-in, the AppArmor override and a serve-nothing seed config.
#
# It used to be inline in install.sh, which made it unreachable for a host where Kea
# appeared *after* the panel — exactly what happened on the router stand, where the
# first DHCP apply failed with `kea.api_password_missing`. Idempotent on purpose.
set -eu

kea_dir=${VS_ROUTER_KEA_DIR:-/etc/kea}
unit_dir=${VS_ROUTER_UNIT_DIR:-/etc/systemd/system}
applied_dir=${VS_ROUTER_APPLIED_DIR:-/etc/vs-router/applied}
apparmor_dir=${VS_ROUTER_APPARMOR_DIR:-/etc/apparmor.d}
profile_file=${apparmor_dir}/usr.sbin.kea-dhcp4

[ -d "$kea_dir" ] || { echo "kea-setup: $kea_dir is missing; install kea-dhcp4-server first" >&2; exit 2; }

# The credential file is read by the ctrl-agent (as _kea) and by the web unit
# through LoadCredential, so root alone cannot read it back by design.
if [ ! -s "$kea_dir/kea-api-password" ]; then
    (umask 077; : > "$kea_dir/kea-api-password")
    python3 -c 'import secrets, sys; open(sys.argv[1], "w").write(secrets.token_urlsafe(32) + "\n")' \
        "$kea_dir/kea-api-password"
fi
chmod 0640 "$kea_dir/kea-api-password"
if getent group _kea >/dev/null 2>&1; then
    chown root:_kea "$kea_dir/kea-api-password"
fi

# A ReadWritePaths entry for a directory that does not exist fails the unit with
# 226/NAMESPACE, which is why the base units stay silent about /etc/kea.
for unit in vs-router-agent vs-router-bootrestore; do
    install -d -m 0755 "$unit_dir/$unit.service.d"
    printf '[Service]\nReadWritePaths=%s\n' "$kea_dir" > "$unit_dir/$unit.service.d/kea.conf"
done

# PID 1 reads the restricted source; the web service gets a private copy so the
# leases view never needs the password in unit text or argv.
install -d -m 0755 "$unit_dir/vs-router-web.service.d"
cat > "$unit_dir/vs-router-web.service.d/kea-api.conf" <<EOF
[Service]
LoadCredential=kea-api-password:$kea_dir/kea-api-password
ExecStartPre=/usr/bin/test -s %d/kea-api-password
Environment=VS_ROUTER_KEA_API_USER=kea-api
Environment=VS_ROUTER_KEA_API_PASSWORD_FILE=%d/kea-api-password
EOF

# Debian's AppArmor profile for kea-dhcp4 reads only /etc/kea, so the syntax check
# the agent runs against /run/vs-router/pending is denied and every apply dies with
# agent.validation_failed on a configuration that is perfectly valid.
if [ -f "$profile_file" ] && command -v apparmor_parser >/dev/null 2>&1; then
    install -d -m 0755 "$apparmor_dir/local"
    cat > "$apparmor_dir/local/usr.sbin.kea-dhcp4" <<'EOF'
# The panel stages its generated configuration and validates it with
# ``kea-dhcp4 -t`` before installing it. The stock profile reads only /etc/kea.
/run/vs-router/pending/* r,
EOF
    grep -q 'include <local/usr.sbin.kea-dhcp4>' "$profile_file" 2>/dev/null ||
        sed -i 's|#include <local/usr.sbin.kea-dhcp4>|include <local/usr.sbin.kea-dhcp4>|' "$profile_file" 2>/dev/null || true
    apparmor_parser -r "$profile_file" >/dev/null 2>&1 ||
        echo 'kea-setup: could not reload the kea AppArmor profile; the first DHCP apply may fail validation' >&2
fi

# The distro default config binds every interface and would hand out leases on the
# host's uplink, so seed a serve-nothing config until the panel writes its own at
# the first apply. Never overwrite one the panel owns.
if [ ! -f "$applied_dir/kea.json" ] && [ ! -f "$kea_dir/.vs-router-seeded" ]; then
    printf '%s\n' '{"Dhcp4": {"interfaces-config": {"interfaces": []},' \
        ' "lease-database": {"type": "memfile", "persist": true,' \
        ' "name": "/var/lib/kea/kea-leases4.csv"}, "valid-lifetime": 3600,' \
        ' "subnet4": []}}' > "$kea_dir/kea-dhcp4.conf"
    chmod 0640 "$kea_dir/kea-dhcp4.conf"
    if getent group _kea >/dev/null 2>&1; then
        chown root:_kea "$kea_dir/kea-dhcp4.conf"
    fi
    : > "$kea_dir/.vs-router-seeded"
fi

if [ -z "${VS_ROUTER_KEA_SETUP_NO_RESTART:-}" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl restart kea-ctrl-agent kea-dhcp4-server 2>/dev/null ||
        echo 'kea-setup: kea services did not start; DHCP reload will fail at apply' >&2
fi
