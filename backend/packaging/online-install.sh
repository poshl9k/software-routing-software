#!/bin/sh
# Online installer for a one-NIC (VPS) panel host — Debian 13, run as root over
# SSH. Unlike the ISO bootstrap it must never touch sshd or port 22 (ADR-0017):
# the operator has no local console, so a fail-closed SSH would be permanent.
# Idempotent: re-running skips anything already in place.
set -eu
umask 022

HOSTNAME_ARG=''
PATH_PREFIX=''
ADDRESS=''
SSH_PORT=22
WHEEL=''
UI=''
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: online-install.sh [options]

  --hostname H      public name for the ACME certificate, e.g. 203.0.113.9.nip.io
  --path-prefix P   secret panel path, e.g. /uOE3flWG7hvM (root then answers 404)
  --address A/P     panel address; default: the uplink's live lease
  --ssh-port N      SSH port to keep open (default 22)
  --wheel FILE      prebuilt vs_router backend wheel
  --ui DIR          prebuilt frontend dist/ directory
  --dry-run         print actions without changing the system
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --hostname) HOSTNAME_ARG=${2:?}; shift 2 ;;
        --path-prefix) PATH_PREFIX=${2:?}; shift 2 ;;
        --address) ADDRESS=${2:?}; shift 2 ;;
        --ssh-port) SSH_PORT=${2:?}; shift 2 ;;
        --wheel) WHEEL=${2:?}; shift 2 ;;
        --ui) UI=${2:?}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

run() {
    if [ "$DRY_RUN" = 1 ]; then echo "+ $*"; else "$@"; fi
}

[ "$(id -u)" = 0 ] || { echo 'run as root' >&2; exit 1; }
[ -r /etc/os-release ] || { echo 'missing /etc/os-release' >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != debian ] || [ "${VERSION_ID:-}" != 13 ]; then
    echo "WARNING: expected Debian 13, found ${PRETTY_NAME:-unknown}" >&2
fi

WORK=/root/vs-router-install
run install -d -m 0755 "$WORK"

# --- 1. Packages ------------------------------------------------------------
# Go builds need scratch space outside the RAM-backed /tmp on small VPSes.
run install -d -m 0700 "$WORK/tmp"

install_packages() {
    export DEBIAN_FRONTEND=noninteractive
    run apt-get update -y
    run apt-get install -y \
        dbus python3 python3-pip python3-venv python3-setuptools python3-wheel \
        git build-essential golang-go nodejs npm curl socat nftables apparmor \
        wireguard-tools unbound kea-dhcp4-server kea-ctrl-agent ppp traceroute \
        fail2ban python3-systemd openssh-server
}
if ! command -v nft >/dev/null 2>&1 || ! command -v unbound >/dev/null 2>&1; then
    install_packages
fi

# --- 2. AmneziaWG (userspace runtime + tools) -------------------------------
if ! command -v awg >/dev/null 2>&1; then
    run git -C "$WORK" clone --branch v3.1.20260812 --depth 1 \
        https://github.com/amnezia-vpn/amneziawg-go
    run git -C "$WORK" clone --branch v3.1.20260812 --depth 1 \
        https://github.com/amnezia-vpn/amneziawg-tools
    run make -C "$WORK/amneziawg-go"
    run install -m 0755 "$WORK/amneziawg-go/amneziawg-go" /usr/local/bin/awg-go
    run make -C "$WORK/amneziawg-tools/src" PREFIX=/usr BINDIR=/usr/local/bin install
fi

# --- 3. Caddy with the L4 module --------------------------------------------
getent group caddy >/dev/null 2>&1 || run groupadd --system caddy
id caddy >/dev/null 2>&1 || run useradd --system --gid caddy --home /var/lib/caddy \
    --shell /usr/sbin/nologin caddy
if ! command -v caddy >/dev/null 2>&1; then
    run sh -c "PATH=\"\$PATH:\$(go env GOPATH)/bin\"; export PATH; \
        TMPDIR='$WORK/tmp' GOTMPDIR='$WORK/tmp'; \
        go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7"
    run sh -c "PATH=\"\$PATH:\$(go env GOPATH)/bin\"; export PATH; \
        TMPDIR='$WORK/tmp' GOTMPDIR='$WORK/tmp'; \
        xcaddy build v2.11.4 --with github.com/mholt/caddy-l4@v0.1.2 \
        --with github.com/caddy-dns/cloudflare@v0.2.4 --output /usr/local/bin/caddy"
fi

# --- 4. Panel (wheel + built UI) --------------------------------------------
if [ -n "$WHEEL" ]; then
    run python3 -m pip install --break-system-packages --ignore-installed \
        "fastapi>=0.115,<1" "sqlalchemy>=2.0,<3" "alembic>=1.13,<2" \
        "pydantic>=2.9,<3" "cryptography>=43" "argon2-cffi>=23" \
        "uvicorn>=0.30,<1" "qrcode>=8.2" "pillow>=12.3.0"
    run python3 -m pip install --break-system-packages --no-deps \
        --force-reinstall "$WHEEL"
fi

# --- 5. Privileged install (never touches sshd) ------------------------------
# VS_ROUTER_KEEP_SSH=1 makes install.sh skip the SSH mask and the sshd drop-in.
if [ -d "${PACKAGING:-}" ]; then
    run env VS_ROUTER_KEEP_SSH=1 sh "$PACKAGING/install.sh"
fi
if [ -n "$UI" ]; then
    run install -d -m 0755 /var/lib/vs-router/ui
    run cp -a "$UI/." /var/lib/vs-router/ui/
    run systemctl restart vs-router-web
fi

# --- 6. Publish the panel on the uplink --------------------------------------
if [ "$DRY_RUN" != 1 ]; then
    set -- --single-uplink --ssh-port "$SSH_PORT"
    if [ -n "$HOSTNAME_ARG" ]; then set -- "$@" --hostname "$HOSTNAME_ARG"; fi
    if [ -n "$PATH_PREFIX" ]; then set -- "$@" --path-prefix "$PATH_PREFIX"; fi
    if [ -n "$ADDRESS" ]; then set -- "$@" --address "$ADDRESS"; fi
    python3 -m vs_router.agent.management_console "$@"
else
    echo "+ management_console --single-uplink --ssh-port $SSH_PORT ${HOSTNAME_ARG:+--hostname $HOSTNAME_ARG}"
fi

# --- 7. Verify: SSH must still be reachable, and so must the panel -----------
# An install that leaves the box unreachable is worse than no install.
if ! systemctl is-active --quiet ssh 2>/dev/null && ! systemctl is-active --quiet ssh.socket; then
    echo 'ERROR: sshd is not active — do not disconnect' >&2
    exit 1
fi
if [ -n "$SSH_PORT" ] && ! ss -lnt 2>/dev/null | grep -q ":$SSH_PORT "; then
    echo "ERROR: nothing is listening on :$SSH_PORT" >&2
    exit 1
fi
if nft list table inet vs_router_ssh_lock >/dev/null 2>&1; then
    echo 'ERROR: the fail-closed SSH lock is present; removing it' >&2
    run nft delete table inet vs_router_ssh_lock
fi
echo 'ONLINE_INSTALL_OK'
