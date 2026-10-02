#!/usr/bin/env bash
set +x
set -Eeuo pipefail
# Packages and build outputs must remain readable by service users. Secrets
# are pre-created with restrictive modes below before any bytes are written.
umask 022

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CURRENT_STAGE=initialization
SKIP_BUILD=0
BUILD_DIR=''
trap 'status=$?; log "ERROR: stage ${CURRENT_STAGE} failed (status ${status})"; exit "$status"' ERR
trap '[[ -z $BUILD_DIR ]] || rm -rf -- "$BUILD_DIR"' EXIT

log() {
    logger -t vs-router-bootstrap -- "$*" 2>/dev/null || true
    printf '[vs-router-bootstrap] %s\n' "$*"
}

fail() {
    log "ERROR: stage '${CURRENT_STAGE}' failed: $*"
    exit 1
}

run_stage() {
    local stage=$1
    shift
    CURRENT_STAGE=$stage
    log "Starting stage: ${stage}"
    # Never call stages in an if/!/&&/|| context: Bash suppresses errexit
    # recursively in functions called that way.
    "$@"
    log "Completed stage: ${stage}"
}

usage() {
    cat <<'EOF'
Usage: bootstrap.sh [--skip-build] [--help]
  --skip-build  Skip frontend and backend builds; use existing backend wheels.
  --help        Show this help.
EOF
}

parse_args() {
    while (($#)); do
        case $1 in
            --skip-build) SKIP_BUILD=1 ;;
            --help|-h) usage; exit 0 ;;
            *) usage >&2; fail "unknown option: $1" ;;
        esac
        shift
    done
}

stage_check_root() {
    if [[ ${EUID} -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
            fail 'run this script as root (sudo ./bootstrap.sh ...)'
        fi
        # Fresh Debian installs ship without sudo: give the exact escape hatch.
        fail "sudo is missing and you are not root. Run:
  su -c 'apt update && apt install -y sudo && usermod -aG sudo $USER'
then log out and back in, and rerun with sudo."
    fi
    [[ -f /etc/os-release ]] || fail 'Debian is required'
    local version
    . /etc/os-release
    version=${VERSION_ID:-unknown}
    [[ ${ID:-} == debian && $version == 13 ]] || fail "Debian 13 required (found ${ID:-unknown} ${version})"
    log "Detected Debian ${version}"
}

stage_networkd() {
    # Do not replace an applied configuration on a bootstrap rerun.
    [[ ! -f /etc/vs-router/confirmed/networkd.conf ]] || return 0
    [[ ! -f /var/lib/vs-router-bootstrap/networkd-migrated ]] || return 0
    local iface mac file index
    [[ -s /var/lib/vs-router-bootstrap/installer-uplink ]] || fail 'installer uplink missing; record its name and MAC from the local console'
    read -r iface mac < /var/lib/vs-router-bootstrap/installer-uplink
    [[ $iface =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$ && $mac =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || fail 'invalid installer uplink'
    [[ -e /sys/class/net/$iface/device && ! -e /sys/class/net/$iface/wireless ]] || fail 'uplink must be a physical wired port'
    [[ $(< "/sys/class/net/$iface/address") == "$mac" ]] || fail 'uplink MAC mismatch; inspect from console'
    # Only DHCP installations are automatically migrated. Static/one-port LAN
    # conversion requires console work; never infer LAN from a default route.
    awk -v iface="$iface" '$1 == "iface" && $2 == iface && $3 == "inet" && $4 == "dhcp" {found=1} END {exit !found}' /etc/network/interfaces || fail 'automatic migration requires installer DHCP'
    file="/etc/systemd/network/10-vs-router-${iface}.network"
    if [[ -e $file ]]; then
        # A failed attempt may have staged this exact owned file. Do not touch
        # an unrelated or edited file during retry.
        [[ -f /etc/vs-router/networkd-manifest.conf ]] || fail 'existing networkd configuration requires console review'
        { printf '### FILE: %s\n' "${file##*/}"; cat "$file"; } | cmp -s - /etc/vs-router/networkd-manifest.conf || fail 'networkd ownership mismatch'
    fi
    install -d -m 0755 /etc/systemd/network
    printf '[Match]\nName=%s\nMACAddress=%s\n\n[Network]\nDHCP=ipv4\nKeepConfiguration=yes\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n\n[DHCPv4]\nClientIdentifier=mac\n' "$iface" "$mac" > "$file"
    chmod 0644 "$file"
    # Record temporary ownership using the agent's bundle format before activation.
    { printf '### FILE: %s\n' "${file##*/}"; cat "$file"; } > /etc/vs-router/networkd-manifest.conf
    systemctl enable --now systemd-networkd.service
    networkctl reload
    /usr/lib/systemd/systemd-networkd-wait-online --interface="$iface":routable --ipv4 --timeout=60
    index=$(< "/sys/class/net/$iface/ifindex")
    [[ -s /run/systemd/netif/leases/$index ]] || fail 'networkd has not acquired a DHCP lease; ifupdown retained'
    ip -4 route show default dev "$iface" | grep -q '^default' || fail 'uplink default route missing; ifupdown retained'
    getent ahostsv4 deb.debian.org >/dev/null
    # Never stop networking here: ifdown would flush the live address. Disable
    # only after networkd has a lease and routing/DNS checks have passed.
    systemctl disable networking.service
    touch /var/lib/vs-router-bootstrap/networkd-migrated
}

stage_firewall() {
    # Existing applied rules belong to the agent, not bootstrap.
    [[ ! -f /etc/vs-router/confirmed/networkd.conf ]] || return 0
    [[ ! -f /var/lib/vs-router-bootstrap/networkd-migrated ]] || return 0
    nft -c -f "$SCRIPT_DIR/bootstrap.nft"
    nft -f "$SCRIPT_DIR/bootstrap.nft"
}

stage_apt_deps() {
    export DEBIAN_FRONTEND=noninteractive
    # VM/lab networks (slirp, NAT) reproducibly stall pipelined apt downloads:
    # connections ESTABLISH, ~240MB flows, then every stream freezes and the
    # method processes spin forever (timeouts never fire). Serial queue mode
    # plus short timeouts and retries turns that freeze into a visible retry.
    printf '%s\n' \
        'Acquire::Queue-Mode "access";' \
        'Acquire::http::Timeout "30";' \
        'Acquire::https::Timeout "30";' \
        'Acquire::Retries "5";' \
        > /etc/apt/apt.conf.d/95vsr-bootstrap
    # Mask before installing OpenSSH: package postinst must not open a listener.
    systemctl mask ssh.service ssh.socket
    systemctl stop ssh.service ssh.socket || true
    apt-get update
    apt-get install -y python3 python3-pip python3-venv git build-essential golang-go \
        kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor wireguard-tools \
        socat curl nodejs npm debian-keyring debian-archive-keyring \
        openssh-server fail2ban python3-systemd
}

stage_caddy() {
    if [[ -x /usr/local/bin/caddy ]] && /usr/local/bin/caddy list-modules 2>/dev/null | grep -q layer4; then
        log 'Caddy with layer4 already exists; skipping build'
        return
    fi
    # The Cloudsmith xcaddy apt repo proved unreliable (config.txt may return
    # an empty body); go install is the dependable path since Go is required
    # for AmneziaWG anyway.
    export PATH="${PATH}:$(go env GOPATH 2>/dev/null || echo /root/go)/bin"
    command -v xcaddy >/dev/null 2>&1 || go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    xcaddy build v2.11.4 --with github.com/mholt/caddy-l4@v0.1.2 --with github.com/caddy-dns/cloudflare \
        --output /usr/local/bin/caddy
}

stage_awg() {
    BUILD_DIR=$(mktemp -d /var/lib/vs-router-build.XXXXXXXX)
    local workdir=$BUILD_DIR
    if [[ ! -x /usr/local/bin/awg-go ]]; then
        if [[ ! -d "$workdir/amneziawg-go/.git" ]]; then
            git clone --branch v3.1.20260812 --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$workdir/amneziawg-go"
        fi
        make -C "$workdir/amneziawg-go"
        install -m 0755 "$workdir/amneziawg-go/amneziawg-go" /usr/local/bin/awg-go
    else
        log 'awg-go already exists; skipping build'
    fi
    if [[ ! -x /usr/local/bin/awg || ! -x /usr/local/bin/awg-quick ]]; then
        if [[ ! -d "$workdir/amneziawg-tools/.git" ]]; then
            git clone --branch v3.1.20260812 --depth 1 https://github.com/amnezia-vpn/amneziawg-tools "$workdir/amneziawg-tools"
        fi
        # The binary is built as 'wg' and 'make install' renames it to awg
        # (plus the awg-quick bash script) — no manual file copying.
        make -C "$workdir/amneziawg-tools/src" PREFIX=/usr BINDIR=/usr/local/bin install
    else
        log 'awg and awg-quick already exist; skipping build'
    fi
    if [[ ! -x /usr/local/bin/wg-go ]]; then
        # git.zx2c4.com is unreachable from some networks; GitHub mirror is the same code.
        if [[ ! -d "$workdir/wireguard-go/.git" ]]; then
            git clone https://github.com/WireGuard/wireguard-go "$workdir/wireguard-go"
        fi
        make -C "$workdir/wireguard-go"
        install -m 0755 "$workdir/wireguard-go/wireguard-go" /usr/local/bin/wg-go
    else
        log 'wg-go already exists; skipping build'
    fi
}

stage_build() {
    if ((SKIP_BUILD)); then
        log 'Build skipped by --skip-build'
        return
    fi
    (cd "$REPO_ROOT/frontend"; npm ci; npm run build)
    rm -f "$REPO_ROOT/backend/dist/"*.whl
    (cd "$REPO_ROOT/backend"; python3 -m pip wheel --no-deps -w dist .)
    test -s "$REPO_ROOT/frontend/dist/index.html"
}

stage_install() {
    local wheel_dir="$REPO_ROOT/backend/dist"
    compgen -G "$wheel_dir/*.whl" >/dev/null || fail "no backend wheel found in ${wheel_dir}"
    python3 -m pip install --break-system-packages --force-reinstall --no-deps "$wheel_dir"/*.whl
    # Debian-owned Python packages (e.g. typing_extensions) lack pip RECORD;
    # pip cannot uninstall them during dependency resolution. Install newer deps
    # into /usr/local without attempting to remove files owned by dpkg.
    python3 -m pip install --break-system-packages --ignore-installed "$wheel_dir"/*.whl

    install -d -m 0700 /etc/vs-router
    if [[ ! -s /etc/vs-router/secrets.env ]]; then
        install -m 0600 /dev/null /etc/vs-router/secrets.env
        local secret_key
        secret_key=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
        printf 'VS_ROUTER_SECRET_KEY=%s\n' "$secret_key" > /etc/vs-router/secrets.env
        chmod 0600 /etc/vs-router/secrets.env
    fi

    if [[ ! -s /etc/kea/kea-api-password ]]; then
        install -m 0600 /dev/null /etc/kea/kea-api-password
        python3 -c 'import secrets; from pathlib import Path; Path("/etc/kea/kea-api-password").write_text(secrets.token_urlsafe(32) + "\n")'
    fi
    chmod 0640 /etc/kea/kea-api-password
    chown root:_kea /etc/kea/kea-api-password

    # PID 1 reads the restricted source; only the web service receives a
    # private credential copy. No password appears in unit text or argv.
    install -d -m 0755 /etc/systemd/system/vs-router-web.service.d
    cat > /etc/systemd/system/vs-router-web.service.d/kea-api.conf <<'EOF'
[Service]
LoadCredential=kea-api-password:/etc/kea/kea-api-password
ExecStartPre=/usr/bin/test -s %d/kea-api-password
Environment=VS_ROUTER_KEA_API_USER=kea-api
Environment=VS_ROUTER_KEA_API_PASSWORD_FILE=%d/kea-api-password
EOF
    # Run via bash: a fresh clone may carry the file without the exec bit.
    bash "$SCRIPT_DIR/install.sh"
    # Kea may be inactive on a fresh machine (no interfaces configured yet) —
    # its restart must not fail the bootstrap; the panel configures it later.
    systemctl restart kea-ctrl-agent kea-dhcp4-server 2>/dev/null || \
        log 'WARNING: kea services did not restart; the panel will configure them on first apply'

    systemctl daemon-reload
    systemctl enable vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer
    systemctl restart vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer
    local service
    for service in vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer caddy; do
        systemctl is-active --quiet "$service"
    done
    runuser -u vs-router-web -- test -r /var/lib/vs-router/ui/index.html
    # This proves local API startup only; it is not a LAN HTTPS readiness test.
    # A restarted web unit may be active before Uvicorn creates its Unix
    # socket. curl --retry-connrefused does not retry a missing socket (ENOENT).
    local attempt
    for ((attempt = 0; attempt < 30; attempt++)); do
        if curl --fail --silent --max-time 2 --unix-socket /run/vs-router/web/web.sock \
                http://localhost/health >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail 'web health endpoint unavailable after service restart'
}

stage_summary() {
    local service status
    for service in vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer; do
        status=$(systemctl is-active "$service" 2>/dev/null || true)
        log "Service ${service}: ${status:-unknown}"
    done
    log 'Software installed; panel readiness is NOT established. From the local root console run: python3 -m vs_router.agent.management_console --mac <LAN-MAC> [--address 192.168.10.1/24]. Then verify access from LAN and denial from WAN.'
}

main() {
    parse_args "$@"
    run_stage 'check:_root' stage_check_root
    run_stage 'firewall' stage_firewall
    run_stage 'apt:deps' stage_apt_deps
    run_stage 'networkd' stage_networkd
    run_stage 'caddy' stage_caddy
    run_stage 'awg' stage_awg
    run_stage 'build' stage_build
    run_stage 'install' stage_install
    run_stage 'summary' stage_summary
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
