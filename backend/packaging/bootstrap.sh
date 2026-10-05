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
readonly XCADDY_VERSION='v0.4.7'
readonly CLOUDFLARE_MODULE_VERSION='v0.2.4'
readonly CADDY_VERSION='v2.11.4'
readonly CADDY_L4_VERSION='v0.1.2'
readonly AMNEZIAWG_VERSION='v3.1.20260812'
readonly AMNEZIAWG_GO_REVISION='1f50ad736ecca22a9bfc7b4606805ec9ca49fe48'
readonly AMNEZIAWG_TOOLS_REVISION='ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'
readonly WIREGUARD_GO_REVISION='ecfc5a8d54462e18e13c72173e2623d16d8e25a0'
readonly GO_TOOLCHAIN_VERSION='go1.25.1'
readonly NODE_VERSION='v20.19.2'
readonly NPM_VERSION='9.2.0'
readonly APT_RELEASE_SOURCES="$SCRIPT_DIR/apt-snapshot.sources"
trap 'status=$?; log "ERROR: stage ${CURRENT_STAGE} failed (status ${status})"; exit "$status"' ERR
trap '[[ -z $BUILD_DIR ]] || rm -rf -- "$BUILD_DIR"' EXIT

log() {
    logger -t vs-router-bootstrap -- "$*" 2>/dev/null || true
    printf '[vs-router-bootstrap] %s\n' "$*"
}

binary_revision() {
    go version -m "$1" 2>/dev/null | awk '$1 == "build" && $2 ~ /^vcs\.revision=/ { sub(/^vcs\.revision=/, "", $2); print $2; exit }'
}

binary_toolchain() {
    go version -m "$1" 2>/dev/null | awk 'NR == 1 { sub(/^.*: /, ""); print $1 }'
}

module_version() {
    go version -m "$1" 2>/dev/null | awk -v module="$2" '$1 == "dep" && $2 == module { print $3; exit }'
}

apt_with_release() {
    apt-get \
        -o "Dir::Etc::sourcelist=${APT_RELEASE_SOURCES}" \
        -o 'Dir::Etc::sourceparts=-' \
        -o 'Acquire::Check-Valid-Until=false' \
        "$@"
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
    install -d -m 0700 /etc/vs-router
    install -d -m 0755 /etc/systemd/network
    printf '[Match]\nName=%s\nMACAddress=%s\n\n[Network]\nDHCP=ipv4\nKeepConfiguration=yes\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n\n[DHCPv4]\nClientIdentifier=mac\n' "$iface" "$mac" > "$file"
    chmod 0644 "$file"
    # Record temporary ownership using the agent's bundle format before activation.
    { printf '### FILE: %s\n' "${file##*/}"; cat "$file"; } > /etc/vs-router/networkd-manifest.conf
    # A minimal Debian Installer system may have an installed but inactive
    # dbus.socket. networkctl uses the system bus even if networkd itself starts.
    systemctl start dbus.socket
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
    [[ -s "$APT_RELEASE_SOURCES" ]] || fail "release APT source list missing: $APT_RELEASE_SOURCES"
    [[ -s /usr/share/keyrings/debian-archive-keyring.gpg ]] || fail 'Debian archive signing keyring missing'
    # Use one signed, date-pinned Debian snapshot for this release. Ignore
    # ambient APT sources only for these operations; preserve host sources for
    # future operator-managed security updates after bootstrap completes.
    apt_with_release update
    apt_with_release install -y dbus python3 python3-pip python3-venv python3-setuptools python3-wheel git build-essential golang-go \
        kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor wireguard-tools \
        socat curl nodejs npm debian-keyring debian-archive-keyring \
        openssh-server fail2ban python3-systemd
    local node_version npm_version go_version
    node_version=$(node --version)
    npm_version=$(npm --version)
    [[ $node_version == "$NODE_VERSION" ]] || fail "Node.js ${NODE_VERSION} required (found ${node_version})"
    [[ $npm_version == "$NPM_VERSION" ]] || fail "npm ${NPM_VERSION} required (found ${npm_version})"
    python3 -c 'import platform, sys; assert sys.version_info[:2] == (3, 13) and platform.machine() == "x86_64"' \
        || fail 'Python 3.13 on amd64 is required by the hashed runtime wheels'
    export GOTOOLCHAIN="${GO_TOOLCHAIN_VERSION}+auto"
    go_version=$(go version)
    [[ $go_version == "go version ${GO_TOOLCHAIN_VERSION} linux/amd64" ]] || fail "Go ${GO_TOOLCHAIN_VERSION} required (found ${go_version})"
}

stage_caddy() {
    if [[ -x /usr/local/bin/caddy ]] \
            && [[ $(/usr/local/bin/caddy version 2>/dev/null | awk '{print $1}') == "$CADDY_VERSION" ]] \
            && [[ $(module_version /usr/local/bin/caddy github.com/mholt/caddy-l4) == "$CADDY_L4_VERSION" ]] \
            && [[ $(module_version /usr/local/bin/caddy github.com/caddy-dns/cloudflare) == "$CLOUDFLARE_MODULE_VERSION" ]] \
            && [[ $(binary_toolchain /usr/local/bin/caddy) == "$GO_TOOLCHAIN_VERSION" ]] \
            && /usr/local/bin/caddy list-modules 2>/dev/null | grep -q layer4; then
        log 'Pinned Caddy build already exists; skipping build'
        return
    fi
    log 'Caddy build missing or unpinned; rebuilding'
    # The Cloudsmith xcaddy apt repo proved unreliable (config.txt may return
    # an empty body); go install is the dependable path since Go is required
    # for AmneziaWG anyway.
    export PATH="${PATH}:$(go env GOPATH 2>/dev/null || echo /root/go)/bin"
    if ! command -v xcaddy >/dev/null 2>&1 \
            || [[ $(xcaddy version 2>/dev/null | awk '{print $1}') != "$XCADDY_VERSION" ]]; then
        go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"
    fi
    [[ $(xcaddy version | awk '{print $1}') == "$XCADDY_VERSION" ]] || fail "xcaddy ${XCADDY_VERSION} required"
    xcaddy build "$CADDY_VERSION" \
        --with "github.com/mholt/caddy-l4@${CADDY_L4_VERSION}" \
        --with "github.com/caddy-dns/cloudflare@${CLOUDFLARE_MODULE_VERSION}" \
        --output /usr/local/bin/caddy
}

stage_awg() {
    BUILD_DIR=$(mktemp -d /var/lib/vs-router-build.XXXXXXXX)
    local workdir=$BUILD_DIR
    if [[ -x /usr/local/bin/awg-go ]] \
            && [[ $(binary_revision /usr/local/bin/awg-go) == "$AMNEZIAWG_GO_REVISION" ]] \
            && [[ $(binary_toolchain /usr/local/bin/awg-go) == "$GO_TOOLCHAIN_VERSION" ]]; then
        log 'Pinned AmneziaWG Go binary already exists; skipping build'
    else
        if [[ -d "$workdir/amneziawg-go/.git" ]]; then
            [[ $(git -C "$workdir/amneziawg-go" rev-parse HEAD) == "$AMNEZIAWG_GO_REVISION" ]] || fail 'AmneziaWG Go checkout revision mismatch'
        else
            git clone --branch "$AMNEZIAWG_VERSION" --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$workdir/amneziawg-go"
            [[ $(git -C "$workdir/amneziawg-go" rev-parse HEAD) == "$AMNEZIAWG_GO_REVISION" ]] || fail 'AmneziaWG Go tag revision mismatch'
        fi
        make -C "$workdir/amneziawg-go"
        install -m 0755 "$workdir/amneziawg-go/amneziawg-go" /usr/local/bin/awg-go
    fi
    if [[ -x /usr/local/bin/awg && -x /usr/local/bin/awg-quick ]] \
            && [[ $(/usr/local/bin/awg --version 2>/dev/null) == "amneziawg-tools ${AMNEZIAWG_VERSION} - "* ]]; then
        log 'Pinned AmneziaWG tools already exist; skipping build'
    else
        if [[ -d "$workdir/amneziawg-tools/.git" ]]; then
            [[ $(git -C "$workdir/amneziawg-tools" rev-parse HEAD) == "$AMNEZIAWG_TOOLS_REVISION" ]] || fail 'AmneziaWG tools checkout revision mismatch'
        else
            git clone --branch "$AMNEZIAWG_VERSION" --depth 1 https://github.com/amnezia-vpn/amneziawg-tools "$workdir/amneziawg-tools"
            [[ $(git -C "$workdir/amneziawg-tools" rev-parse HEAD) == "$AMNEZIAWG_TOOLS_REVISION" ]] || fail 'AmneziaWG tools tag revision mismatch'
        fi
        # The binary is built as 'wg' and 'make install' renames it to awg
        # (plus the awg-quick bash script) — no manual file copying.
        make -C "$workdir/amneziawg-tools/src" PREFIX=/usr BINDIR=/usr/local/bin install
    fi
    if [[ -x /usr/local/bin/wg-go ]] \
            && [[ $(binary_revision /usr/local/bin/wg-go) == "$WIREGUARD_GO_REVISION" ]] \
            && [[ $(binary_toolchain /usr/local/bin/wg-go) == "$GO_TOOLCHAIN_VERSION" ]]; then
        log 'Pinned WireGuard Go binary already exists; skipping build'
    else
        if [[ -d "$workdir/wireguard-go/.git" ]]; then
            [[ $(git -C "$workdir/wireguard-go" rev-parse HEAD) == "$WIREGUARD_GO_REVISION" ]] || fail 'WireGuard Go checkout revision mismatch'
        else
            # Fetch by immutable revision; the upstream Git server is unreliable from some networks.
            git init "$workdir/wireguard-go"
            git -C "$workdir/wireguard-go" fetch --depth 1 \
                https://github.com/WireGuard/wireguard-go "$WIREGUARD_GO_REVISION"
            git -C "$workdir/wireguard-go" checkout --detach FETCH_HEAD
            [[ $(git -C "$workdir/wireguard-go" rev-parse HEAD) == "$WIREGUARD_GO_REVISION" ]] || fail 'WireGuard Go revision mismatch'
        fi
        make -C "$workdir/wireguard-go"
        install -m 0755 "$workdir/wireguard-go/wireguard-go" /usr/local/bin/wg-go
    fi
}

stage_build() {
    if ((SKIP_BUILD)); then
        log 'Build skipped by --skip-build'
        return
    fi
    (cd "$REPO_ROOT/frontend"; npm ci; npm run build)
    rm -f "$REPO_ROOT/backend/dist/"*.whl
    (cd "$REPO_ROOT/backend"; python3 -m pip wheel --no-build-isolation --no-deps -w dist .)
    test -s "$REPO_ROOT/frontend/dist/index.html"
}

stage_install() {
    local wheel_dir="$REPO_ROOT/backend/dist"
    compgen -G "$wheel_dir/*.whl" >/dev/null || fail "no backend wheel found in ${wheel_dir}"
    python3 -m pip install --break-system-packages --force-reinstall --no-deps "$wheel_dir"/*.whl
    # Runtime wheel hashes come from the committed uv.lock export.
    bash "$SCRIPT_DIR/install-runtime-deps.sh" "$REPO_ROOT/backend/requirements-runtime.txt"

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
