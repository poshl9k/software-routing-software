#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CURRENT_STAGE=initialization
LAB_MODE=0
SKIP_BUILD=0
KEA_PASSWORD=''

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
    if "$@"; then
        log "Completed stage: ${stage}"
    else
        local status=$?
        fail "command returned status ${status}"
    fi
}

usage() {
    cat <<'EOF'
Usage: bootstrap.sh [--lab] [--skip-build] [--help]
  --lab         Enable the plain HTTP TCP bridge on port 8080 and insecure cookies.
  --skip-build  Skip frontend and backend builds; use existing backend wheels.
  --help        Show this help.
EOF
}

parse_args() {
    while (($#)); do
        case $1 in
            --lab) LAB_MODE=1 ;;
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
    [[ -f /etc/debian_version ]] || fail 'Debian is required'
    local version
    version=$(< /etc/debian_version)
    [[ $version == 12* || $version == 13* ]] || fail "Debian 12 or 13 required (found ${version})"
    log "Detected Debian ${version}"
}

stage_apt_deps() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3 python3-pip python3-venv git build-essential golang-go \
        kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor wireguard-tools \
        socat curl nodejs npm debian-keyring debian-archive-keyring
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
    xcaddy build --with github.com/mholt/caddy-l4 --with github.com/caddy-dns/cloudflare \
        --output /usr/local/bin/caddy
}

stage_awg() {
    local workdir=/tmp/vs-router-bootstrap
    install -d "$workdir"
    if [[ ! -x /usr/local/bin/awg-go ]]; then
        if [[ ! -d "$workdir/amneziawg-go/.git" ]]; then
            git clone https://github.com/amnezia-vpn/amneziawg-go "$workdir/amneziawg-go"
        fi
        make -C "$workdir/amneziawg-go"
        install -m 0755 "$workdir/amneziawg-go/amneziawg-go" /usr/local/bin/awg-go
    else
        log 'awg-go already exists; skipping build'
    fi
    if [[ ! -x /usr/local/bin/awg || ! -x /usr/local/bin/awg-quick ]]; then
        if [[ ! -d "$workdir/amneziawg-tools/.git" ]]; then
            git clone https://github.com/amnezia-vpn/amneziawg-tools "$workdir/amneziawg-tools"
        fi
        make -C "$workdir/amneziawg-tools/src"
        install -m 0755 "$workdir/amneziawg-tools/src/awg" /usr/local/bin/awg
        install -m 0755 "$workdir/amneziawg-tools/src/awg-quick" /usr/local/bin/awg-quick
    else
        log 'awg and awg-quick already exist; skipping build'
    fi
    if [[ ! -x /usr/local/bin/wg-go ]]; then
        if [[ ! -d "$workdir/wireguard-go/.git" ]]; then
            git clone https://git.zx2c4.com/wireguard-go "$workdir/wireguard-go"
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
    (cd "$REPO_ROOT/frontend" && npm install && npm run build)
    (cd "$REPO_ROOT/backend" && python3 -m pip wheel --no-deps -w dist .)
}

stage_install() {
    local wheel_dir="$REPO_ROOT/backend/dist"
    compgen -G "$wheel_dir/*.whl" >/dev/null || fail "no backend wheel found in ${wheel_dir}"
    python3 -m pip install --break-system-packages "$wheel_dir"/*.whl

    install -d -m 0700 /etc/vs-router
    if [[ ! -f /etc/vs-router/secrets.env ]]; then
        local secret_key
        secret_key=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
        printf 'VS_ROUTER_SECRET_KEY=%s\n' "$secret_key" > /etc/vs-router/secrets.env
        chmod 0600 /etc/vs-router/secrets.env
    fi

    if [[ ! -s /etc/kea/kea-api-password ]]; then
        KEA_PASSWORD="vsr-$(python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(18)))')"
        printf '%s\n' "$KEA_PASSWORD" > /etc/kea/kea-api-password
        chmod 0640 /etc/kea/kea-api-password
        chown root:_kea /etc/kea/kea-api-password
    else
        KEA_PASSWORD=$(< /etc/kea/kea-api-password)
    fi

    "$SCRIPT_DIR/install.sh"
    # Kea may be inactive on a fresh machine (no interfaces configured yet) —
    # its restart must not fail the bootstrap; the panel configures it later.
    systemctl restart kea-ctrl-agent kea-dhcp4-server 2>/dev/null || \
        log 'WARNING: kea services did not restart; the panel will configure them on first apply'

    # Wire the Kea ctrl-agent credentials into the web service so the leases
    # tab works out of the box (password file is root:_kea readable only).
    install -d -m 0755 /etc/systemd/system/vs-router-web.service.d
    cat > /etc/systemd/system/vs-router-web.service.d/kea-api.conf <<EOF
[Service]
Environment=VS_ROUTER_KEA_API_USER=kea-api
Environment=VS_ROUTER_KEA_API_PASSWORD=${KEA_PASSWORD}
EOF

    local enable_lab=$LAB_MODE
    if (( ! LAB_MODE )); then
        local answer
        read -r -p 'Enable lab TCP bridge on port 8080? [y/N] ' answer
        [[ $answer =~ ^[Yy]([Ee][Ss])?$ ]] && enable_lab=1 || enable_lab=0
    fi
    if ((enable_lab)); then
        install -d -m 0755 /etc/systemd/system/vs-router-web.service.d
        cat > /etc/systemd/system/vs-router-web.service.d/lab.conf <<'EOF'
[Service]
Environment=VS_ROUTER_COOKIE_SECURE=0
EOF
    fi
    systemctl daemon-reload
    systemctl enable --now vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer
    if ((enable_lab)); then
        systemctl enable --now vs-router-web-tcp.service
    fi
}

stage_summary() {
    local service status
    for service in vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer; do
        status=$(systemctl is-active "$service" 2>/dev/null || true)
        log "Service ${service}: ${status:-unknown}"
    done
    if systemctl is-enabled --quiet vs-router-web-tcp.service 2>/dev/null; then
        log 'Service vs-router-web-tcp.service: enabled (lab, TCP 8080)'
    else
        log 'Service vs-router-web-tcp.service: disabled'
    fi
    log 'Open the panel and complete first-run onboarding to create the administrator and configure the network.'
    log "Kea ctrl-agent credentials: username kea-api, password ${KEA_PASSWORD}"
    log 'Firewall reminder: add the 8080 rule through the panel for lab access, or put the panel behind an HTTPS proxy.'
}

main() {
    parse_args "$@"
    run_stage 'check:_root' stage_check_root
    run_stage 'apt:deps' stage_apt_deps
    run_stage 'caddy' stage_caddy
    run_stage 'awg' stage_awg
    run_stage 'build' stage_build
    run_stage 'install' stage_install
    run_stage 'summary' stage_summary
}

main "$@"
