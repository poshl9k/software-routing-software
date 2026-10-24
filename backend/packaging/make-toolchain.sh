#!/usr/bin/env bash
# Build the pinned compiled toolchain (Caddy, AmneziaWG, WireGuard-go) on the
# WORKSTATION — not on the target host — and package it as a releaseable bundle.
#
# Why: online-install.sh and bootstrap.sh currently compile these on the host
# (the Go builds are the memory peak of a ≈1 GB VPS install). A prebuilt,
# hash-verified bundle lets both installers skip the build entirely.
#
# The bundle identity is the TOOLCHAIN PINS, not the app commit: the binaries
# depend only on the upstream versions pinned in bootstrap.sh, so a release that
# keeps the same pins reuses the existing bundle unchanged.
#
# Statically linked where possible (CGO_ENABLED=0 for Go binaries, -static for
# the C awg tool) so the bundle is amd64-only and NOT tied to the build host's
# glibc — Debian 13, Ubuntu, anything with a Linux kernel can run it.
#
# Usage:
#   make-toolchain.sh [--out DIR] [--force] [--check] [--upload] [--print-id] [--help]
#     --out DIR   output directory (default: <repo>/release/toolchain)
#     --force     rebuild even if the cache already holds this toolchain bundle
#     --check     verify the cached bundle against its manifest; no build
#     --upload    publish the bundle as a GitHub Release asset (tag
#                 toolchain-<id>; requires `gh` auth)
#     --print-id  print the toolchain id for the current pins and exit (no build)
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

OUT=${VS_ROUTER_TOOLCHAIN_OUT:-$REPO_ROOT/release/toolchain}
FORCE=0
CHECK=0
PRINT_ID=0
UPLOAD=0
ARCH=amd64

usage() {
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while (($#)); do
    case $1 in
        --out)    OUT=${2:?--out needs a directory}; shift ;;
        --force)  FORCE=1 ;;
        --check)  CHECK=1 ;;
        --upload) UPLOAD=1 ;;
        --print-id) PRINT_ID=1 ;;
        --help|-h) usage; exit 0 ;;
        --*)      usage >&2; echo "unknown option: $1" >&2; exit 1 ;;
        *)        usage >&2; echo "unexpected argument: $1" >&2; exit 1 ;;
    esac
    shift
done

log()  { printf '[make-toolchain] %s\n' "$*" >&2; }
fail() { printf '[make-toolchain] ERROR: %s\n' "$*" >&2; exit 1; }

# Single source of truth for the pins: bootstrap.sh holds the readonly
# variables; sourcing it defines them without running its stages (main is
# guarded by ${BASH_SOURCE[0]} == $0).
# shellcheck disable=SC1091
source "$SCRIPT_DIR/bootstrap.sh"

PINS=(
    "arch=$ARCH"
    "caddy=$CADDY_VERSION"
    "caddy-l4=$CADDY_L4_VERSION"
    "caddy-cloudflare=$CLOUDFLARE_MODULE_VERSION"
    "xcaddy=$XCADDY_VERSION"
    "amneziawg=$AMNEZIAWG_VERSION"
    "amneziawg-go-rev=$AMNEZIAWG_GO_REVISION"
    "amneziawg-tools-rev=$AMNEZIAWG_TOOLS_REVISION"
    "wireguard-go-rev=$WIREGUARD_GO_REVISION"
    "go=$GO_TOOLCHAIN_VERSION"
)
pins_tmp=$(mktemp)
printf '%s\n' "${PINS[@]}" > "$pins_tmp"
TOOLCHAIN_ID=$(sha256sum "$pins_tmp" | awk '{print substr($1, 1, 16)}')
rm -f "$pins_tmp"
if (( PRINT_ID )); then
    printf '%s\n' "$TOOLCHAIN_ID"
    exit 0
fi

bundle_name="toolchain-$ARCH-$TOOLCHAIN_ID.tar.gz"
bundle_tar="$OUT/$bundle_name"
manifest="$OUT/toolchain-$TOOLCHAIN_ID.json"

verify_bundle() {
    [[ -f $bundle_tar && -f $manifest ]] \
        || fail "cached bundle incomplete: $bundle_tar / $manifest"
    local recorded actual
    recorded=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['bundle_sha256'])" "$manifest")
    actual=$(sha256sum "$bundle_tar" | awk '{print $1}')
    [[ $recorded == "$actual" ]] \
        || fail "bundle sha mismatch: manifest $recorded, file $actual"
    log "Bundle verified: $bundle_tar ($actual)"
}

if (( CHECK )); then
    verify_bundle
    exit 0
fi

if [[ -f $bundle_tar ]]; then
    if (( FORCE )); then
        log "Rebuilding (forced): toolchain $TOOLCHAIN_ID"
    elif (( ! UPLOAD )); then
        log "Bundle for toolchain $TOOLCHAIN_ID already exists: $bundle_tar"
        log 'Pins unchanged; pass --force to rebuild'
        exit 0
    else
        # An existing bundle is a valid upload source: verify it before publishing.
        log "Bundle for toolchain $TOOLCHAIN_ID already exists: $bundle_tar; uploading it"
    fi
fi
if (( UPLOAD )) && [[ -f $bundle_tar && $FORCE == 0 ]]; then
    verify_bundle
fi

command -v go >/dev/null 2>&1 || fail 'go is required (https://go.dev/dl/)'
command -v git >/dev/null 2>&1 || fail 'git is required'
command -v make >/dev/null 2>&1 || fail 'make is required'
command -v gcc >/dev/null 2>&1 || fail 'gcc is required (awg tools are C)'

# Pin the exact Go toolchain: a different toolchain version changes the binary
# and the `go version -m` identity the installers verify.
export GOTOOLCHAIN="${GO_TOOLCHAIN_VERSION}+auto"
export CGO_ENABLED=0
export PATH="$PATH:$(go env GOPATH)/bin"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$OUT" "$stage/bins" "$stage/tmp"
export TMPDIR="$stage/tmp" GOTMPDIR="$stage/tmp"
log "Toolchain id: $TOOLCHAIN_ID  (pins: ${PINS[*]})"

# --- Caddy (xcaddy, pure Go, static) -----------------------------------------
if ! command -v xcaddy >/dev/null 2>&1; then
    log "Installing xcaddy $XCADDY_VERSION"
    go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"
fi
log "Building Caddy $CADDY_VERSION (+l4 $CADDY_L4_VERSION, cloudflare $CLOUDFLARE_MODULE_VERSION)"
(cd "$stage" && xcaddy build "$CADDY_VERSION" \
    --with "github.com/mholt/caddy-l4@${CADDY_L4_VERSION}" \
    --with "github.com/caddy-dns/cloudflare@${CLOUDFLARE_MODULE_VERSION}" \
    --output "$stage/bins/caddy")

# --- AmneziaWG Go daemon (pure Go, static) -----------------------------------
log "Cloning amneziawg-go $AMNEZIAWG_VERSION"
git clone --branch "$AMNEZIAWG_VERSION" --depth 1 \
    https://github.com/amnezia-vpn/amneziawg-go "$stage/amneziawg-go"
rev=$(git -C "$stage/amneziawg-go" rev-parse HEAD)
[[ $rev == "$AMNEZIAWG_GO_REVISION" ]] \
    || fail "amneziawg-go tag moved: expected $AMNEZIAWG_GO_REVISION, got $rev"
log 'Building awg-go'
make -C "$stage/amneziawg-go" CGO_ENABLED=0
install -m 0755 "$stage/amneziawg-go/amneziawg-go" "$stage/bins/awg-go"

# --- AmneziaWG tools (C, static so the bundle is glibc-independent) ----------
log "Cloning amneziawg-tools $AMNEZIAWG_VERSION"
git clone --branch "$AMNEZIAWG_VERSION" --depth 1 \
    https://github.com/amnezia-vpn/amneziawg-tools "$stage/amneziawg-tools"
rev=$(git -C "$stage/amneziawg-tools" rev-parse HEAD)
[[ $rev == "$AMNEZIAWG_TOOLS_REVISION" ]] \
    || fail "amneziawg-tools tag moved: expected $AMNEZIAWG_TOOLS_REVISION, got $rev"
log 'Building awg tools (static)'
# The Makefile's `install` target renames the built 'wg' to 'awg' and places
# the 'awg-quick' bash script next to it — exactly how bootstrap.sh installs it.
# PREFIX is redirected so the man pages and the runtime config dir
# ($(SYSCONFDIR)/amnezia/amneziawg) do not require root on the workstation.
make -C "$stage/amneziawg-tools/src" LDFLAGS="-static" \
    PREFIX="$stage/prefix" BINDIR="$stage/bins" SYSCONFDIR="$stage/prefix/etc" \
    WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no install
[[ -f $stage/bins/awg ]] || fail 'the tools build did not produce the awg binary'
[[ -f $stage/bins/awg-quick ]] || fail 'the tools build did not produce the awg-quick script'

# --- WireGuard-go fallback (pure Go, static) ---------------------------------
log "Cloning wireguard-go $WIREGUARD_GO_REVISION"
git init -q "$stage/wireguard-go"
git -C "$stage/wireguard-go" fetch --depth 1 \
    https://github.com/WireGuard/wireguard-go "$WIREGUARD_GO_REVISION"
git -C "$stage/wireguard-go" checkout --detach FETCH_HEAD
log 'Building wg-go'
make -C "$stage/wireguard-go" CGO_ENABLED=0
install -m 0755 "$stage/wireguard-go/wireguard-go" "$stage/bins/wg-go"

# --- Verify: static, runnable, pinned identity --------------------------------
log 'Verifying binaries'
for bin in caddy awg-go awg wg-go; do
    file "$stage/bins/$bin" | grep -q 'statically linked' \
        || fail "$bin is not statically linked"
done
"$stage/bins/caddy" version | grep -q "$CADDY_VERSION" \
    || fail "caddy reports the wrong version: $("$stage/bins/caddy" version 2>&1 | head -1)"
"$stage/bins/awg" --version 2>&1 | grep -q "amneziawg-tools ${AMNEZIAWG_VERSION}" \
    || fail "awg reports the wrong version: $("$stage/bins/awg" --version 2>&1 | head -1)"

# --- Package + manifest --------------------------------------------------------
tar -czf "$bundle_tar" -C "$stage/bins" .
names=(caddy awg-go awg awg-quick wg-go)
{
    printf '{\n'
    printf '  "arch": "%s",\n' "$ARCH"
    printf '  "toolchain_id": "%s",\n' "$TOOLCHAIN_ID"
    printf '  "bundle_name": "%s",\n' "$bundle_name"
    printf '  "bundle_sha256": "%s",\n' "$(sha256sum "$bundle_tar" | awk '{print $1}')"
    printf '  "pins": {\n'
    for i in "${!PINS[@]}"; do
        key=${PINS[$i]%%=*}; value=${PINS[$i]#*=}
        comma=,
        [[ $i -eq $(( ${#PINS[@]} - 1 )) ]] && comma=
        printf '    "%s": "%s"%s\n' "$key" "$value" "$comma"
    done
    printf '  },\n'
    printf '  "binaries": {\n'
    for i in "${!names[@]}"; do
        name=${names[$i]}
        sha=$(sha256sum "$stage/bins/$name" | awk '{print $1}')
        comma=,
        [[ $i -eq $(( ${#names[@]} - 1 )) ]] && comma=
        printf '    "%s": "%s"%s\n' "$name" "$sha" "$comma"
    done
    printf '  }\n}\n'
} > "$manifest"
verify_bundle

log "Bundle:    $bundle_tar"
log "Manifest:  $manifest"
log "Toolchain: $TOOLCHAIN_ID"

if (( UPLOAD )); then
    command -v gh >/dev/null 2>&1 || fail 'gh is required for --upload'
    tag="toolchain-$TOOLCHAIN_ID"
    if gh release view "$tag" >/dev/null 2>&1; then
        log "Release $tag already exists; uploading the bundle with --clobber"
        gh release upload "$tag" --clobber "$bundle_tar" "$manifest"
    else
        gh release create "$tag" \
            --title "vs-router toolchain $TOOLCHAIN_ID ($ARCH)" \
            --notes "Pinned compiled toolchain bundle. Pins: ${PINS[*]}" \
            "$bundle_tar" "$manifest"
    fi
    log "Uploaded to GitHub Release $tag"
fi
