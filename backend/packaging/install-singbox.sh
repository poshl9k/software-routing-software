#!/usr/bin/env bash
# Deliver the pinned sing-box engine binary (ADR-0012) to the fixed path the
# agent's adapter expects: /usr/local/lib/vs-router/sing-box.
#
# Trust is anchored on a pinned SHA-256 (ADR-0005/0012), not on the download
# host: the archive digest is checked before extraction, and the extracted ELF
# digest *and* its build provenance revision are checked before anything is
# installed. Any mismatch fails closed and leaves the destination untouched.
#
# Idempotent: an already-correct pinned binary is kept and the network is not
# touched. This is an install-time script run by root (from bootstrap.sh); it
# never uses an agent RPC, takes no path or argument from the RPC surface, and
# uses no shell interpolation of caller data. It is additive to bootstrap/update
# and does not replace any existing step.
#
# Offline/mirror use: VS_ROUTER_SINGBOX_ARCHIVE may point at a locally available
# copy of the *pinned* archive (an air-gapped mirror); the pinned SHA-256 is
# still enforced, so a different or tampered archive fails closed. The URL pin
# is likewise only a default, never a trust source: the hash always decides.
set -Eeuo pipefail
umask 022

# --- pinned release (keep in sync with agent/singbox_service.py, ADR-0012) ---
readonly SINGBOX_VERSION='1.14.2'
readonly SINGBOX_TAG='v1.14.2'
readonly SINGBOX_ARCHIVE_DIR="sing-box-${SINGBOX_VERSION}-linux-amd64"
readonly SINGBOX_PINNED_URL="https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_TAG}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
readonly SINGBOX_ARCHIVE_SHA256='a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6'
readonly SINGBOX_BINARY_SHA256='fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8'
readonly SINGBOX_PROVENANCE_REVISION='af6e64c3b69e6132ebaee0e1a3d24e93903f6709'

# Fixed absolute destination the agent runs; overridable only for offline lab.
readonly SINGBOX_DEFAULT_DEST='/usr/local/lib/vs-router/sing-box'
DEST=${VS_ROUTER_SINGBOX_DEST:-$SINGBOX_DEFAULT_DEST}
SOURCE_ARCHIVE=${VS_ROUTER_SINGBOX_ARCHIVE:-}
URL=${VS_ROUTER_SINGBOX_URL:-$SINGBOX_PINNED_URL}

log()  { printf '[vs-router-singbox] %s\n' "$*"; }
fail() { printf '[vs-router-singbox] ERROR: %s\n' "$*" >&2; exit 1; }

# sha_of PATH -> lowercase sha256 (empty on error). Overridable seam for tests.
sha_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# Working directory for download/extraction, removed on exit. Global (not a
# `local`) so the EXIT trap can still reach it after main() returns.
WORK=''
cleanup() { [[ -z $WORK ]] || rm -rf -- "$WORK"; }
trap cleanup EXIT

# binary_ok PATH -> 0 iff the file is the pinned digest *and* reports the pinned
# version and provenance revision. Mirrors agent.singbox_service verification so
# an install is never accepted where the agent's fail-closed check would reject.
binary_ok() {
    local path=$1 report
    [[ -f $path && -x $path ]] || return 1
    [[ $(sha_of "$path") == "$SINGBOX_BINARY_SHA256" ]] || return 1
    report=$("$path" version 2>/dev/null) || return 1
    printf '%s\n' "$report" | grep -qx "sing-box version ${SINGBOX_VERSION}" || return 1
    printf '%s\n' "$report" | grep -qx "Revision: ${SINGBOX_PROVENANCE_REVISION}" || return 1
    return 0
}

fetch_archive() {  # $1 destination file
    if [[ -n $SOURCE_ARCHIVE ]]; then
        [[ -r $SOURCE_ARCHIVE ]] || fail "local archive is not readable: ${SOURCE_ARCHIVE}"
        log "using local sing-box archive ${SOURCE_ARCHIVE}"
        cp -- "$SOURCE_ARCHIVE" "$1" || fail 'could not copy the local archive'
        return
    fi
    command -v curl >/dev/null 2>&1 || fail 'curl is required to download the pinned sing-box archive'
    log "downloading pinned sing-box ${SINGBOX_VERSION} from ${URL}"
    curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
        -o "$1" "$URL" || fail "download failed: ${URL}"
}

verify_archive() {  # $1 archive path
    printf '%s  %s\n' "$SINGBOX_ARCHIVE_SHA256" "$1" | sha256sum -c - >/dev/null \
        || fail 'archive SHA-256 does not match the ADR-0012 pin'
    if tar -tzf "$1" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
        fail 'archive contains unsafe paths'
    fi
}

install_from_archive() {  # $1 archive path
    local extracted report
    verify_archive "$1"
    tar -xzf "$1" -C "$WORK" --no-same-owner || fail 'archive extraction failed'
    extracted="$WORK/${SINGBOX_ARCHIVE_DIR}/sing-box"
    [[ -f $extracted ]] || fail 'archive does not contain the expected sing-box binary'
    printf '%s  %s\n' "$SINGBOX_BINARY_SHA256" "$extracted" | sha256sum -c - >/dev/null \
        || fail 'extracted binary SHA-256 does not match the ADR-0012 pin'
    report=$("$extracted" version 2>/dev/null) || fail 'extracted binary did not report a version'
    printf '%s\n' "$report" | grep -qx "sing-box version ${SINGBOX_VERSION}" \
        || fail "extracted binary version is not ${SINGBOX_VERSION}"
    printf '%s\n' "$report" | grep -qx "Revision: ${SINGBOX_PROVENANCE_REVISION}" \
        || fail 'extracted binary provenance revision does not match ADR-0012'
    install -d -m 0755 "$(dirname -- "$DEST")"
    install -m 0755 -o root -g root "$extracted" "$DEST"
    log "installed pinned sing-box ${SINGBOX_VERSION} at ${DEST}"
}

main() {
    if binary_ok "$DEST"; then
        log "pinned sing-box ${SINGBOX_VERSION} already present and verified at ${DEST}; nothing to do"
        return 0
    fi
    local archive
    WORK=$(mktemp -d)
    archive="$WORK/sing-box.tar.gz"
    fetch_archive "$archive"
    install_from_archive "$archive"
}

# Run only when executed, never when sourced (tests source this to exercise the
# idempotency and fail-closed branches with stubbed host commands).
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
