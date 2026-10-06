#!/usr/bin/env bash
# Update the vs-router application code and built distribution ("distro") on a
# running server, without reinstalling OS packages or rebuilding the toolchain
# (Caddy, amneziawg-tools, wireguard-go) that bootstrap.sh provisioned.
#
# Release channel (ADR-0010): an update installs a PINNED, verified release —
# a manifest (release.json) plus a tar.gz artifact of one commit. There is no
# `git fetch`, no branch and no `latest` git ref (ADR-0005); a self-contained
# ISO install has no `.git` (ADR-0008), so the artifact is downloaded and
# checked by SHA-256 and by the REVISION file inside the archive.
#
# What it does:
#   1. resolve a pinned release from a manifest and download its artifact
#   2. verify source_sha256 and REVISION == manifest commit, extract to
#      /opt/vs-router.new and keep the previous tree at /opt/vs-router.prev
#   3. rebuild the frontend static bundle (frontend/dist) and the backend wheel
#   4. reinstall the Python package (system python, matching bootstrap.sh)
#   5. apply database migrations (alembic upgrade head) against the live DB
#   6. deploy the UI bundle + systemd units via install.sh
#   7. restart the runtime services
#
# Re-run bootstrap.sh only when OS-level dependencies or the toolchain change
# (new Caddy/AmneziaWG/WireGuard builds, new apt packages).
#
# Usage:
#   update.sh [--release <40-hex-commit> | --manifest <url>]
#             [--manifest-url <url>] [--skip-build] [--help]
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
DB=/var/lib/vs-router/vs-router.db

log()  { printf '[vs-router-update] %s\n' "$*" >&2; }
warn() { printf '[vs-router-update] WARNING: %s\n' "$*" >&2; }
fail() { printf '[vs-router-update] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: update.sh [--release <40-hex-commit> | --manifest <url>]
                 [--manifest-url <url>] [--skip-build] [--help]
  --release SHA  Install this pinned release (requires a manifest URL whose
                 commit equals SHA; never a branch or `latest`).
  --manifest URL Install the release described by this manifest (release.json).
  --manifest-url URL  Manifest URL used with --release
                 ($VS_ROUTER_UPDATE_MANIFEST_URL by default).
  --skip-build   Do not rebuild frontend/backend; deploy what is already built.
  --skip-pull    Deprecated no-op.
  --help         Show this help.
Without --release/--manifest, rebuild and redeploy the current tree.
EOF
}

fetch() {  # url dest — https only, failure is fatal
    command -v curl >/dev/null 2>&1 || fail 'curl is required to download a release'
    curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
        -o "$2" "$1" || fail "download failed: $1"
}

manifest_field() {  # file key -> value on stdout
    python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as handle:
    data = json.load(handle)
value = data.get(sys.argv[2])
print(value if isinstance(value, str) else '')
PY
}

stage_release() {
    local tmp commit source_url sha revision stage prev
    local -a args
    if [[ -z $MANIFEST ]]; then
        [[ -n $MANIFEST_URL ]] || fail 'a manifest URL is required for a pinned release: pass --manifest <url> or set VS_ROUTER_UPDATE_MANIFEST_URL'
        MANIFEST=$MANIFEST_URL
    fi
    case $MANIFEST in
        https://*) : ;;
        *) fail "manifest URL must be https (got: ${MANIFEST})" ;;
    esac

    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    log "Fetching release manifest ${MANIFEST}"
    fetch "$MANIFEST" "$tmp/release.json"

    commit=$(manifest_field "$tmp/release.json" commit) || fail "manifest is not valid JSON: ${MANIFEST}"
    source_url=$(manifest_field "$tmp/release.json" source_url) || fail "manifest is not valid JSON: ${MANIFEST}"
    sha=$(manifest_field "$tmp/release.json" source_sha256) || fail "manifest is not valid JSON: ${MANIFEST}"
    [[ $commit =~ ^[0-9a-f]{40}$ ]] || fail "manifest commit is not a full commit id: '${commit}'"
    [[ $sha =~ ^[0-9a-f]{64}$ ]] || fail "manifest source_sha256 is not a sha256: '${sha}'"
    [[ -n $source_url ]] || fail 'manifest source_url is empty'
    case $source_url in
        https://*) : ;;
        *) fail "manifest source_url must be https (got: ${source_url})" ;;
    esac
    if [[ -n ${RELEASE:-} && $RELEASE != "$commit" ]]; then
        fail "--release ${RELEASE} does not match manifest commit ${commit}"
    fi
    log "Manifest release commit ${commit}"

    fetch "$source_url" "$tmp/source.tar.gz"
    printf '%s  %s\n' "$sha" "$tmp/source.tar.gz" | sha256sum -c - >/dev/null \
        || fail 'release artifact SHA-256 does not match the manifest'
    # Refuse archives with absolute or parent-escaping paths before unpacking.
    if tar -tzf "$tmp/source.tar.gz" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
        fail 'release artifact contains unsafe paths'
    fi

    stage=$REPO_ROOT.new
    rm -rf "$stage"
    mkdir -p "$stage"
    tar -xzf "$tmp/source.tar.gz" -C "$stage" --no-same-owner \
        || fail 'release extraction failed'
    [[ -f "$stage/REVISION" ]] || fail 'release artifact lacks a REVISION file'
    revision=$(tr -d '[:space:]' < "$stage/REVISION")
    [[ $revision == "$commit" ]] || fail "REVISION (${revision}) does not match manifest commit (${commit})"
    [[ -f "$stage/backend/packaging/install.sh" && -d "$stage/frontend" && -f "$stage/backend/pyproject.toml" ]] \
        || fail 'release artifact is not a vs-router source tree'

    prev=$REPO_ROOT.prev
    rm -rf "$prev"
    mv "$REPO_ROOT" "$prev"
    mv "$stage" "$REPO_ROOT"
    log "Staged release ${commit}; previous tree kept at ${prev}"

    rm -rf "$tmp"
    trap - EXIT
    # Continue in the freshly staged tree so its update.sh drives the build;
    # re-exec avoids reading this script file after its directory was replaced.
    args=(--staged)
    (( SKIP_BUILD )) && args+=(--skip-build)
    exec bash "$REPO_ROOT/backend/packaging/update.sh" "${args[@]}"
}

main() {
    RELEASE=
    MANIFEST=
    MANIFEST_URL=${VS_ROUTER_UPDATE_MANIFEST_URL:-}
    SKIP_BUILD=0
    STAGED=0
    while (($#)); do
        case $1 in
            --release)      RELEASE=${2:-}; shift ;;
            --manifest)     MANIFEST=${2:-}; shift ;;
            --manifest-url) MANIFEST_URL=${2:-}; shift ;;
            --skip-pull)    warn '--skip-pull is deprecated; omit --release to update the current tree' ;;
            --skip-build)   SKIP_BUILD=1 ;;
            --staged)       STAGED=1 ;;  # internal: the tree was just staged by this script
            --help|-h)      usage; exit 0 ;;
            *) usage >&2; fail "unknown option: $1" ;;
        esac
        shift
    done

    if [[ -n $RELEASE && ! $RELEASE =~ ^[0-9a-f]{40}$ ]]; then
        fail "--release requires a full 40-character commit id (got: ${RELEASE})"
    fi
    [[ -z $RELEASE || -z $MANIFEST ]] || fail 'use either --release or --manifest, not both'

    if [[ ${EUID} -ne 0 ]]; then
        fail 'run this script as root (sudo ./update.sh)'
    fi

    if (( ! STAGED )) && [[ -n $RELEASE || -n $MANIFEST ]]; then
        stage_release
    elif (( ! STAGED )) && [[ -z $RELEASE && -z $MANIFEST ]]; then
        log 'No --release/--manifest given; updating from the currently checked-out tree'
    fi

    cd "$REPO_ROOT"

    if (( ! SKIP_BUILD )); then
        log 'Building frontend bundle'
        ( cd "$REPO_ROOT/frontend" && npm ci && npm run build )
        log 'Building backend wheel'
        ( cd "$REPO_ROOT/backend" && rm -rf dist && python3 -m pip wheel --no-build-isolation --no-deps -w dist . )
    fi

    log 'Installing backend package'
    local wheel_dir="$REPO_ROOT/backend/dist"
    compgen -G "$wheel_dir"/*.whl >/dev/null || fail "no backend wheel found in ${wheel_dir} (run without --skip-build)"
    python3 -m pip install --break-system-packages --force-reinstall --no-deps "$wheel_dir"/*.whl
    bash "$SCRIPT_DIR/install-runtime-deps.sh" "$REPO_ROOT/backend/requirements-runtime.txt"

    log 'Applying database migrations'
    if [ -f "$DB" ]; then
        ( cd "$REPO_ROOT/backend" && VS_ROUTER_DATABASE_URL="sqlite:///${DB}" python3 -m alembic upgrade head ) \
            || fail 'alembic upgrade failed; the database was not migrated'
    else
        warn "DB not found at ${DB}; skipping migrations (fresh install will create it)"
    fi

    log 'Deploying UI bundle and systemd units'
    VS_ROUTER_RELEASE_SOURCE=online bash "$SCRIPT_DIR/install.sh"

    log 'Restarting runtime services'
    systemctl daemon-reload
    systemctl restart vs-router-agent vs-router-web \
        || fail 'one or more runtime services failed to restart; check systemctl status'

    log 'Update complete. Verify: systemctl status vs-router-web vs-router-agent'
}

# Only run when executed, never when sourced (tests source this file to drive
# stage_release with a stub fetch()).
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
