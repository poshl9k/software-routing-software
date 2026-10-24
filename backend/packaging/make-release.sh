#!/usr/bin/env bash
# Build a pinned, verifiable vs-router release artifact for the ONLINE update
# channel (ADR-0010). Produces, in $OUT:
#   vs-router-<commit>.tar.gz   the pinned commit's tree, plus a REVISION file
#                               at the archive root, and — by default — the
#                               PREBUILT frontend bundle (frontend/dist) and
#                               backend wheel (backend/dist/*.whl), so an
#                               online install never builds on the host.
#   release.json                {commit, semver, source_url, source_sha256,
#                                min_os, toolchain?}
#   get.sh                      public entry with the same baked release pins
# The artifact format matches what the ISO vendors (ADR-0008): a `git archive`
# of one commit; the added REVISION lets a guest cross-check the archive
# against the manifest commit without any git history. source_sha256 covers the
# FINAL archive, so the prebuilt binaries are pinned exactly like the source.
# A default build also references the PREBUILT compiled-toolchain bundle for
# this release's pins (make-toolchain.sh): the toolchain section in release.json
# tells the host installers to download and verify the pinned Caddy/AWG binaries
# instead of building them. Without a bundle for these pins the section is
# omitted and the host builds as before.
#
# Usage:
#   VS_ROUTER_RELEASE_BASE_URL=<url> make-release.sh [<40-hex-commit>] [--upload]
#     <commit>         commit to release (default: current HEAD)
#     --out DIR        output directory (default: <repo>/release)
#     --base-url URL   public URL prefix holding the assets; source_url becomes
#                      "$BASE_URL/vs-router-<commit>.tar.gz". Required unless
#                      --upload (then derived from `gh repo view`).
#     --upload         create/update the GitHub Release and upload the assets
#                      with `gh` (requires gh auth and a pushed commit)
#     --skip-build     publish a SOURCE-ONLY artifact (legacy); the default
#                      builds frontend/dist and the backend wheel and fails
#                      closed when either is missing. Needs node+npm (and uv
#                      or pip) on the workstation running this script.
#     --help
#
# Never a branch or `latest` git ref (ADR-0005).
set -euo pipefail
umask 022

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

OUT=${VS_ROUTER_RELEASE_OUT:-$REPO_ROOT/release}
BASE_URL=${VS_ROUTER_RELEASE_BASE_URL:-}
UPLOAD=0
SKIP_BUILD=0
COMMIT=

usage() {
    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while (($#)); do
    case $1 in
        --out)      OUT=${2:?--out needs a directory}; shift ;;
        --base-url) BASE_URL=${2:?--base-url needs a URL}; shift ;;
        --upload)   UPLOAD=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --help|-h)  usage; exit 0 ;;
        --*)        usage >&2; echo "unknown option: $1" >&2; exit 1 ;;
        *)          COMMIT=$1 ;;
    esac
    shift
done

command -v git >/dev/null 2>&1 || { echo 'git is required' >&2; exit 1; }

if [[ -z $COMMIT ]]; then
    COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD)
fi
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "a full 40-character commit id is required (got: ${COMMIT})" >&2; exit 1; }
git -C "$REPO_ROOT" cat-file -e "${COMMIT}^{commit}" 2>/dev/null \
    || { echo "commit ${COMMIT} is not present in ${REPO_ROOT}" >&2; exit 1; }

semver=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$REPO_ROOT/backend/pyproject.toml" | head -n1)
[[ -n $semver ]] || semver=unknown

name="vs-router-${COMMIT}.tar.gz"
if [[ $UPLOAD == 1 ]]; then
    command -v gh >/dev/null 2>&1 || { echo 'gh is required for --upload' >&2; exit 1; }
    if [[ -z $BASE_URL ]]; then
        slug=$(gh repo view --json nameWithOwner -q .nameWithOwner) \
            || { echo 'could not resolve the GitHub repository with gh' >&2; exit 1; }
        BASE_URL="https://github.com/${slug}/releases/download/vs-router-${COMMIT}"
    fi
fi
if [[ -z $BASE_URL ]]; then
    echo "warning: no --base-url/VS_ROUTER_RELEASE_BASE_URL; release.json will carry a relative source_url" >&2
    source_url="$name"
else
    source_url="${BASE_URL%/}/$name"
fi

mkdir -p "$OUT"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# The tree of exactly this commit, plus the pinned REVISION at the root.
git -C "$REPO_ROOT" archive --format=tar "$COMMIT" | tar -x -C "$stage"
printf '%s\n' "$COMMIT" > "$stage/REVISION"

log()  { printf '[make-release] %s\n' "$*" >&2; }
fail() { printf '[make-release] ERROR: %s\n' "$*" >&2; exit 1; }

# Prebuilt bundle: build the compiled frontend and the backend wheel INTO the
# staged tree, so the published archive carries binaries and an online install
# never builds on the host (the npm build was the OOM wall on thin VPSes).
# git archive copies only tracked files, so no stale untracked dist is
# inherited; both outputs are built fresh and verified before tarring.
if (( ! SKIP_BUILD )); then
    command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 \
        || fail 'node and npm are required to build the frontend (or pass --skip-build)'
    if ! command -v uv >/dev/null 2>&1; then
        command -v python3 >/dev/null 2>&1 \
            && python3 -m pip --version >/dev/null 2>&1 \
            && python3 -c 'import setuptools, wheel' >/dev/null 2>&1 \
            || fail 'uv or python3+pip+setuptools+wheel is required to build the backend wheel (or pass --skip-build)'
    fi
    rm -rf "$stage/frontend/dist" "$stage/backend/dist"
    log 'Building frontend bundle (npm ci && npm run build)'
    (cd "$stage/frontend" && npm ci && npm run build)
    log 'Building backend wheel'
    if command -v uv >/dev/null 2>&1; then
        (cd "$stage/backend" && uv build --wheel --out-dir dist)
    else
        python3 -m pip wheel --no-deps --no-build-isolation -w "$stage/backend/dist" "$stage/backend"
    fi
    shopt -s nullglob
    wheels=("$stage/backend/dist"/*.whl)
    shopt -u nullglob
    (( ${#wheels[@]} == 1 )) \
        || fail "expected exactly one backend wheel in backend/dist (found ${#wheels[@]})"
    [[ -f $stage/frontend/dist/index.html && ! -L $stage/frontend/dist/index.html ]] \
        || fail 'frontend bundle missing after the build: frontend/dist/index.html'
    log "Prebuilt bundle: ${wheels[0]#$stage/} + frontend/dist"
fi

# Toolchain section (default build only): a release whose pins have a built
# compiled-toolchain bundle (release/toolchain/toolchain-<id>.json, published by
# make-toolchain.sh under its own immutable tag) references it from release.json
# — host installers then download and verify the pinned Go binaries instead of
# building them. The bundle id is the hash of the pins, so releases sharing the
# pins share the binaries; no bundle for these pins -> no section -> host builds.
tc_manifest=
tc_url=
if (( ! SKIP_BUILD )); then
    tc_id=$(bash "$SCRIPT_DIR/make-toolchain.sh" --print-id) \
        || fail 'cannot compute the toolchain id (make-toolchain.sh failed)'
    tc_manifest="$REPO_ROOT/release/toolchain/toolchain-$tc_id.json"
    if [[ ! -f $tc_manifest ]]; then
        log "WARNING: no toolchain bundle for pins $tc_id in release/toolchain; the host will build the Go binaries"
        tc_manifest=
    fi
    if [[ -n $tc_manifest && $BASE_URL == https://github.com/* ]]; then
        tc_url="${BASE_URL%%/releases/download*}/releases/download/toolchain-$tc_id/toolchain-amd64-$tc_id.tar.gz"
    elif [[ -n $tc_manifest ]]; then
        log 'WARNING: BASE_URL is not a github releases URL; skipping the toolchain section'
        tc_manifest=
    fi
fi

tar -czf "$OUT/$name" -C "$stage" .

sha256=$(sha256sum "$OUT/$name" | awk '{print $1}')
[[ $sha256 =~ ^[0-9a-f]{64}$ ]] || { echo 'sha256sum failed' >&2; exit 1; }

RELEASE_OUT="$OUT/release.json" RELEASE_COMMIT="$COMMIT" RELEASE_SEMVER="$semver" \
RELEASE_URL="$source_url" RELEASE_SHA="$sha256" \
RELEASE_TOOLCHAIN="$tc_manifest" RELEASE_TOOLCHAIN_URL="$tc_url" python3 - <<'PY'
import json, os
manifest = {
    'commit': os.environ['RELEASE_COMMIT'],
    'semver': os.environ['RELEASE_SEMVER'],
    'source_url': os.environ['RELEASE_URL'],
    'source_sha256': os.environ['RELEASE_SHA'],
    'min_os': 'debian-13',
}
if os.environ.get('RELEASE_TOOLCHAIN'):
    with open(os.environ['RELEASE_TOOLCHAIN'], encoding='utf-8') as handle:
        bundle = json.load(handle)
    manifest['toolchain'] = {
        'id': bundle['toolchain_id'],
        'arch': bundle['arch'],
        'bundle_name': bundle['bundle_name'],
        'bundle_url': os.environ['RELEASE_TOOLCHAIN_URL'],
        'bundle_sha256': bundle['bundle_sha256'],
        'binaries': bundle['binaries'],
        'pins': bundle['pins'],
    }
with open(os.environ['RELEASE_OUT'], 'w', encoding='utf-8') as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write('\n')
PY

# Bake the same artifact pins into the public entry, never a moving source ref.
VS_ROUTER_COMMIT="$COMMIT" VS_ROUTER_BASE_URL="${BASE_URL%/}" \
VS_ROUTER_SOURCE_SHA256="$sha256" python3 - "$SCRIPT_DIR/get.sh" "$OUT/get.sh" <<'PY'
import os, pathlib, re
import sys

template = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
values = {}
for name in ('VS_ROUTER_COMMIT', 'VS_ROUTER_BASE_URL', 'VS_ROUTER_SOURCE_SHA256'):
    value = os.environ[name]
    if not value:
        sys.exit('cannot publish get.sh: ' + name + ' is empty')
    placeholder = '__' + name + '__'
    if template.count(placeholder) != 1:
        sys.exit('cannot publish get.sh: expected exactly one ' + placeholder)
    # Placeholders sit inside single quotes; keep URL punctuation literal shell data.
    values[placeholder] = value.replace("'", "'\"'\"'")
rendered = re.sub('|'.join(re.escape(key) for key in values),
                  lambda match: values[match.group()], template)
if '__VS_ROUTER_' in rendered:
    sys.exit('cannot publish get.sh: unreplaced placeholder')
output = pathlib.Path(sys.argv[2])
output.write_text(rendered, encoding='utf-8')
output.chmod(0o755)
PY

echo "Artifact: $OUT/$name"
echo "Manifest: $OUT/release.json"
echo "Entry:    $OUT/get.sh"
echo "Commit:   $COMMIT   semver: $semver"
echo "SHA-256:  $sha256"

if [[ $UPLOAD == 1 ]]; then
    tag="vs-router-${COMMIT}"
    if gh release view "$tag" >/dev/null 2>&1; then
        gh release upload "$tag" --clobber "$OUT/$name" "$OUT/release.json" "$OUT/get.sh"
    else
        gh release create "$tag" --target "$COMMIT" \
            --title "vs-router ${semver} (${COMMIT:0:7})" \
            --notes "Pinned vs-router release ${COMMIT}." \
            "$OUT/$name" "$OUT/release.json" "$OUT/get.sh"
    fi
    echo "Uploaded to GitHub Release ${tag}"
fi
