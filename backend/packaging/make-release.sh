#!/usr/bin/env bash
# Build a pinned, verifiable vs-router release artifact for the ONLINE update
# channel (ADR-0010). Produces, in $OUT:
#   vs-router-<commit>.tar.gz   the pinned commit's tree, plus a REVISION file
#                               at the archive root, and
#   release.json                {commit, semver, source_url, source_sha256,
#                                min_os}
# The artifact format matches what the ISO vendors (ADR-0008): a `git archive`
# of one commit; the added REVISION lets a guest cross-check the archive
# against the manifest commit without any git history.
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
COMMIT=

usage() {
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while (($#)); do
    case $1 in
        --out)      OUT=${2:?--out needs a directory}; shift ;;
        --base-url) BASE_URL=${2:?--base-url needs a URL}; shift ;;
        --upload)   UPLOAD=1 ;;
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
tar -czf "$OUT/$name" -C "$stage" .

sha256=$(sha256sum "$OUT/$name" | awk '{print $1}')
[[ $sha256 =~ ^[0-9a-f]{64}$ ]] || { echo 'sha256sum failed' >&2; exit 1; }

RELEASE_OUT="$OUT/release.json" RELEASE_COMMIT="$COMMIT" RELEASE_SEMVER="$semver" \
RELEASE_URL="$source_url" RELEASE_SHA="$sha256" python3 - <<'PY'
import json, os
manifest = {
    'commit': os.environ['RELEASE_COMMIT'],
    'semver': os.environ['RELEASE_SEMVER'],
    'source_url': os.environ['RELEASE_URL'],
    'source_sha256': os.environ['RELEASE_SHA'],
    'min_os': 'debian-13',
}
with open(os.environ['RELEASE_OUT'], 'w', encoding='utf-8') as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write('\n')
PY

echo "Artifact: $OUT/$name"
echo "Manifest: $OUT/release.json"
echo "Commit:   $COMMIT   semver: $semver"
echo "SHA-256:  $sha256"

if [[ $UPLOAD == 1 ]]; then
    tag="vs-router-${COMMIT}"
    if gh release view "$tag" >/dev/null 2>&1; then
        gh release upload "$tag" --clobber "$OUT/$name" "$OUT/release.json"
    else
        gh release create "$tag" --title "vs-router ${semver} (${COMMIT:0:7})" \
            --notes "Pinned vs-router release ${COMMIT}." \
            "$OUT/$name" "$OUT/release.json"
    fi
    echo "Uploaded to GitHub Release ${tag}"
fi
