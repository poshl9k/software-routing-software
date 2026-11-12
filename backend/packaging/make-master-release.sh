#!/usr/bin/env bash
# Build and (with --upload) publish a pinned vs-master release bundle (ADR-0035).
# Bundle contents (vs-master-<commit>.tar.gz):
#   backend wheel, backend/requirements-runtime.txt, alembic-master/,
#   frontend-master dist (ui/), vs-master-web.service, vs-master-worker.service,
#   vs-master-bot.service, vs-master-backup.service/timer, install-master.sh,
#   caddy-master.conf fragment.
# Plus, next to the tarball:
#   release.json  {commit, semver, source_url, source_sha256}
#   get-master.sh the public entry with baked URL + sha256 (commit-pinned, ADR-0005)
# Usage: make-master-release.sh [<40-hex-commit>] [--upload]
set -euo pipefail
umask 022

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
OUT=${VS_MASTER_RELEASE_OUT:-$REPO_ROOT/release}
UPLOAD=0
COMMIT=
COMMIT_SET=0

while (($#)); do
    case $1 in
        --upload) UPLOAD=1 ;;
        --help|-h) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *)
            [[ $COMMIT_SET == 0 && -n $1 ]] || { echo 'expected one nonempty commit id' >&2; exit 1; }
            COMMIT=$1
            COMMIT_SET=1
            ;;
    esac
    shift
done

if [[ $COMMIT_SET == 0 ]]; then
    COMMIT=$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
        || { echo 'HEAD commit is not present' >&2; exit 1; }
fi
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "commit must be a 40-hex id, never a branch (ADR-0005)" >&2; exit 1; }
[[ $(git -C "$REPO_ROOT" cat-file -t "$COMMIT" 2>/dev/null) == commit ]] \
    || { echo "commit $COMMIT is not present or is not a commit object" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SOURCE=$WORK/source
BUNDLE=$WORK/vs-master-$COMMIT
mkdir -p "$SOURCE" "$BUNDLE"

# Export only the requested commit: no dirty/untracked sources, stale bundles,
# node_modules or build metadata from the caller's checkout may enter a release.
git -C "$REPO_ROOT" -c core.autocrlf=false -c core.eol=lf \
    archive --format=tar "$COMMIT" | tar -x -C "$SOURCE"
SEMVER=$(python3 -c 'import sys,tomllib;print(tomllib.load(open(sys.argv[1],"rb"))["project"]["version"])' \
    "$SOURCE/backend/pyproject.toml")

echo "[master-release] building backend wheel"
(cd "$SOURCE/backend" && uv build --wheel --out-dir "$WORK/wheel")
cp "$WORK"/wheel/vs_router_backend-*-py3-none-any.whl "$BUNDLE/"
cp "$SOURCE/backend/requirements-runtime.txt" "$BUNDLE/"
cp -a "$SOURCE/backend/alembic-master" "$BUNDLE/alembic-master"
rm -rf "$BUNDLE/alembic-master/__pycache__" "$BUNDLE/alembic-master/versions/__pycache__"

echo "[master-release] building frontend-master"
(cd "$SOURCE/frontend-master" && npm ci && VS_MASTER_STATIC_DIR="$BUNDLE/ui" npm run build --silent)
[ -f "$BUNDLE/ui/index.html" ] || { echo "UI build missing index.html" >&2; exit 1; }

cp "$SOURCE/backend/packaging/vs-master-web.service" \
   "$SOURCE/backend/packaging/vs-master-worker.service" \
   "$SOURCE/backend/packaging/vs-master-bot.service" \
   "$SOURCE/backend/packaging/vs-master-backup.service" \
   "$SOURCE/backend/packaging/vs-master-backup.timer" \
   "$SOURCE/backend/packaging/install-master.sh" \
   "$SOURCE/backend/packaging/caddy-master.conf" "$BUNDLE/"

# Self-describing bundle: the installer prints this and an operator can prove
# which commit a deployed directory came from without any git history. Same
# convention as the node release archive (make-release.sh).
printf '%s\n' "$COMMIT" > "$BUNDLE/REVISION"

echo "[master-release] packing"
mkdir -p "$OUT"
(cd "$WORK" && tar czf "$OUT/vs-master-$COMMIT.tar.gz" "vs-master-$COMMIT")
SHA=$(sha256sum "$OUT/vs-master-$COMMIT.tar.gz" | cut -d' ' -f1)

cat > "$OUT/release-master.json" <<JSON
{"commit": "$COMMIT", "semver": "$SEMVER", "kind": "vs-master",
 "source_url": "https://github.com/poshl9k/software-routing-software/releases/download/vs-master-$SEMVER/vs-master-$COMMIT.tar.gz",
 "source_sha256": "$SHA"}
JSON
cat > "$OUT/get-master.sh" <<ENTRY
#!/bin/sh
# Commit-pinned vs-master install entry (ADR-0005/0035). Run as root:
#   curl -fsSL <asset-url>/get-master.sh | sh
set -eu
VSM_COMMIT='$COMMIT'
VSM_BASE_URL='https://github.com/poshl9k/software-routing-software/releases/download/vs-master-$SEMVER'
VSM_SHA='$SHA'
log() { printf '[vs-master-get] %s\n' "\$*" >&2; }
fail() { log "ERROR: \$*"; exit 1; }
[ "\$(id -u)" = 0 ] || fail 'run as root'
FETCH=\${VS_MASTER_FETCH_DIR:-/root/vs-master-deploy}
mkdir -p "\$FETCH"
if command -v curl >/dev/null 2>&1; then FETCHER="curl -fsSL"; else FETCHER="wget -qO-"; fi
log "downloading vs-master \$VSM_COMMIT"
\$FETCHER "\$VSM_BASE_URL/vs-master-\$VSM_COMMIT.tar.gz" > "\$FETCH/bundle.tar.gz"
echo "\$VSM_SHA  \$FETCH/bundle.tar.gz" | sha256sum -c - || fail 'bundle checksum mismatch'
rm -rf "\$FETCH/vs-master-\$VSM_COMMIT"
tar xzf "\$FETCH/bundle.tar.gz" -C "\$FETCH"
log "installing"
bash "\$FETCH/vs-master-\$VSM_COMMIT/install-master.sh"
log "done; probe: curl http://127.0.0.1:8440/health"
ENTRY
chmod +x "$OUT/get-master.sh"

echo "bundle: $OUT/vs-master-$COMMIT.tar.gz"
echo "sha256: $SHA"

if [ "$UPLOAD" = 1 ]; then
    TAG="vs-master-$SEMVER"
    REPO=poshl9k/software-routing-software
    UPSTREAM="https://github.com/$REPO.git"
    REMOTE_HEAD=$(git -C "$REPO_ROOT" ls-remote --exit-code "$UPSTREAM" refs/heads/main | cut -f1) \
        || { echo 'cannot verify canonical main before upload' >&2; exit 1; }
    [[ $REMOTE_HEAD =~ ^[0-9a-f]{40}$ ]] \
        || { echo 'cannot resolve canonical main before upload' >&2; exit 1; }
    git -C "$REPO_ROOT" fetch --no-tags "$UPSTREAM" "$REMOTE_HEAD" >/dev/null \
        || { echo 'cannot fetch canonical main commit before upload' >&2; exit 1; }
    git -C "$REPO_ROOT" merge-base --is-ancestor "$COMMIT" "$REMOTE_HEAD" \
        || { echo "commit $COMMIT is not published on canonical main" >&2; exit 1; }
    TAG_REFS=$(git -C "$REPO_ROOT" ls-remote --tags "$UPSTREAM" "refs/tags/$TAG") \
        || { echo "cannot verify remote tag $TAG" >&2; exit 1; }
    if [ -n "$TAG_REFS" ]; then
        echo "tag $TAG already exists; publish a new version" >&2
        exit 1
    fi
    # A GitHub release always has a tag; create is the final collision gate.
    gh release create "$TAG" --repo "$REPO" --target "$COMMIT" \
        --title "vs-master $SEMVER ($COMMIT)" \
        --notes "Master portal release (ADR-0035), commit $COMMIT." \
        "$OUT/vs-master-$COMMIT.tar.gz" "$OUT/release-master.json" "$OUT/get-master.sh"
    echo "uploaded: https://github.com/poshl9k/software-routing-software/releases/download/$TAG/get-master.sh"
fi
