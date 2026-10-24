#!/usr/bin/env bash
# Build and (with --upload) publish a pinned vs-master release bundle (ADR-0035).
# Bundle contents (vs-master-<commit>.tar.gz):
#   backend wheel, backend/requirements-runtime.txt, alembic-master/,
#   frontend-master dist (ui/), vs-master-web.service, install-master.sh,
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

while (($#)); do
    case $1 in
        --upload) UPLOAD=1 ;;
        --help|-h) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *) COMMIT=$1 ;;
    esac
    shift
done

COMMIT=${COMMIT:-$(git -C "$REPO_ROOT" rev-parse HEAD)}
echo "$COMMIT" | grep -Eq '^[0-9a-f]{40}$' || { echo "commit must be a 40-hex id, never a branch (ADR-0005)" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BUNDLE=$WORK/vs-master-$COMMIT
mkdir -p "$BUNDLE"

echo "[master-release] building backend wheel"
(cd "$REPO_ROOT/backend" && uv build --wheel --out-dir "$WORK/wheel" >/dev/null 2>&1 \
    || uv build --wheel --out-dir "$WORK/wheel")
cp "$WORK"/wheel/vs_router_backend-*-py3-none-any.whl "$BUNDLE/"
cp "$REPO_ROOT/backend/requirements-runtime.txt" "$BUNDLE/"
cp -a "$REPO_ROOT/backend/alembic-master" "$BUNDLE/alembic-master"
rm -rf "$BUNDLE/alembic-master/__pycache__" "$BUNDLE/alembic-master/versions/__pycache__"

echo "[master-release] building frontend-master"
(cd "$REPO_ROOT/frontend-master" && VS_MASTER_STATIC_DIR="$BUNDLE/ui" npm run build --silent)
[ -f "$BUNDLE/ui/index.html" ] || { echo "UI build missing index.html" >&2; exit 1; }

cp "$REPO_ROOT/backend/packaging/vs-master-web.service" \
   "$REPO_ROOT/backend/packaging/install-master.sh" \
   "$REPO_ROOT/backend/packaging/caddy-master.conf" "$BUNDLE/"

echo "[master-release] packing"
mkdir -p "$OUT"
(cd "$WORK" && tar czf "$OUT/vs-master-$COMMIT.tar.gz" "vs-master-$COMMIT")
SHA=$(sha256sum "$OUT/vs-master-$COMMIT.tar.gz" | cut -d' ' -f1)
SEMVER=$(python3 -c "import tomllib;print(tomllib.load(open('$REPO_ROOT/backend/pyproject.toml','rb'))['project']['version'])")

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
    git -C "$REPO_ROOT" fetch origin "$COMMIT" >/dev/null 2>&1 || true
    TAG="vs-master-$SEMVER"
    gh release create "$TAG" --title "vs-master $SEMVER ($COMMIT)" \
        --notes "Master portal release (ADR-0035), commit $COMMIT." --clobber 2>/dev/null || true
    gh release upload "$TAG" "$OUT/vs-master-$COMMIT.tar.gz" "$OUT/release-master.json" "$OUT/get-master.sh" --clobber
    echo "uploaded: https://github.com/poshl9k/software-routing-software/releases/download/$TAG/get-master.sh"
fi
