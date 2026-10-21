#!/bin/sh
# Published, commit-pinned release entry; use the generated release asset.
# curl -fsSL "$VS_ROUTER_BASE_URL/get.sh" | sudo sh          # curl present
# A bare Debian has python3 but no curl: pipe the same shell into sh.
# sudo python3 -c "import urllib.request as u,subprocess; subprocess.run(['sh'],input=u.urlopen('<url>').read(),check=True)"
# <url> is the commit-specific release asset URL, ending in /get.sh.
# Overrides: VS_ROUTER_FETCH_DIR, VS_ROUTER_FETCH_OS_RELEASE.
set -eu

VS_ROUTER_COMMIT='__VS_ROUTER_COMMIT__'
VS_ROUTER_BASE_URL='__VS_ROUTER_BASE_URL__'
VS_ROUTER_SOURCE_SHA256='__VS_ROUTER_SOURCE_SHA256__'

log() { printf '[vs-router-get] %s\n' "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }
case "$VS_ROUTER_COMMIT$VS_ROUTER_BASE_URL$VS_ROUTER_SOURCE_SHA256" in
    *'__VS_'"ROUTER_"*) fail 'unreplaced template; use the published copy from the release asset' ;;
esac
[ "$(id -u)" = 0 ] || fail 'run as root'

# Read data, never source an OS-release override as executable shell code.
os_release=${VS_ROUTER_FETCH_OS_RELEASE:-/etc/os-release}
[ -f "$os_release" ] || fail "missing OS release file: $os_release"
os_id= os_version= os_name=unknown
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        ID=*|VERSION_ID=*|PRETTY_NAME=*)
            key=${line%%=*}
            value=${line#*=}
            case "$value" in
                \"*) value=${value#\"}; value=${value%%\"*} ;;
                \'*) value=${value#\'}; value=${value%%\'*} ;;
                *) value=${value%%#*}; value=${value%% *} ;;
            esac
            case "$key" in
                ID) os_id=$value ;;
                VERSION_ID) os_version=$value ;;
                PRETTY_NAME) os_name=$value ;;
            esac ;;
    esac
done < "$os_release"
if [ "$os_id" != debian ] || [ "$os_version" != 13 ]; then
    log "WARNING: expected Debian 13, found ${os_name:-unknown}"
fi

case "$VS_ROUTER_COMMIT" in
    ''|*[!0-9a-fA-F]*) fail 'commit must be a full 40-character hex commit id' ;;
esac
[ "${#VS_ROUTER_COMMIT}" = 40 ] || fail 'commit must be a full 40-character hex commit id'
case "$VS_ROUTER_BASE_URL" in
    https://?*) ;;
    *) fail 'base URL must start with https://' ;;
esac
case "$VS_ROUTER_SOURCE_SHA256" in
    ''|*[!0-9a-fA-F]*) fail 'source SHA-256 must be 64 hex characters' ;;
esac
[ "${#VS_ROUTER_SOURCE_SHA256}" = 64 ] || fail 'source SHA-256 must be 64 hex characters'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required before source verification'
command -v bash >/dev/null 2>&1 || fail 'bash is required to run install-release.sh'

fetch_dir=${VS_ROUTER_FETCH_DIR:-/root/vs-router-bootstrap}
archive="$fetch_dir/vs-router-$VS_ROUTER_COMMIT.tar.gz"
# Keep bootstrap separate from the wrapper's /root/vs-router-install: --fresh
# clears the wrapper's work directory. Refuse links in our own write paths too.
python3 - "$fetch_dir" "$archive" <<'PY' || fail 'unsafe fetch path'
import pathlib, sys
for raw in sys.argv[1:]:
    path = pathlib.Path(raw).absolute()
    if '..' in path.parts:
        raise ValueError('parent traversal in fetch path')
    for node in (path, *path.parents):
        if node.is_symlink():
            raise ValueError('symlink in fetch path: ' + str(node))
PY
mkdir -p -m 0700 -- "$fetch_dir"

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
            -o "$2" "$1" || fail "download failed: $1"
        return 0
    fi
    log 'curl is absent; downloading with python3'
    python3 - "$1" "$2" <<'PY' || fail "download failed: $1"
import sys, urllib.request
url, dest = sys.argv[1:]
if not url.startswith('https://'):
    sys.exit('refusing a non-https URL: ' + url)
class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith('https://'):
            raise ValueError('refusing a non-https redirect: ' + newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)
request = urllib.request.Request(url, headers={'User-Agent': 'vs-router-get'})
with urllib.request.build_opener(HTTPSOnly()).open(request, timeout=120) as response, open(dest, 'wb') as output:
    while True:
        chunk = response.read(262144)
        if not chunk:
            break
        output.write(chunk)
PY
}
verify() {
    printf '%s  %s\n' "$VS_ROUTER_SOURCE_SHA256" "$1" | sha256sum -c - >/dev/null
}
url="${VS_ROUTER_BASE_URL%/}/vs-router-$VS_ROUTER_COMMIT.tar.gz"
if [ -f "$archive" ] && verify "$archive" 2>/dev/null; then
    log "Reusing verified release archive $archive"
else
    download=$(mktemp "$fetch_dir/.download.XXXXXXXX")
    trap 'rm -f -- "$download"' 0
    log "Fetching release artifact $url"
    fetch "$url" "$download"
    verify "$download" || fail 'release artifact SHA-256 does not match the published pin'
    mv -- "$download" "$archive"
    trap - 0
fi
verify "$archive" || fail 'release artifact SHA-256 does not match the published pin'
log 'Extracting only backend/packaging/install-release.sh from the verified archive'
# This second extractor cannot reuse archive_tree: the wrapper does not exist
# on the host yet; it is the file we extract. The wrapper safely extracts the
# rest of the tree itself in its own work path after independent verification.
python3 - "$archive" "$fetch_dir/bootstrap/install-release.sh" <<'PY' || fail 'unsafe bootstrap archive or extraction failed'
import os, pathlib, shutil, sys, tarfile, tempfile
archive, dest = sys.argv[1:]
target = pathlib.Path(dest).absolute()
with tarfile.open(archive, 'r:gz') as tar:
    matches = []
    for member in tar:
        raw = member.name
        if raw.startswith('/') or '\\' in raw or '..' in raw.split('/'):
            raise ValueError('unsafe archive path: ' + raw)
        parts = [part for part in raw.split('/') if part not in ('', '.')]
        if '/'.join(parts) == 'backend/packaging/install-release.sh':
            if not member.isfile():
                raise ValueError('bootstrap member is not a regular file')
            matches.append(member)
    if len(matches) != 1:
        raise ValueError('expected exactly one bootstrap member')
    for node in (target, *target.parents):
        if node.is_symlink():
            raise ValueError('symlink in bootstrap path: ' + str(node))
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.install-release.', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as output, tar.extractfile(matches[0]) as source:
            shutil.copyfileobj(source, output)
        os.chmod(temporary, 0o755)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
PY
log "Installing commit $VS_ROUTER_COMMIT"
exec "$fetch_dir/bootstrap/install-release.sh" --release "$VS_ROUTER_COMMIT" \
    --manifest "${VS_ROUTER_BASE_URL%/}/release.json" "$@"
