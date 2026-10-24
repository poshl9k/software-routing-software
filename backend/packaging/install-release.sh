#!/usr/bin/env bash
# Source/build wrapper for the one-NIC panel installer. The installer, not this
# wrapper, owns the host's product profile, SSH policy and system services.
# Usage: install-release.sh [--release SHA | --manifest URL | --source DIR]
#        [--hostname H] [--custom-hostname H] [--path-prefix P] [--address A/P]
#        [--ssh-port N] [--work DIR] [--fresh] [--skip-build] [--dry-run] [--help]
# Overrides: VS_ROUTER_INSTALL_WORK, VS_ROUTER_INSTALL_MANIFEST_URL,
# VS_ROUTER_INSTALL_OS_RELEASE, VS_ROUTER_UPDATE_CONFIG,
# VS_ROUTER_INSTALL_IP_PROBE_URL.
# Python 3 is required for source/path verification and is also the download
# fallback; curl is preferred when present.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
log()  { printf '[vs-router-install] %s\n' "$*" >&2; }
warn() { log "WARNING: $*"; }
fail() { log "ERROR: $*"; exit 1; }

usage() {
    cat <<'EOF'
Usage: install-release.sh [--release 40-hex-commit] [--manifest URL] [--source DIR]
       [--hostname H] [--custom-hostname H] [--path-prefix P] [--address A/P]
       [--ssh-port N] [--work DIR] [--fresh] [--skip-build] [--dry-run] [--help]

--release and --manifest may be used together to pin the manifest's commit.
--source cannot be combined with either. Default source: this script's repo.
--work defaults to VS_ROUTER_INSTALL_WORK or /root/vs-router-install.
--release URL lookup: --manifest, VS_ROUTER_INSTALL_MANIFEST_URL, then
  manifest_url in VS_ROUTER_UPDATE_CONFIG (/etc/vs-router/update.json).
VS_ROUTER_INSTALL_OS_RELEASE overrides /etc/os-release for platform checks.
--fresh removes the contents of the selected --work directory.
--skip-build requires exactly one existing wheel and frontend/dist/index.html.
--dry-run verifies source and prints build/install plan without building or apt.
Python 3 is required beforehand; release downloads additionally require curl.
EOF
}

release= manifest= source= hostname= custom_hostname= path_prefix= address= ssh_port=
work=${VS_ROUTER_INSTALL_WORK:-/root/vs-router-install}
fresh=0 skip_build=0 dry_run=0
while (($#)); do
    case $1 in
        --release|--manifest|--source|--hostname|--custom-hostname|--path-prefix|--address|--ssh-port|--work)
            (($# >= 2)) && [[ -n $2 ]] || fail "$1 needs a value"
            case $1 in
                --release) release=$2 ;; --manifest) manifest=$2 ;; --source) source=$2 ;;
                --hostname) hostname=$2 ;; --custom-hostname) custom_hostname=$2 ;;
                --path-prefix) path_prefix=$2 ;; --address) address=$2 ;;
                --ssh-port) ssh_port=$2 ;; --work) work=$2 ;;
            esac
            shift 2 ;;
        --fresh) fresh=1; shift ;; --skip-build) skip_build=1; shift ;;
        --dry-run) dry_run=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

# Refuse before any filesystem writes, downloads or package operations.
[[ $(id -u) == 0 ]] || fail 'run as root'
[[ -z $release || $release =~ ^[0-9a-f]{40}$ ]] || fail '--release requires a full 40-character commit id'
[[ -z $source || ( -z $release && -z $manifest ) ]] || fail '--source cannot be combined with --release/--manifest'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required before source verification'

os_release=${VS_ROUTER_INSTALL_OS_RELEASE:-/etc/os-release}
[[ -f $os_release ]] || fail "missing OS release file: $os_release"
os_identity=$(python3 - "$os_release" <<'PY'
import shlex, sys
values = {}
with open(sys.argv[1], encoding='utf-8') as stream:
    for line in stream:
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.strip().split('=', 1)
            if key in ('ID', 'VERSION_ID', 'PRETTY_NAME'):
                fields = shlex.split(value, comments=True)
                values[key] = fields[0] if fields else ''
print(values.get('ID', '') + '\t' + values.get('VERSION_ID', '') + '\t' + values.get('PRETTY_NAME', 'unknown'))
PY
) || fail 'could not read OS release'
IFS=$'\t' read -r os_id os_version os_name <<< "$os_identity"
[[ $os_id == debian && $os_version == 13 ]] || warn "expected Debian 13, found ${os_name:-unknown}"

source=${source:-$REPO_ROOT}
[[ -d $source && ! -L $source ]] || fail "source directory missing or symlink: $source"
source=$(CDPATH= cd -- "$source" && pwd -P)
# Refuse symlink components: a selected work path must never redirect deletion,
# downloads or extraction into an unrelated tree. Reject source/work overlap.
path_guard() {
    python3 - "$work" "$source" "$REPO_ROOT" <<'PY'
import os, sys
work, source, repo = (os.path.abspath(p) for p in sys.argv[1:])
def no_links(path):
    current = '/'
    for part in path.split('/'):
        if part:
            current = os.path.join(current, part)
            if os.path.islink(current):
                raise ValueError('symlink path component: ' + current)
def contains(parent, child):
    return os.path.commonpath((parent, child)) == parent
no_links(work)
if work == '/' or any(contains(work, path) or contains(path, work) for path in (source, repo)):
    raise ValueError('work overlaps source/repository or filesystem root')
print(work)
PY
}
work=$(path_guard) || fail 'unsafe --work path (root, symlink or source/repository overlap)'
if (( fresh )); then
    [[ ! -e $work || -d $work ]] || fail "work is not a directory: $work"
    mkdir -p -m 0700 -- "$work"
    log "Clearing explicitly selected work directory $work"
    shopt -s dotglob nullglob
    entries=("$work"/*)
    if (( ${#entries[@]} )); then rm -rf -- "${entries[@]}"; fi
    shopt -u dotglob nullglob
fi

# update.sh performs the same HTTPS, digest and REVISION checks on the update path.
# curl is not part of a minimal Debian install while python3 is, so both the
# download and the public-address probe fall back to python3 instead of refusing
# to run on a bare host. curl stays preferred (--proto '=https', --tlsv1.2);
# the fallback verifies the same system trust store and refuses a non-https URL
# before making a request.
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
            -o "$2" "$1" || fail "download failed: $1"
        return 0
    fi
    log 'curl is absent; downloading with python3'
    python3 - "$1" "$2" <<'PY' || fail "download failed: $1"
import sys, urllib.request
url, dest = sys.argv[1], sys.argv[2]
if not url.startswith('https://'):
    sys.exit('refusing a non-https URL: ' + url)
request = urllib.request.Request(url, headers={'User-Agent': 'vs-router-install'})
with urllib.request.urlopen(request, timeout=120) as response, open(dest, 'wb') as output:
    while True:
        chunk = response.read(262144)
        if not chunk:
            break
        output.write(chunk)
PY
}

https_body() {  # url -> stdout; empty on any failure
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 10 "$1" 2>/dev/null || true
        return 0
    fi
    python3 - "$1" <<'PY' 2>/dev/null || true
import sys, urllib.request
if not sys.argv[1].startswith('https://'):
    sys.exit('refusing a non-https URL')
with urllib.request.urlopen(sys.argv[1], timeout=10) as response:
    sys.stdout.write(response.read().decode('utf-8', 'replace'))
PY
}

manifest_field() {  # Same field reader as update.sh; only string fields are accepted.
    python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as handle:
    data = json.load(handle)
value = data.get(sys.argv[2])
print(value if isinstance(value, str) else '')
PY
}

# ADR-0010: the update channel is host-owned configuration. Installing from a
# release manifest also records that channel, so the panel can check and apply
# later releases without hand-editing /etc/vs-router/update.json. Best effort:
# a failed record must not abort an otherwise verified install.
persist_update_channel() {  # manifest URL -> $VS_ROUTER_UPDATE_CONFIG
    local url=$1
    local config=${VS_ROUTER_UPDATE_CONFIG:-/etc/vs-router/update.json}
    # A pinned per-release manifest URL would freeze the channel on the
    # release that happened to be installed; the stable GitHub
    # latest/download URL always serves the newest published release.json.
    if [[ $url =~ ^https://[^/]+/[^/]+/[^/]+/releases/download/[^/]+/release\.json$ ]]; then
        local base=${url%/release.json}
        base=${base%/*}
        url="${base%/download}/latest/download/release.json"
    fi
    if ! mkdir -p -- "$(dirname -- "$config")"; then
        warn "could not create the update config directory for $config"
        return 0
    fi
    if ! VS_ROUTER_CHANNEL_URL=$url python3 - "$config" <<'PY'
import json, os, sys
url, path = os.environ['VS_ROUTER_CHANNEL_URL'], sys.argv[1]
data = {}
try:
    with open(path, encoding='utf-8') as handle:
        loaded = json.load(handle)
    if isinstance(loaded, dict):
        data = loaded
except (OSError, ValueError):
    pass
data['manifest_url'] = url
temporary = path + '.tmp'
with open(temporary, 'w', encoding='utf-8') as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write('\n')
os.replace(temporary, path)
PY
    then
        warn "could not record the update channel in $config; the panel will not see releases until it is set"
        return 0
    fi
    log "Update channel recorded: $url"
}

# Reject links and special members rather than trusting tar's pathname filters.
# make-release.sh creates a root-level git archive with an added REVISION file.
archive_tree() {
    python3 - "$1" "$2" "$3" <<'PY'
import hashlib, os, pathlib, shutil, sys, tarfile
archive, tree, operation = sys.argv[1:]
root = pathlib.Path(tree)
with tarfile.open(archive, 'r:gz') as tar:
    members = []
    seen = set()
    for member in tar:
        raw = member.name
        if raw.startswith('/') or '\\' in raw:
            raise ValueError('unsafe archive path: ' + raw)
        parts = [part for part in raw.split('/') if part not in ('', '.')]
        if not parts:
            continue
        if '..' in parts or not (member.isfile() or member.isdir()):
            raise ValueError('unsafe archive member: ' + raw)
        relative = pathlib.Path(*parts)
        if relative in seen:
            raise ValueError('duplicate archive member: ' + raw)
        seen.add(relative)
        members.append((member, relative))
    for member, relative in members:
        target = root / relative
        for parent in (root, *target.parents):
            if parent == root.parent:
                break
            if parent.is_symlink():
                raise ValueError('symlink in extraction tree: ' + str(parent))
        if target.is_symlink():
            raise ValueError('symlink in extraction tree: ' + str(target))
        if member.isdir():
            if operation == 'extract':
                target.mkdir(parents=True, exist_ok=True)
            elif not target.is_dir():
                raise ValueError('missing directory: ' + str(target))
            continue
        if operation == 'extract':
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as stream, open(target, 'xb') as output:
                shutil.copyfileobj(stream, output)
            target.chmod(member.mode & 0o755)
        else:
            if not target.is_file():
                raise ValueError('missing file: ' + str(target))
            with tar.extractfile(member) as expected, open(target, 'rb') as actual:
                digest_expected, digest_actual = hashlib.sha256(), hashlib.sha256()
                for chunk in iter(lambda: expected.read(1024 * 1024), b''):
                    digest_expected.update(chunk)
                for chunk in iter(lambda: actual.read(1024 * 1024), b''):
                    digest_actual.update(chunk)
                if digest_expected.digest() != digest_actual.digest():
                    raise ValueError('modified source file: ' + str(target))
PY
}

if [[ -n $release || -n $manifest ]]; then
    if [[ -z $manifest ]]; then
        manifest=${VS_ROUTER_INSTALL_MANIFEST_URL:-}
        if [[ -z $manifest ]]; then
            config=${VS_ROUTER_UPDATE_CONFIG:-/etc/vs-router/update.json}
            if [[ -f $config ]]; then
                manifest=$(python3 - "$config" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as stream:
        value = json.load(stream).get('manifest_url', '')
    print(value if isinstance(value, str) else '')
except (OSError, ValueError, AttributeError):
    print('')
PY
)
            fi
        fi
    fi
    [[ -n $manifest ]] || fail 'a manifest URL is required; pass --manifest or set VS_ROUTER_INSTALL_MANIFEST_URL'
    [[ $manifest == https://* ]] || fail 'manifest URL must be https'
    [[ -e $work && ! -d $work ]] && fail "work is not a directory: $work"
    mkdir -p -m 0700 -- "$work"
    tmp=$(mktemp -d "$work/.release.XXXXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    log "Fetching manifest $manifest"
    fetch "$manifest" "$tmp/release.json"
    commit=$(manifest_field "$tmp/release.json" commit) || fail 'invalid release manifest'
    artifact_url=$(manifest_field "$tmp/release.json" source_url) || fail 'invalid release manifest'
    sha=$(manifest_field "$tmp/release.json" source_sha256) || fail 'invalid release manifest'
    [[ $commit =~ ^[0-9a-f]{40}$ ]] || fail 'manifest commit is not a full commit id'
    [[ $sha =~ ^[0-9a-f]{64}$ ]] || fail 'manifest source_sha256 is not a sha256'
    [[ $artifact_url == https://* ]] || fail 'manifest source_url must be https'
    [[ -z $release || $release == "$commit" ]] || fail "--release $release does not match manifest commit $commit"

    archive="$work/source-$commit.tar.gz"
    tree="$work/source-$commit"
    for item in "$archive" "$tree"; do
        [[ ! -L $item ]] || fail "unsafe symlink in work: $item"
    done
    if [[ -e $archive ]]; then
        [[ -f $archive ]] || fail "cached archive is not a file: $archive"
        log "Rechecking cached release archive $archive"
    else
        log "Fetching release artifact $artifact_url"
        fetch "$artifact_url" "$tmp/source.tar.gz"
        archive="$tmp/source.tar.gz"
    fi
    printf '%s  %s\n' "$sha" "$archive" | sha256sum -c - >/dev/null \
        || fail 'release artifact SHA-256 does not match the manifest'
    if [[ ! -e $tree ]]; then
        log "Extracting verified release into $work"
        archive_tree "$archive" "$tmp/tree" extract || fail 'release archive contains unsafe paths or extraction failed'
        [[ -f $tmp/tree/REVISION ]] || fail 'release artifact lacks REVISION'
        [[ $(<"$tmp/tree/REVISION") == "$commit" ]] || fail 'REVISION does not match manifest commit'
        mv -- "$tmp/tree" "$tree"
    else
        [[ -d $tree ]] || fail 'cached source is not a directory'
        archive_tree "$archive" "$tree" verify || fail 'cached source differs from the verified archive'
    fi
    [[ -f $tree/REVISION && $(<"$tree/REVISION") == "$commit" ]] || fail 'REVISION does not match manifest commit'
    if [[ $archive == "$tmp/source.tar.gz" ]]; then
        mv -- "$archive" "$work/source-$commit.tar.gz"
    fi
    source=$tree
    log "Verified release $commit"
    if (( ! dry_run )); then
        persist_update_channel "$manifest"
    fi
fi

# --- Prebuilt compiled toolchain (release path only) -------------------------
# A release's manifest may pin a toolchain bundle (release.json's toolchain
# section): the pinned Caddy/AmneziaWG binaries, downloaded once and verified
# against the manifest, replacing the host Go builds. Every digest is checked
# before anything is installed; the release path aborts on any mismatch.
tc_bundle_args=()
if [[ -n ${tmp:-} ]]; then
    tc_json=$(python3 - "$tmp/release.json" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as handle:
        tc = json.load(handle).get('toolchain')
except (OSError, ValueError):
    tc = None
if tc:
    print(tc['bundle_url'])
    print(tc['bundle_sha256'])
    for name, digest in sorted(tc['binaries'].items()):
        print(name, digest)
PY
    ) || fail 'release.json toolchain section is invalid'
    if [[ -n $tc_json ]]; then
        tc_url=$(head -n1 <<<"$tc_json")
        tc_sha=$(sed -n '2p' <<<"$tc_json")
        tc_pairs=$(tail -n +3 <<<"$tc_json")
        tc_bundle="$work/toolchain-$tc_sha.tar.gz"
        if [[ -e $tc_bundle ]]; then
            log 'Reusing the cached toolchain bundle'
        else
            log 'Fetching the release toolchain bundle'
            fetch "$tc_url" "$tc_bundle"
        fi
        printf '%s  %s\n' "$tc_sha" "$tc_bundle" | sha256sum -c - >/dev/null \
            || fail 'toolchain bundle SHA-256 does not match the manifest'
        if tar -tzf "$tc_bundle" | grep -Evq '^(\./)?[^/]+$'; then
            fail 'toolchain bundle contains unexpected paths'
        fi
        tc_stage=$tmp/toolchain
        mkdir -p "$tc_stage"
        tar -xzf "$tc_bundle" -C "$tc_stage" --no-same-owner
        while read -r bin_name bin_digest; do
            [[ -f $tc_stage/$bin_name ]] || fail "toolchain bundle lacks $bin_name"
            printf '%s  %s\n' "$bin_digest" "$tc_stage/$bin_name" | sha256sum -c - >/dev/null \
                || fail "toolchain binary $bin_name does not match the manifest"
        done <<<"$tc_pairs"
        log "Verified toolchain bundle ($tc_sha); installing its binaries"
        tc_bundle_args=(--toolchain "$tc_bundle")
    fi
fi

# Do not follow links into build or installer outputs.
python3 - "$source" <<'PY' || fail 'source contains unsafe paths'
import os, pathlib, sys
root = pathlib.Path(sys.argv[1])
for part in ('backend', 'backend/packaging', 'backend/dist', 'frontend',
             'frontend/dist', 'frontend/node_modules'):
    node = root / part
    if node.is_symlink():
        raise ValueError('symlink in source: ' + str(node))
for part in ('backend/packaging/install.sh', 'backend/packaging/online-install.sh',
             'backend/pyproject.toml', 'frontend/package.json'):
    node = root / part
    if not node.is_file() or node.is_symlink():
        raise ValueError('source missing safe file: ' + str(node))
PY
log "Source tree: $source"

# Only a public IPv4 can form the nip.io reserve. Never silently use a LAN IP.
public_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress, sys
try:
    addr = ipaddress.ip_address(sys.argv[1])
    if (isinstance(addr, ipaddress.IPv4Address) and addr.is_global
            and not addr.is_multicast and not addr.is_reserved):
        print(addr)
except ValueError:
    pass
PY
}
if [[ -z $hostname ]]; then
    route=$(ip -4 route get 1.1.1.1 2>/dev/null || true)
    candidate=
    if [[ $route =~ (^|[[:space:]])src[[:space:]]+([^[:space:]]+) ]]; then
        candidate=$(public_ipv4 "${BASH_REMATCH[2]}")
    fi
    if [[ -z $candidate ]]; then
        default_route=$(ip -4 route show default 2>/dev/null || true)
        [[ $default_route =~ (^|[[:space:]])dev[[:space:]]+([a-zA-Z0-9_.:-]+) ]] && iface=${BASH_REMATCH[2]}
        if [[ -n ${iface:-} ]]; then
            addresses=$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null || true)
            while read -r addr; do
                [[ $addr =~ (^|[[:space:]])inet[[:space:]]+([0-9.]+)/[0-9]+ ]] || continue
                candidate=$(public_ipv4 "${BASH_REMATCH[2]}")
                [[ -z $candidate ]] || break
            done <<< "$addresses"
        fi
    fi
    if [[ -z $candidate ]]; then
        observed=$(https_body "${VS_ROUTER_INSTALL_IP_PROBE_URL:-https://api.ipify.org}")
        candidate=$(public_ipv4 "$observed")
        # Egress address, not necessarily the ingress one: behind NAT the box is
        # reached on an address it never sees itself (observed live: the host's
        # own egress was .212 while SSH and ports 80/443 arrived on .214). Say so
        # instead of publishing a name that may point away from this host.
        if [[ -n $candidate ]]; then
            warn "the public address was read from an external echo service; behind NAT the egress address can differ from the address that reaches this host — if the panel cannot be published, pass --hostname <ip>.nip.io explicitly"
        fi
    fi
    [[ -n $candidate ]] || fail 'cannot detect public IPv4; pass --hostname <ip>.nip.io'
    hostname="$candidate.nip.io"
    log "Derived reserve hostname $hostname"
fi


# The release archive normally ships prebuilt artifacts (make-release.sh builds
# them into the tree): exactly one backend wheel and frontend/dist/index.html.
# When both are present the host build — and the nodejs/npm toolchain it needs —
# is skipped without any flag; an explicit --skip-build still works, and an
# incomplete prebuilt set falls back to the normal build.
if (( ! skip_build )); then
    shopt -s nullglob
    prebuilt_wheels=("$source/backend/dist"/*.whl)
    shopt -u nullglob
    if (( ${#prebuilt_wheels[@]} == 1 )) && [[ -f $source/frontend/dist/index.html ]]; then
        skip_build=1
        log "Release ships prebuilt artifacts (${prebuilt_wheels[0]#$source/} + frontend/dist); skipping the host build"
    fi
fi

# The online installer prepares runtime dependencies, but runs after the build.
# Only bootstrap the minimal build toolchain here, after source verification.
if (( ! skip_build )); then
    if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1 || \
       { ! command -v uv >/dev/null 2>&1 &&
         { ! python3 -m pip --version >/dev/null 2>&1 || ! python3 -c 'import setuptools, wheel' >/dev/null 2>&1; }; }; then
        if (( dry_run )); then
            log 'Would apt-get update -y && apt-get install -y python3-pip python3-setuptools python3-wheel nodejs npm'
        else
            command -v apt-get >/dev/null 2>&1 || fail 'apt-get is required to prepare build tools'
            log 'Preparing minimal build prerequisites'
            DEBIAN_FRONTEND=noninteractive apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip python3-setuptools python3-wheel nodejs npm
        fi
    fi
fi
node_caveat=
# Node is only needed to build the UI. --skip-build reuses artifacts that are
# already there, so a host without node must not be refused for it. In --dry-run
# the toolchain is not installed yet by design, so its absence is a plan line,
# not a failure: reporting it as fatal made the dry run contradict its own
# "would install nodejs and npm" step.
if (( ! skip_build )); then
    if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
        node_version=$(node --version) || fail 'node --version failed'
        if [[ $node_version =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]}
            if (( 10#$major < 22 || (10#$major == 22 && 10#$minor < 12) )); then
                node_caveat="Node $node_version is below v22.12.0; docs/install.md records Debian 13 v20.19.2 as sufficient"
                warn "$node_caveat"
            fi
        else
            fail "unrecognized Node version: $node_version"
        fi
    elif (( dry_run )); then
        log 'Would install nodejs and npm before building'
    else
        fail 'node is missing; install nodejs and npm before continuing'
    fi
fi
if (( ! skip_build )); then
    if (( ! dry_run )); then
        if command -v uv >/dev/null 2>&1; then
            log 'Building backend wheel with uv'
            (cd "$source/backend" && uv build --wheel --out-dir dist)
        else
            log 'Building backend wheel with python3 -m pip'
            python3 -m pip wheel --no-deps --no-build-isolation -w "$source/backend/dist" "$source/backend"
        fi
        log 'Building frontend with npm ci && npm run build'
        (cd "$source/frontend" && npm ci && npm run build)
    else
        log 'Would build backend wheel and run npm ci && npm run build in frontend'
    fi
else
    log 'Skipping build; using existing wheel and UI'
fi

shopt -s nullglob
wheels=("$source"/backend/dist/*.whl)
if (( ${#wheels[@]} != 1 )); then
    if (( ! dry_run || skip_build || ${#wheels[@]} > 1 )); then
        fail "expected exactly one backend wheel in $source/backend/dist (found ${#wheels[@]})"
    fi
    wheel="$source/backend/dist/vs_router_backend-<built-wheel>.whl"
else
    wheel=${wheels[0]}
    [[ -f $wheel && ! -L $wheel ]] || fail "unsafe backend wheel: $wheel"
fi
ui="$source/frontend/dist"
if [[ ! -f $ui/index.html || -L $ui/index.html ]]; then
    (( dry_run && ! skip_build )) || fail "frontend bundle missing: $ui/index.html"
fi

args=(--wheel "$wheel" --ui "$ui" --hostname "$hostname")
(( ${#tc_bundle_args[@]} == 0 )) || args+=("${tc_bundle_args[@]}")
[[ -z $custom_hostname ]] || args+=(--custom-hostname "$custom_hostname")
[[ -z $path_prefix ]] || args+=(--path-prefix "$path_prefix")
[[ -z $address ]] || args+=(--address "$address")
[[ -z $ssh_port ]] || args+=(--ssh-port "$ssh_port")
(( ! dry_run )) || args+=(--dry-run)
log "Running online installer from $source"
env PACKAGING="$source/backend/packaging" sh "$source/backend/packaging/online-install.sh" "${args[@]}"
log "Panel URL: https://$hostname${path_prefix:-/}"
[[ -z $node_caveat ]] || log "Caveat: $node_caveat"
if [[ -n $custom_hostname ]]; then
    log "Custom panel URL: https://$custom_hostname${path_prefix:-/}"
fi
