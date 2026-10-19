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
#   8. check that the panel and SSH answer, and roll the tree and the database
#      revision back if they do not (ADR-0010/0021)
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

# An update is not an install: it must never re-decide how SSH is exposed on the
# host. install.sh's non-KEEP_SSH branch masks ssh.service/ssh.socket and repoints
# sshd at /etc/vs-router-ssh behind a /run marker that only an apply creates, so an
# update that ran it plainly stranded a console-less panel: measured live, the
# release update left :22 refusing for good while :443 stayed open. The host's SSH
# policy was decided at install time; the updater leaves it exactly as it found it.
run_installer() {  # path to the tree's install.sh
    VS_ROUTER_RELEASE_SOURCE=online VS_ROUTER_KEEP_SSH=1 bash "$1"
}

# The product identity is installer-owned (ADR-0026), and an update must not
# change it: install.sh derives the profile from VS_ROUTER_PROFILE and defaults
# to `router`, so an update that passed nothing would silently relabel a panel
# host a router. Its own stored documents, which say `panel`, would then fail the
# profile check at the next apply — the host would keep serving while refusing to
# accept any configuration. The marker the installer wrote is the source of truth
# here; an unreadable marker keeps the old capability-only behaviour, and a marker
# that holds something other than a profile stops the update instead of guessing.
resolve_profile() {  # sets and exports VS_ROUTER_PROFILE; empty means "installer decides"
    VS_ROUTER_PROFILE=${VS_ROUTER_PROFILE:-}
    if [[ -n $VS_ROUTER_PROFILE ]]; then
        export VS_ROUTER_PROFILE
        return 0
    fi
    local marker=${VS_ROUTER_PROFILE_MARKER:-/etc/vs-router/profile}
    if [[ ! -r $marker ]]; then
        export VS_ROUTER_PROFILE
        return 0
    fi
    local value
    value=$(tr -d '[:space:]' < "$marker")
    case $value in
        router|panel) VS_ROUTER_PROFILE=$value ;;
        '') warn "profile marker ${marker} is empty; the installer will decide by capability" ;;
        *) fail "profile marker ${marker} is not a known profile: '${value}'" ;;
    esac
    export VS_ROUTER_PROFILE
}

# An update must not leave a host that answers nothing (ADR-0021). The panel and
# SSH are the only two ways in, and on a VPS losing both means losing the machine.
# Both are probed after the restart: the panel through the web app's own socket
# (not through Caddy in front of it, so a TLS or Caddy problem is not mistaken for
# a working panel), SSH by its unit and its listening port. A failure restores the
# tree update.sh kept at $REPO_ROOT.prev.
PROBE_ATTEMPTS=${VS_ROUTER_UPDATE_PROBE_ATTEMPTS:-15}
PROBE_INTERVAL=${VS_ROUTER_UPDATE_PROBE_INTERVAL:-2}

panel_answers() {
    local socket=${VS_ROUTER_WEB_SOCKET:-/run/vs-router/web/web.sock} code
    [[ -S $socket ]] || return 1
    code=$(curl --silent --output /dev/null --max-time 5 --write-out '%{http_code}' \
        --unix-socket "$socket" http://localhost/health 2>/dev/null) || return 1
    [[ $code == 200 ]]
}

ssh_answers() {
    local port=${VS_ROUTER_SSH_PORT:-22} unit=
    for unit in ssh sshd; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            break
        fi
        unit=
    done
    [[ -n $unit ]] || return 1
    # A missing `ss` must not be read as "SSH is down": the unit is the signal we
    # have, and rolling back on an absent tool would be a false alarm.
    command -v ss >/dev/null 2>&1 || return 0
    ss -H -tln 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"
}

db_revision() {  # the alembic revision the database is at; empty when unreadable
    ( cd "$REPO_ROOT/backend" && VS_ROUTER_DATABASE_URL="sqlite:///${DB}" \
        python3 -m alembic current 2>/dev/null | awk 'NR==1 {print $1}' )
}

verify_update() {
    local attempts=$PROBE_ATTEMPTS
    while (( attempts > 0 )); do
        if panel_answers && ssh_answers; then
            log 'Post-update check: the panel answers and SSH is up'
            return 0
        fi
        attempts=$((attempts - 1))
        (( attempts > 0 )) && sleep "$PROBE_INTERVAL"
    done
    warn 'Post-update check failed: the panel or SSH is not answering'
    return 1
}

rollback_update() {
    local prev=$REPO_ROOT.prev
    if [[ ! -d $prev ]]; then
        warn "no previous tree at ${prev}: nothing to roll back to"
        return 1
    fi
    log "Rolling back to ${prev}"
    rm -rf "$REPO_ROOT.broken" || return 1
    mv "$REPO_ROOT" "$REPO_ROOT.broken" || return 1
    mv "$prev" "$REPO_ROOT" || return 1
    local wheel_dir="$REPO_ROOT/backend/dist"
    if compgen -G "$wheel_dir"/*.whl >/dev/null; then
        python3 -m pip install --break-system-packages --force-reinstall --no-deps \
            "$wheel_dir"/*.whl || warn 'could not reinstall the previous wheel'
    else
        warn "no wheel in ${wheel_dir}: the previous Python package is still installed"
    fi
    # ADR-0010: a rollback that leaves a newer schema behind is not a rollback.
    # The revision that was in place before the upgrade is restored from the
    # previous tree's migrations; if it was never read, or the downgrade fails,
    # that is said out loud instead of implying the database came back too.
    if [[ -n ${DB_REVISION_BEFORE:-} ]]; then
        log "Reverting the database to ${DB_REVISION_BEFORE}"
        ( cd "$REPO_ROOT/backend" && VS_ROUTER_DATABASE_URL="sqlite:///${DB}" \
            python3 -m alembic downgrade "$DB_REVISION_BEFORE" ) \
            || warn "could not revert the database to ${DB_REVISION_BEFORE}: the schema stays newer than the restored code"
    else
        warn 'the database revision before the update was not recorded; the schema is left as it is'
    fi
    resolve_profile
    run_installer "$REPO_ROOT/backend/packaging/install.sh" \
        || warn 'the previous installer did not complete'
    systemctl daemon-reload || true
    systemctl restart vs-router-agent vs-router-web \
        || warn 'the previous release did not restart cleanly'
    log "Rolled back; the tree that failed is kept at ${REPO_ROOT}.broken"
}

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
    DB_REVISION_BEFORE=
    if [ -f "$DB" ]; then
        # ADR-0010: migrations must be reversible, otherwise the update must
        # refuse, because a rollback that restores the code and leaves a newer
        # schema is not a rollback. The revision in place before the upgrade is
        # what a rollback returns to; if it cannot be read we do not pretend the
        # update is reversible.
        DB_REVISION_BEFORE=$(db_revision)
        ( cd "$REPO_ROOT/backend" && VS_ROUTER_DATABASE_URL="sqlite:///${DB}" python3 -m alembic upgrade head ) \
            || fail 'alembic upgrade failed; the database was not migrated'
    else
        warn "DB not found at ${DB}; skipping migrations (fresh install will create it)"
    fi

    log 'Deploying UI bundle and systemd units'
    resolve_profile
    log "Product profile: ${VS_ROUTER_PROFILE:-decided by host capability}"
    run_installer "$SCRIPT_DIR/install.sh"

    log 'Restarting runtime services'
    systemctl daemon-reload
    if ! systemctl restart vs-router-agent vs-router-web; then
        warn 'the runtime services did not restart'
        rollback_update || true
        fail 'the update could not restart the services; the previous release was restored'
    fi

    # ADR-0021: the update must not leave a host with no way in. A failure here is
    # the one an operator cannot repair from outside, so it rolls itself back.
    if ! verify_update; then
        rollback_update \
            || fail 'the update left the host unreachable and the rollback failed; the previous tree is kept where the log above says'
        fail 'the panel or SSH did not come back after the update; the previous release was restored'
    fi

    log 'Update complete. Verify: systemctl status vs-router-web vs-router-agent'
}

# Only run when executed, never when sourced (tests source this file to drive
# stage_release with a stub fetch()).
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
