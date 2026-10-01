#!/usr/bin/env bash
# Update the vs-router application code and built distribution ("distro") on a
# running server, without reinstalling OS packages or rebuilding the toolchain
# (Caddy, amneziawg-tools, wireguard-go) that bootstrap.sh provisioned.
#
# What it does:
#   1. git pull (fast-forward) the latest code
#   2. rebuild the frontend static bundle (frontend/dist) and the backend wheel
#   3. reinstall the Python package (system python, matching bootstrap.sh)
#   4. apply database migrations (alembic upgrade head) against the live DB
#   5. deploy the UI bundle + systemd units via install.sh
#   6. restart the runtime services
#
# Re-run bootstrap.sh only when OS-level dependencies or the toolchain change
# (new Caddy/AmneziaWG/WireGuard builds, new apt packages).
#
# Usage: sudo ./backend/packaging/update.sh [--skip-pull] [--skip-build]
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
DB=/var/lib/vs-router/vs-router.db

log()  { printf '[vs-router-update] %s\n' "$*" >&2; }
warn() { printf '[vs-router-update] WARNING: %s\n' "$*" >&2; }
fail() { printf '[vs-router-update] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: update.sh [--skip-pull] [--skip-build] [--help]
  --skip-pull    Do not git pull; update from the current working tree.
  --skip-build   Do not rebuild frontend/backend; deploy what is already built.
  --help         Show this help.
EOF
}

SKIP_PULL=0
SKIP_BUILD=0
while (($#)); do
    case $1 in
        --skip-pull)  SKIP_PULL=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --help|-h)    usage; exit 0 ;;
        *) usage >&2; fail "unknown option: $1" ;;
    esac
    shift
done

if [[ ${EUID} -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 && fail 'run as root (sudo ./update.sh)'
    fail 'run this script as root'
fi

cd "$REPO_ROOT"

if (( ! SKIP_PULL )); then
    log 'Pulling latest code'
    if ! git pull --ff-only; then
        warn 'git pull --ff-only failed; continuing with the current tree. Resolve divergence or use --skip-pull if intentional.'
    fi
fi

if (( ! SKIP_BUILD )); then
    log 'Building frontend bundle'
    ( cd "$REPO_ROOT/frontend" && npm ci && npm run build )
    log 'Building backend wheel'
    ( cd "$REPO_ROOT/backend" && rm -rf dist && python3 -m pip wheel --no-deps -w dist . )
fi

log 'Installing backend package'
wheel_dir="$REPO_ROOT/backend/dist"
compgen -G "$wheel_dir"/*.whl >/dev/null || fail "no backend wheel found in ${wheel_dir} (run without --skip-build)"
python3 -m pip install --break-system-packages --force-reinstall --no-deps "$wheel_dir"/*.whl
python3 -m pip install --break-system-packages "$wheel_dir"/*.whl

log 'Applying database migrations'
if [ -f "$DB" ]; then
    ( cd "$REPO_ROOT/backend" && VS_ROUTER_DATABASE_URL="sqlite:///${DB}" python3 -m alembic upgrade head ) \
        || warn 'alembic upgrade failed; check DB state before applying configuration'
else
    warn "DB not found at ${DB}; skipping migrations (fresh install will create it)"
fi

log 'Deploying UI bundle and systemd units'
bash "$SCRIPT_DIR/install.sh"

log 'Restarting runtime services'
systemctl daemon-reload
systemctl restart vs-router-agent vs-router-web 2>/dev/null \
    || warn 'one or more runtime services did not restart; check systemctl status'

log 'Update complete. Verify: systemctl status vs-router-web vs-router-agent'
