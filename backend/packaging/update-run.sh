#!/usr/bin/env bash
# Detached wrapper around update.sh for the panel's "apply update" action.
# Records the outcome in a state file so the read-only status endpoint can show
# progress and the last result without holding the agent's RPC call open
# (a release build can take minutes).
#
# Usage: update-run.sh --release <40hex> --manifest-url <https-url>
set -uo pipefail

STATE=${VS_ROUTER_UPDATE_STATE:-/run/vs-router/update-state.json}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

release=
manifest_url=
args=("$@")
while (($#)); do
    case $1 in
        --release)      release=${2:-}; shift ;;
        --manifest-url) manifest_url=${2:-}; shift ;;
    esac
    shift
done

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
write_state() {  # status finished_at exit_code
    mkdir -p "$(dirname "$STATE")" 2>/dev/null || true
    printf '{"status":"%s","release":"%s","started_at":"%s","finished_at":"%s","exit_code":%s}\n' \
        "$1" "$release" "$started" "$2" "$3" > "$STATE" 2>/dev/null || true
}

started=$(now)
write_state running "" 0

if [[ -z $release || ! $release =~ ^[0-9a-f]{40}$ || $manifest_url != https://* ]]; then
    write_state failed "$(now)" 2
    exit 2
fi

bash "$SCRIPT_DIR/update.sh" "${args[@]}"
code=$?

if (( code == 0 )); then
    write_state success "$(now)" "$code"
else
    write_state failed "$(now)" "$code"
fi
exit "$code"
