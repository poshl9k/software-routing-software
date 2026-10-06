#!/bin/bash
set +x
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
export HOME=/root
export GOPATH=/root/go
export GOMODCACHE=/root/go/pkg/mod
export GOCACHE=/root/.cache/go-build
export PATH="$PATH:$GOPATH/bin"
state=/var/lib/vs-router-bootstrap
install -d -m 0700 "$state"
exec 9>"$state/lock"
flock -n 9 || { echo 'Bootstrap is already running' >&2; exit 1; }
case ${1:-} in
    --retry) rm -f "$state/attempted" ;;
    '') ;;
    *) echo 'Usage: firstboot-bootstrap.sh [--retry]' >&2; exit 2 ;;
esac
if [[ -e $state/incomplete ]]; then
    # The installer never staged the source (see install-source.sh). Do not run
    # the software bootstrap on a broken install; the admin must repair first.
    printf 'Bootstrap skipped: installation is incomplete. Fix the cause, re-run install-source.sh from the ISO, then: firstboot-bootstrap.sh --retry\n' > /dev/console || true
    echo 'Installation is incomplete (source not staged); refusing to bootstrap.' >&2
    exit 1
fi
if [[ -e $state/attempted ]]; then
    echo 'Previous bootstrap attempted. Use firstboot-bootstrap.sh --retry from the console.' >&2
    exit 1
fi
rm -f "$state/succeeded"
touch "$state/attempted"
# Keep the unit enabled on failure, but the persistent attempt marker prevents
# automatic retries after reboot. An interrupted attempt also needs --retry.
rc=0
install -m 0600 /dev/null /root/bootstrap.log
bash /opt/vs-router/backend/packaging/bootstrap.sh > /root/bootstrap.log 2>&1 || rc=$?
tail -50 /root/bootstrap.log > /dev/console || true
if ((rc == 0)); then
    systemctl disable vs-router-bootstrap-firstboot.service
    touch "$state/succeeded"
else
    printf 'Bootstrap FAILED (%s). See /root/bootstrap.log; correct the cause, then run:\nsudo bash /opt/vs-router/backend/packaging/firstboot-bootstrap.sh --retry\n' "$rc" > /dev/console || true
fi
exit "$rc"
