#!/bin/bash
# First-boot bootstrap for the vs-router installer ISO.
#
# Why not in d-i late_command: inside the d-i chroot the pipelined apt
# downloads reproducibly deadlock — the http method process spins at ~100%
# CPU around the ~300MB mark, makes no connections and no disk writes, and
# never hits its own timeouts (observed on slirp AND virbr0 NAT). The same
# bootstrap.sh on a booted Debian 13 system is proven to work, so the
# preseed late_command only clones the repo, installs
# vs-router-bootstrap-firstboot.service and enables it; this script runs on
# the first boot in the normal environment.
set -u
export DEBIAN_FRONTEND=noninteractive
export PS4="+$(date +%H:%M:%S) "

# Bounded wait for connectivity (DHCP may lag the service start at boot).
n=0
until getent hosts deb.debian.org >/dev/null 2>&1 || [ "$n" -ge 30 ]; do
    sleep 2
    n=$((n+1))
done

bash -x /opt/vs-router/backend/packaging/bootstrap.sh --lab > /root/bootstrap.log 2>&1
rc=$?
tail -50 /root/bootstrap.log > /dev/console
# Phone-home to the HOST, which is the default gateway on every test network
# (slirp: 10.0.2.2, libvirt NAT: 192.168.122.1, passt: host address).
gw=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1)
if [ -n "$gw" ]; then
    curl -s -m 5 "http://$gw:8099/?bootstrap=$rc" >/dev/null 2>&1 || true
fi
systemctl disable vs-router-bootstrap-firstboot.service 2>/dev/null || true
exit $rc