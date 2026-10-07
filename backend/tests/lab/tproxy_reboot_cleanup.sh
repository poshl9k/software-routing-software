#!/bin/bash
# lab-32 teardown: remove every lab artifact and confirm the guest is ordinary.
set -u
NFT=/usr/sbin/nft
IP=/usr/sbin/ip
systemctl disable --now vsr-tproxy-lab-boot.service 2>/dev/null || true
systemctl disable --now vs-router-singbox.service 2>/dev/null || true
rm -f /etc/systemd/system/vsr-tproxy-lab-boot.service /etc/systemd/system/vs-router-singbox.service
rm -rf /etc/systemd/system/vs-router-singbox.service.d
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
rm -rf /etc/vs-router /usr/local/lib/vs-router /run/vsr-tproxy-boot-order.log /root/vsr-lab
for t in vs_router_tproxy_ct_reset vs_router_tproxy_interception vs_router_tproxy_input \
         vs_router_tproxy_guard vs_router_tproxy_preauth vs_router_tproxy_dns_ingress \
         vs_router_tproxy_dns_listener vs_router_tproxy_dns_output vs_router; do
    $NFT delete table inet $t 2>/dev/null || true
done
$IP rule del priority 100 fwmark 0x100 lookup 100 2>/dev/null || true
$IP route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
for n in vsr-l32-selected vsr-l32-ordinary vsr-l32-origin; do
    ip netns del $n 2>/dev/null || true
done
echo "--- residual check ---"
$NFT list tables
echo "rules:"; $IP rule
echo "route100:"; $IP route show table 100
echo "netns:"; ip netns list
echo "units:"; systemctl list-unit-files 'vs*' 2>/dev/null
echo "applied:"; ls /etc/vs-router 2>&1
echo "CLEANUP_DONE"
