#!/bin/bash
# One-time lab-32 setup on the disposable VM. Idempotent.
set -e
LIB=/usr/local/lib/vs-router
APPLIED=/etc/vs-router/applied
SRC=/root/vsr-lab
mkdir -p "$LIB" "$APPLIED"
install -m0755 "$SRC/sing-box"            "$LIB/sing-box"
install -m0755 "$SRC/lab-boot.sh"         "$LIB/lab-boot.sh"
install -m0644 "$SRC/artifacts/"*.nft     "$APPLIED/"
install -m0644 "$SRC/artifacts/singbox.json" "$APPLIED/singbox.json"
install -m0644 "$SRC/artifacts/tproxy-unbound-selected.conf" "$APPLIED/"
install -m0644 "$SRC/artifacts/tproxy-unbound-ordinary.conf" "$APPLIED/"
install -m0644 "$SRC/vs-router-singbox.service"      /etc/systemd/system/
install -m0644 "$SRC/vsr-tproxy-lab-boot.service"     /etc/systemd/system/
mkdir -p /etc/systemd/system/vs-router-singbox.service.d
install -m0644 "$SRC/singbox-netlink-lab.conf" \
    /etc/systemd/system/vs-router-singbox.service.d/lab-netlink.conf
systemctl daemon-reload
systemctl enable vs-router-singbox.service vsr-tproxy-lab-boot.service
echo "--- binary identity ---"
"$LIB/sing-box" version
sha256sum "$LIB/sing-box"
echo "--- applied dir ---"
ls -l "$APPLIED"
echo "SETUP_OK"
