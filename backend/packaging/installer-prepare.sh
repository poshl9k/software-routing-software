#!/bin/bash
# Runs inside the d-i target. No daemon starts in the installer chroot.
set -euo pipefail
umask 077
packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -m 0700 /etc/vs-router /var/lib/vs-router-bootstrap
# Preserve the installer-selected DHCP port, not a guessed LAN/default route.
mapfile -t uplinks < <(awk '$1 == "iface" && $3 == "inet" && $4 == "dhcp" {print $2}' /etc/network/interfaces)
((${#uplinks[@]} == 1)) || { echo 'Exactly one wired DHCP installer uplink required' >&2; exit 1; }
iface=${uplinks[0]}
[[ $iface =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$ && -e /sys/class/net/$iface/device && ! -e /sys/class/net/$iface/wireless ]]
printf '%s %s\n' "$iface" "$(< "/sys/class/net/$iface/address")" > /var/lib/vs-router-bootstrap/installer-uplink
# SSH is not selected in the initial package set. Mask socket activation now;
# bootstrap installs SSH but only an applied interface-scoped policy may open it.
systemctl mask ssh.service ssh.socket
install -m 0644 "$packaging_dir/bootstrap.nft" /etc/nftables.conf
systemctl enable nftables.service
install -m 0644 "$packaging_dir/vs-router-bootstrap-firstboot.service" /etc/systemd/system/
systemctl enable vs-router-bootstrap-firstboot.service
