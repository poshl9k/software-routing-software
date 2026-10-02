#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Supply an independently verified Debian 13 ISO and its trusted SHA-256.
ISO=${1:?Usage: VS_ROUTER_REVISION=<40 hex commit> VS_ROUTER_ISO_SHA256=<trusted hash> make-iso.sh <Debian 13 ISO>}
OUT=${OUT:-vs-router-installer-amd64.iso}
[[ ${VS_ROUTER_REVISION:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'A full reviewed source commit is required' >&2; exit 1; }
[[ ${VS_ROUTER_ISO_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || { echo 'Trusted Debian ISO SHA-256 required' >&2; exit 1; }
printf '%s  %s\n' "$VS_ROUTER_ISO_SHA256" "$ISO" | sha256sum -c -
if [[ ${VS_ROUTER_UNATTENDED_LAB:-0} != 1 ]]; then
    for lab_option in VS_ROUTER_STATIC_NET VS_ROUTER_PHONEHOME_IP VS_ROUTER_WIFI VS_ROUTER_KEEP_WIFI; do
        [[ -z ${!lab_option:-} ]] || { echo "$lab_option requires VS_ROUTER_UNATTENDED_LAB=1" >&2; exit 1; }
    done
fi

need_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Missing required command: %s\nInstall build tools with: sudo apt install xorriso isolinux\n' "$1" >&2
        exit 1
    fi
}

need_command xorriso

for file in /usr/lib/ISOLINUX/isohdpfx.bin; do
    if [[ ! -f $file ]]; then
        printf 'Missing %s. Install build tools with: sudo apt install xorriso isolinux\n' "$file" >&2
        exit 1
    fi
done

workdir=$(mktemp -d)
trap 'chmod -R u+w "$workdir" 2>/dev/null; rm -rf "$workdir"' EXIT
# Extracted files keep their ISO permissions (read-only) — make them writable
# for later edits and cleanup.
chmod -R u+w "$workdir" 2>/dev/null || true

xorriso -osirrox on -indev "$ISO" -extract / "$workdir/iso"
chmod -R u+w "$workdir" 2>/dev/null || true
if [[ ${VS_ROUTER_UNATTENDED_LAB:-0} == 1 ]]; then
    install -m 0644 "$SCRIPT_DIR/preseed.cfg" "$workdir/iso/preseed.cfg"
else
    # The known lab password never enters a production ISO, even as an
    # alternative menu option.
    install -m 0644 "$SCRIPT_DIR/preseed-semiauto.cfg" "$workdir/iso/preseed.cfg"
fi
install -m 0644 "$SCRIPT_DIR/preseed-semiauto.cfg" "$workdir/iso/preseed-semiauto.cfg"

grep -Eq 'Debian GNU/Linux 13[. /]' "$workdir/iso/.disk/info" || { echo 'Debian 13 ISO required' >&2; exit 1; }
sed -i "s/@VS_ROUTER_REVISION@/$VS_ROUTER_REVISION/g" "$workdir/iso/"preseed*.cfg

# Production selects the interactive entry. Unattended boot is lab-only.
grub_default=0
if [[ ${VS_ROUTER_UNATTENDED_LAB:-0} != 1 ]]; then
    grub_default="'Semi-automatic install (expert)'"
fi
while IFS= read -r cfg; do
    sed -i 's/^set timeout=.*/set timeout=0/' "$cfg"
    printf 'set default=%s\nset timeout=0\n' "$grub_default" >> "$cfg"
done < <(find "$workdir/iso/boot/grub" "$workdir/iso/EFI" -name grub.cfg -type f 2>/dev/null)

preseed_args='priority=high preseed/file=/cdrom/preseed.cfg file=/cdrom/preseed.cfg'
if [[ ${VS_ROUTER_UNATTENDED_LAB:-0} == 1 ]]; then
    preseed_args="auto=true ${preseed_args/priority=high/priority=critical}"
fi
# Test-only static network: qemu user-net with the passt backend does not
# always answer d-i's DHCP in time; passt passes traffic through with the
# HOST's address, so for VM tests set VS_ROUTER_STATIC_NET="ip mask gw dns"
# and the installer will skip DHCP entirely. Product ISO builds are unaffected.
if [[ -n ${VS_ROUTER_STATIC_NET:-} ]]; then
    read -r _static_ip _static_mask _static_gw _static_dns <<<"$VS_ROUTER_STATIC_NET"
    preseed_args+=" netcfg/use_dhcp=false netcfg/disable_autoconfig=true"
    preseed_args+=" netcfg/get_ipaddress=${_static_ip} netcfg/get_netmask=${_static_mask}"
    preseed_args+=" netcfg/get_gateway=${_static_gw} netcfg/get_nameservers=${_static_dns}"
    preseed_args+=" netcfg/confirm_static=true"
    echo "Test static network: ip=${_static_ip} mask=${_static_mask} gw=${_static_gw} dns=${_static_dns}"
fi
# Test-only phone-home override: slirp's 10.0.2.2 does not exist on other
# network backends (virbr0 NAT, passt). Set VS_ROUTER_PHONEHOME_IP to the
# host address the guest can reach; only the STAGED preseed copies inside
# the ISO are patched — repo files and product builds are unaffected.
if [[ -n ${VS_ROUTER_PHONEHOME_IP:-} ]]; then
    sed -i "s|http://10.0.2.2:8099|http://${VS_ROUTER_PHONEHOME_IP}:8099|" \
        "$workdir/iso/preseed.cfg" "$workdir/iso/preseed-semiauto.cfg"
    echo "Test phone-home: http://${VS_ROUTER_PHONEHOME_IP}:8099"
fi
# Wi-Fi preseed: netcfg/choose_interface=auto takes the first interface with
# a link — on machines with Wi-Fi that is often the wlan NIC (cable up but
# negotiation slower), so full-auto stops at the WPA passphrase prompt and
# fails on the empty input ("Invalid passphrase"). Auto mode therefore
# BLACKLISTS the wireless stack entirely (see wifi_block_args below).
# Set VS_ROUTER_WIFI="essid passphrase" ONLY if installing over Wi-Fi is
# really wanted: it preseeds WPA credentials (unquoted secrets live in the
# ISO file — avoid; prefer Ethernet or the semi-auto mode).
if [[ -n ${VS_ROUTER_WIFI:-} ]]; then
    read -r _wifi_essid _wifi_pass <<<"$VS_ROUTER_WIFI"
    preseed_args+=" netcfg/wireless_essid=\"${_wifi_essid}\""
    preseed_args+=" netcfg/wireless_security_type=wpa netcfg/wireless_wpa=\"${_wifi_pass}\""
    echo "Test Wi-Fi: essid=${_wifi_essid} (passphrase set)"
fi
# Full-auto must never use Wi-Fi: choose_interface=auto races the wlan NIC
# against Ethernet and the wlan often links first -> dead end at the WPA
# prompt. Blacklisting mac80211+cfg80211 kills every modern wireless driver
# (all depend on them), so netcfg only ever sees wired NICs. Args before
# '---' affect the INSTALLER only — the installed system boots with its own
# cmdline and keeps its Wi-Fi. Semi-auto strips this (it asks the network
# step explicitly). Escape hatch: VS_ROUTER_KEEP_WIFI=1 to disable.
wifi_block_args=''
if [[ -z ${VS_ROUTER_KEEP_WIFI:-} ]]; then
    wifi_block_args='modprobe.blacklist=mac80211,cfg80211'
fi
# IMPORTANT: installer boot args must be placed BEFORE the '---' separator —
# everything after it goes to the installed system's cmdline, which d-i ignores.
append_to_linux_lines() {
    local cfg=$1 tmp
    tmp=$(mktemp "$workdir/edit.XXXXXX")
    awk -v extra="$preseed_args${wifi_block_args:+ $wifi_block_args}" '
        /^[[:space:]]*linux([[:space:]]|$)/ {
            if (index($0, "preseed/file=/cdrom/preseed.cfg") == 0) {
                sub(/---/, extra " ---")
            }
        }
        { print }
    ' "$cfg" > "$tmp"
    cat "$tmp" > "$cfg"
    rm -f "$tmp"
}

# Clone the first GRUB menuentry after adding the unattended arguments. This
# keeps the kernel/initrd configuration identical. priority=high keeps d-i's
# normal LINEAR flow (no main menu between steps — that is what medium does)
# while letting preseed "seen false" flags surface the core questions with
# their preseeded values as defaults. Appending a complete menuentry is valid
# GRUB syntax even when the final existing entry is followed by other commands.
append_grub_semiauto_entry() {
    local cfg=$1 tmp
    tmp=$(mktemp "$workdir/edit.XXXXXX")
    awk '
        !found && /^[[:space:]]*menuentry[[:space:]]/ {
            found=1
            block=1
        }
        found && block {
            line=$0
            if (line ~ /menuentry[[:space:]]/) {
                sub(/menuentry.*[{]/, "menuentry '\''Semi-automatic install (expert)'\'' {", line)
            }
            gsub(/priority=critical/, "priority=high", line)
            # auto=true makes d-i skip preseeded questions — the opposite of
            # semi-auto (which asks them with preseed values as defaults).
            gsub(/auto=true[[:space:]]*/, "", line)
            # The semi-auto flow asks the operator the core set (language,
            # location, keyboard, hostname, network, disk, SSH account) with
            # preseed defaults — a different preseed file drives that.
            gsub("/cdrom/preseed.cfg", "/cdrom/preseed-semiauto.cfg", line)
            # Wi-Fi stays available in semi-auto: the network step is asked
            # explicitly, so the operator can pick wlan or wired.
            gsub(/modprobe\.blacklist=mac80211,cfg80211[[:space:]]*/, "", line)
            print line
            opens=gsub(/{/, "{", $0)
            closes=gsub(/}/, "}", $0)
            depth += opens - closes
            if (depth <= 0 && opens + closes > 0) block=0
        }
    ' "$cfg" > "$tmp"
    if [[ -s $tmp ]]; then
        cat "$tmp" >> "$cfg"
    else
        printf 'Could not find a GRUB menuentry to clone in %s; skipping expert entry.\n' "$cfg" >&2
    fi
    rm -f "$tmp"
}

append_to_isolinux_append() {
    local cfg=$1 tmp
    tmp=$(mktemp "$workdir/edit.XXXXXX")
    awk -v extra="$preseed_args${wifi_block_args:+ $wifi_block_args}" '
        /^[[:space:]]*append([[:space:]]|$)/ {
            if (index($0, "preseed/file=/cdrom/preseed.cfg") == 0) {
                sub(/---/, extra " ---")
            }
        }
        { print }
    ' "$cfg" > "$tmp"
    cat "$tmp" > "$cfg"
    rm -f "$tmp"
}

found_grub=0
while IFS= read -r -d '' cfg; do
    found_grub=1
    append_to_linux_lines "$cfg"
done < <(find "$workdir/iso/boot/grub" -type f -name grub.cfg -print0 2>/dev/null || true)
if [[ -f $workdir/iso/EFI/boot/grub.cfg ]]; then
    append_to_linux_lines "$workdir/iso/EFI/boot/grub.cfg"
    found_grub=1
fi
if (( ! found_grub )); then
    printf 'Could not find a GRUB grub.cfg in the extracted ISO.\n' >&2
    exit 1
fi

# Add the expert option only after every existing Linux line has received the
# normal preseed arguments, then change only the cloned entry's priority.
while IFS= read -r -d '' cfg; do
    append_grub_semiauto_entry "$cfg"
done < <(find "$workdir/iso/boot/grub" -type f -name grub.cfg -print0 2>/dev/null || true)
if [[ -f $workdir/iso/EFI/boot/grub.cfg ]]; then
    append_grub_semiauto_entry "$workdir/iso/EFI/boot/grub.cfg"
fi

append_isolinux_semiauto_entry() {
    local cfg=$1 tmp
    tmp=$(mktemp "$workdir/edit.XXXXXX")
    awk '
        /^label[[:space:]]/ {
            if (block) exit
            if ($0 ~ /^label[[:space:]]+install([[:space:]]|$)/) { found=1; block=1 }
        }
        found && block {
            line=$0
            if (line ~ /^label[[:space:]]/) sub(/^label[[:space:]]+install/, "label semiauto", line)
            if (line ~ /^[[:space:]]*menu[[:space:]]+label[[:space:]]/) sub(/Install/, "Semi-automatic install (expert)", line)
            if (line ~ /^[[:space:]]*append[[:space:]]/) sub(/priority=critical/, "priority=high", line)
            if (line ~ /^[[:space:]]*append[[:space:]]/) gsub(/auto=true[[:space:]]*/, "", line)
            if (line ~ /^[[:space:]]*append[[:space:]]/) gsub("/cdrom/preseed.cfg", "/cdrom/preseed-semiauto.cfg", line)
            # Wi-Fi stays available in semi-auto (network step asked explicitly).
            if (line ~ /^[[:space:]]*append[[:space:]]/) gsub(/modprobe\.blacklist=mac80211,cfg80211[[:space:]]*/, "", line)
            print line
        }
    ' "$cfg" > "$tmp"
    if [[ -s $tmp ]]; then
        cat "$tmp" >> "$cfg"
    else
        printf 'Could not find an install label in %s; skipping expert entry.\n' "$cfg" >&2
    fi
    rm -f "$tmp"
}

for cfgdir in "$workdir/iso/boot/isolinux" "$workdir/iso/isolinux"; do
    [[ -d $cfgdir ]] || continue
    while IFS= read -r -d '' cfg; do
        append_to_isolinux_append "$cfg"
        if [[ $(basename "$cfg") == txt.cfg ]]; then
            append_isolinux_semiauto_entry "$cfg"
        fi
    done < <(find "$cfgdir" -type f -name '*.cfg' -print0)
done

efi_img=
for candidate in boot/grub/efi.img boot/grub/efi.img boot/grub/efi.img; do
    if [[ -f $workdir/iso/$candidate ]]; then efi_img=$candidate; break; fi
done
if [[ -z $efi_img ]]; then
    efi_img=$(find "$workdir/iso" -type f \( -iname 'efi.img' -o -iname 'efiboot.img' \) -printf '%P\n' -quit)
fi
if [[ -z $efi_img ]]; then
    printf 'Could not locate the EFI boot image in the extracted ISO.\n' >&2
    exit 1
fi

out_path=$(cd -- "$(dirname -- "$OUT")" && pwd)/$(basename -- "$OUT")
(
    cd "$workdir"
    xorriso -as mkisofs -r -V VS_ROUTER -o "$out_path" -J -joliet-long \
        -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
        -b isolinux/isolinux.bin -c isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -eltorito-alt-boot -e "$efi_img" -no-emul-boot \
        -isohybrid-gpt-basdat iso/
)
printf 'Created %s\n' "$out_path"
