#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEFAULT_ISO=/var/lib/libvirt/images/debian-13.7.0-amd64-netinst.iso
DOWNLOAD_URL=https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso
OUT=${OUT:-vs-router-installer-13.7.0-amd64.iso}
ISO=${1:-$DEFAULT_ISO}

need_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Missing required command: %s\nInstall build tools with: sudo apt install xorriso isolinux\n' "$1" >&2
        exit 1
    fi
}

need_command xorriso
if [[ ! -f $ISO ]]; then
    if [[ $ISO != "$DEFAULT_ISO" ]]; then
        printf 'Input ISO not found: %s\n' "$ISO" >&2
        exit 1
    fi
    need_command curl
    ISO=/tmp/debian-13.7.0-amd64-netinst.iso
    printf 'Downloading Debian netinst ISO to %s\n' "$ISO"
    curl -fL "$DOWNLOAD_URL" -o "$ISO"
fi

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
install -m 0644 "$SCRIPT_DIR/preseed.cfg" "$workdir/iso/preseed.cfg"

# Fully unattended GRUB: the netinst grub.cfg has NO 'set timeout=' line, and
# GRUB then waits for user input forever. Force the default entry with zero
# timeout (append works: menu entries above are already defined).
while IFS= read -r cfg; do
    sed -i 's/^set timeout=.*/set timeout=0/' "$cfg"
    printf 'set default=0\nset timeout=0\n' >> "$cfg"
done < <(find "$workdir/iso/boot/grub" "$workdir/iso/EFI" -name grub.cfg -type f 2>/dev/null)

preseed_args='auto=true priority=critical preseed/file=/cdrom/preseed.cfg file=/cdrom/preseed.cfg'
# IMPORTANT: installer boot args must be placed BEFORE the '---' separator —
# everything after it goes to the installed system's cmdline, which d-i ignores.
append_to_linux_lines() {
    local cfg=$1 tmp
    tmp=$(mktemp "$workdir/edit.XXXXXX")
    awk -v extra="$preseed_args" '
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
# keeps the kernel/initrd configuration identical while exposing d-i's expert
# questions through priority=medium. Appending a complete menuentry is valid
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
                sub(/menuentry[[:space:]]+[^ ]+/, "menuentry '\''Semi-automatic install (expert)'\''", line)
            }
            gsub(/priority=critical/, "priority=medium", line)
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
    awk -v extra="$preseed_args" '
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
            if (line ~ /^[[:space:]]*append[[:space:]]/) sub(/priority=critical/, "priority=medium", line)
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
