#!/bin/sh
# Runs INSIDE the installed target (d-i in-target) to unpack the vendored
# vs-router source of the pinned release. No network access is needed.
#
# On any failure it leaves a detectable incomplete-install marker and prints
# the reason on the local console, so a broken install is never silent
# (CONTEXT.md "Незавершённая установка"; ADR-0008).
set -u
cd /opt/vs-router || exit 1

marker=/var/lib/vs-router-bootstrap/incomplete
note() { printf 'vs-router: %s\n' "$*" > /dev/console 2>/dev/null || true; }
fail() {
    install -d -m 0700 "$(dirname "$marker")"
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" > "$marker"
    note "installation incomplete: $1"
    exit 1
}

command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum not available'
sha256sum -c sha256.txt >/dev/null 2>&1 || fail 'source integrity check failed'
tar -xzf source.tar.gz || fail 'source extraction failed'
rm -f source.tar.gz sha256.txt
[ -f backend/packaging/installer-prepare.sh ] || fail 'installer-prepare.sh missing'
bash backend/packaging/installer-prepare.sh || fail 'installer-prepare failed'
rm -f "$marker" 2>/dev/null || true
note 'software staged; first-boot bootstrap will run on reboot'
