#!/bin/bash
# vs-router TProxy REAL-reboot LAB harness (lab-32).
#
# Mirrors the PRODUCT phase order (tproxy_apply.PHASE_ORDER + READINESS_STEPS):
#   phase 1  guards      ordinary firewall + containment/preauth/DNS guards -> fail-closed
#   phase 2  readiness   systemd engine unit (pinned sing-box) + policy route
#   phase 3  interception capture/reset/input-guard tables, strictly last
#
# A readiness failure exits BEFORE interception is installed, so a broken engine
# leaves only the protective (deny) state up: the tract stays fail-closed.
#
# This is a LAB harness, NOT the product service. boot_restore.py restores only
# the guard file; this script extends the same order to the engine and the
# capture tables so a REAL reboot can be observed. It is enabled only on the
# disposable VM.
APPLIED=/etc/vs-router/applied
BIN=/usr/local/lib/vs-router/sing-box
NFT=/usr/sbin/nft
IP=/usr/sbin/ip
LOG=/run/vsr-tproxy-boot-order.log

: > "$LOG"
log() { echo "$(date -Is) $*" | tee -a "$LOG"; }

log "PHASE_START pid=$$"
# ---------------------------------------------------------------- phase 1
"$NFT" -f "$APPLIED/ordinary-firewall.nft"  || { log "FATAL guards(firewall) failed"; exit 1; }
"$NFT" -f "$APPLIED/tproxy-guards.nft"      || { log "FATAL guards(tproxy) failed"; exit 1; }
if "$NFT" list table inet vs_router_tproxy_interception >/dev/null 2>&1; then
    log "FATAL pre-interception assertion violated: capture table already present"
    exit 1
fi
log "GUARDS_UP interception_absent=yes"

# ---------------------------------------------------------------- phase 2
systemctl start vs-router-singbox.service
ok=0
for _ in $(seq 1 80); do
    if systemctl is-active --quiet vs-router-singbox.service \
       && /usr/bin/ss -H -lnt 2>/dev/null | grep -q '127.0.0.1:51272'; then
        ok=1; break
    fi
    sleep 0.1
done
if [ "$ok" != 1 ]; then
    log "FATAL readiness failed: engine not active/listening -> interception withheld (fail-closed)"
    exit 1
fi
if ! "$BIN" check -c "$APPLIED/singbox.json" >/dev/null 2>&1; then
    log "FATAL readiness failed: sing-box check"
    exit 1
fi
sysctl -qw net.ipv4.ip_forward=1
"$IP" rule del priority 100 fwmark 0x100 lookup 100 2>/dev/null || true
"$IP" route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
"$IP" rule  add priority 100 fwmark 0x100 lookup 100 || { log "FATAL policy rule"; exit 1; }
"$IP" route add local 0.0.0.0/0 dev lo table 100 || { log "FATAL policy route"; exit 1; }
log "READINESS_UP engine_active=yes policy_route=yes"

# ---------------------------------------------------------------- phase 3
"$NFT" -f "$APPLIED/tproxy-intercept.nft"   || { log "FATAL interception failed"; exit 1; }
log "INTERCEPTION_UP capture_loaded=yes"
log "PHASE_DONE"
