"""Focused TCP experiment: authorize INPUT from the conntrack mark, NOT the
forgeable packet ``meta mark``. AUTHORIZED DISPOSABLE DEBIAN VM ONLY, as root.

Motivation (``docs/lab-09-tproxy-mark-collision.md``): in the packet-mark proof
design a competing privileged nft rule running *after* the per-packet proof reset
could set the ``0x200`` bit on ``meta mark`` and let established TCP through
INPUT. ``meta mark`` is attacker-controllable by any writer that runs earlier in
the packet path, so it can never be unforgeable proof.

Design tested here: the interception chain sets a *conntrack* mark
(``ct mark``) after a successful TProxy expression; the per-packet reset clears
that conntrack bit; the independent INPUT guard authorizes only on
``ct mark & 0x200``. A rule that only forges the packet ``meta mark`` (exactly the
lab-09 injector) no longer reproduces the authorization token.

Honest boundary: a *privileged* rule that itself writes ``ct mark`` (``ct mark set
ct mark | 0x200``) still forges the token. Unforgeability against a competing root
nftables writer is impossible in principle; the real trust boundary is a single
writer of the mark/table/hook space (root). That residual case is executed and
recorded, not asserted away. This is a lab-only experiment: the product gate
``tproxy.not_available`` stays closed and no generator/apply/boot path changes.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

SOURCE = Path(__file__).with_name('tproxy_tcp_probe.py')
_spec = importlib.util.spec_from_file_location('vsr_tcp_ct_proof_base', SOURCE)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

require = base.require

# Interception sets the routing packet mark AND a conntrack proof bit after the
# successful TProxy expression. ct mark, unlike meta mark, is stored in the
# conntrack entry and survives across the packets of one flow.
INTERCEPT_CT = '''destroy table inet vsr_tcp_intercept
table inet vsr_tcp_intercept {
 chain prerouting { type filter hook prerouting priority -80; policy accept;
  iifname != "lan0" return
  fib daddr type local return
  meta nfproto ipv4 meta l4proto tcp meta mark set 0x100 ct mark set ct mark | 0x200
  ct status dnat return
  meta nfproto ipv4 meta l4proto tcp meta mark set 0x100 tproxy ip to 127.0.0.1:51272 counter accept
 }
}'''

# -85 reset clears the conntrack proof bit on every selected packet BEFORE the
# -80 interception re-sets it after a successful TProxy. -20 INPUT guard drops a
# selected established packet whose conntrack was not authorized by interception.
CT_GUARD = '''table inet vsr_tcp_ct_proof_reset {
 chain prerouting { type filter hook prerouting priority -85; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp dport 19090 ct mark set ct mark & 0xfffffdff
 }
}
table inet vsr_tcp_ct_input_proof {
 chain input { type filter hook input priority -20; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp dport 19090 ct mark & 0x200 == 0 counter drop
 }
}'''

COLLISION_TABLE = 'vsr_tcp_mark_collision'
CT_FORGE_TABLE = 'vsr_tcp_ct_collision'


def packet_forge_injector(port, priority):
    """Exact lab-09 injector: forge ONLY the packet meta mark, never ct mark."""
    require(priority in (-86, -84), 'invalid collision priority')
    require(type(port) is int and 1 <= port <= 65535, 'invalid client port')
    return f'''table inet {COLLISION_TABLE} {{
 chain prerouting {{ type filter hook prerouting priority {priority}; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} tcp dport 19090 meta mark set meta mark | 0x200 counter
 }}
}}'''


def ct_forge_injector(port, priority):
    """Residual boundary: a privileged rule that writes the conntrack mark."""
    require(priority in (-86, -84), 'invalid collision priority')
    require(type(port) is int and 1 <= port <= 65535, 'invalid client port')
    return f'''table inet {CT_FORGE_TABLE} {{
 chain prerouting {{ type filter hook prerouting priority {priority}; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} tcp dport 19090 ct mark set ct mark | 0x200 counter
 }}
}}'''


class CtProofLab(base.Lab):
    """Conntrack-mark INPUT authorization with the lab-09 injection replayed."""

    def __init__(self, policies, folder):
        super().__init__(policies, folder)
        require(not self.proof_mode and not self.mark_collision_mode,
                'ct proof experiment is standalone')
        self.intercept = INTERCEPT_CT

    def setup(self):
        super().setup()
        self.nft(CT_GUARD)

    def ct_drop(self):
        return self.counter('vsr_tcp_ct_input_proof', 'input')

    def established_client(self, label):
        guard_before = self.ct_drop()
        client, port = self.positive(label + '-healthy', retain=True)
        self.nft('flush chain inet vsr_tcp_observe established\n'
                 'add rule inet vsr_tcp_observe established iifname "lan0" '
                 f'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                 'tcp dport 19090 ct state established counter\n')
        token, result = self.exchange(client, label + '-established')
        established = self.counter('vsr_tcp_observe', 'established')
        require(result['reply'] == token and established > 0,
                f'{label}: healthy conntrack tuple was not established')
        require(self.ct_drop() == guard_before,
                f'{label}: ct guard dropped a healthy authorized flow')
        return client, port, established

    def trial(self, label, injector_fn, injector_table, priority):
        client, port, established = self.established_client(label)
        try:
            self.nft('destroy table inet vsr_tcp_intercept\n')
            self.nft(injector_fn(port, priority))
            before = self.counters()
            ct_before = self.ct_drop()
            inject_before = self.counter(injector_table, 'prerouting')
            payload, result = self.exchange(client, label + '-post-fault')
            time.sleep(base.WINDOW)
            self.settle()
            after = self.counters()
            delta = {k: after[k] - before[k] for k in before}
            ct_delta = self.ct_drop() - ct_before
            inject_delta = self.counter(injector_table, 'prerouting') - inject_before
        finally:
            try:
                client.stop(abort=True)
            finally:
                self.proxy.stop()
        self.settle()
        ingress = [e for e in self.frames(self.ingress, payload)
                   if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                   and e['sport'] == port and e['dport'] == 19090]
        origin = self.frames(self.origin_wire, payload)
        received = self.frames(self.receiver, payload)
        delivered = bool(origin or received)
        record = dict(case=label, priority=priority, source_port=port, token=payload,
                      sender=result, ingress_records=ingress,
                      origin_wire_records=origin, origin_records=received,
                      delivered=delivered, echoed=result['reply'] == payload,
                      injector_delta=inject_delta, ct_input_drop_delta=ct_delta,
                      counters=delta, established_control_packets=established,
                      observation_seconds=base.WINDOW, scope='lab-only observational')
        print(json.dumps(record), flush=True)
        require(result['sent'] == len(payload) and ingress,
                f'{label}: token lacks exact client ingress proof')
        require(inject_delta > 0, f'{label}: injector was not reached')
        require(delta['established'] > 0, f'{label}: packet lacks established evidence')
        self.nft(f'destroy table inet {injector_table}\n')
        self.nft(self.intercept)
        self.start_proxy()
        self.positive(label + '-recovered')
        return record

    def execute(self):
        self.setup()
        guard_before = self.ct_drop()
        self.positive('ct-allow')
        require(self.ct_drop() == guard_before,
                'ct guard dropped a healthy authorized flow')
        # Reproduce lab-09: the packet-mark forge runs AFTER the -85 reset and
        # implements no TProxy and no ct mark write.
        blocked = self.trial('ct-packet-forge', packet_forge_injector,
                             COLLISION_TABLE, priority=-84)
        require(not blocked['delivered'] and blocked['sender']['reply'] != blocked['token']
                and blocked['ct_input_drop_delta'] > 0,
                'packet-mark forge bypassed conntrack INPUT authorization')
        # Residual boundary: a privileged conntrack-mark writer still forges.
        forged = self.trial('ct-mark-forge', ct_forge_injector,
                            CT_FORGE_TABLE, priority=-84)
        self.proxy.stop()
        self.nft('destroy table inet vsr_tcp_ct_input_proof\n'
                 'destroy table inet vsr_tcp_ct_proof_reset\n'
                 'destroy table inet vsr_tcp_intercept\n'
                 + self.policies['off'] + self.policies['off_guard']
                 + self.policies['allow_firewall'])
        self.policy_rule('del')
        self.policy_route('del')
        self.off = True
        self.positive('off-allow', proxied=False)
        self.nft(self.policies['default_deny_firewall'])
        self.negative_syn('off-default-deny-fresh')
        require(not self.violations, f'ct proof violations: {self.violations}')
        print('PASS: conntrack-mark INPUT authorization rejected the lab-09 '
              f'packet-mark forge (delivered={blocked["delivered"]}); residual '
              f'conntrack-mark forge delivered={forged["delivered"]} '
              '(root/single-writer trust boundary, recorded not asserted).', flush=True)


def validate_fixture(policies):
    require(policies.get('__ct_proof__') is True,
            'requires opt-in --tcp-ct-proof fixture')
    require(policies.get('__input_proof__') is None,
            'ct proof fixture must not carry the packet-mark proof mode')
    require(policies.get('__mark_collision__') is None,
            'ct proof fixture must not carry the packet-mark collision mode')
    for case in ('allow', 'allow_first', 'deny_first', 'default_deny'):
        for suffix in ('', '_firewall', '_guard'):
            require(isinstance(policies.get(case + suffix), str),
                    f'missing generated policy: {case + suffix}')
        require('priority -90' in policies[case], 'expected generated preauth priority -90')
        require('priority -10' in policies[case + '_guard'],
                'expected generated FORWARD containment priority -10')
    for key in ('off', 'off_guard', 'allow_singbox'):
        require(isinstance(policies.get(key), str), f'missing generated policy: {key}')
    config = json.loads(policies['allow_singbox'])
    require(any(i.get('type') == 'tproxy' and i.get('network') == 'tcp'
                and i.get('listen') == '127.0.0.1' and i.get('listen_port') == 51272
                for i in config.get('inbounds', [])), 'expected TCP TProxy listener 51272')


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_tcp_ct_proof_probe.py generated-tcp-ct-proof.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    validate_fixture(policies)
    require(os.geteuid() == 0, 'root required in authorized disposable VM')
    require(sys.flags.optimize == 0, 'run without Python optimization')
    with tempfile.TemporaryDirectory(prefix='vsr-tcp-ct-', dir='/var/cache') as folder:
        lab = CtProofLab(policies, Path(folder))
        try:
            lab.execute()
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
