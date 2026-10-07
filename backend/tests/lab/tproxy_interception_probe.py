"""Generated TProxy capture proof. AUTHORIZED DISPOSABLE DEBIAN VM ONLY, as root.

Runs the *product* interception generator (``generate_tproxy_interception``)
together with the real ordinary firewall, the offline preauthorization and
containment generators and the generated sing-box config, all inside three
freshly created network namespaces. The guest root namespace, its routes and its
firewall are untouched. Needs the reviewed sing-box binary at
``/var/cache/vsr-singbox-probe``.

This is not a product enablement path: the public gate ``tproxy.not_available``
stays closed, nothing is wired to bundle/apply/boot, and the capture text is the
exact generator output (off text is ``destroy table`` for its own table only).
Bounded observation: sender timeout 1.5s plus a 1.5s window per negative case.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

SOURCE = Path(__file__).with_name('tproxy_tcp_probe.py')
_spec = importlib.util.spec_from_file_location('vsr_interception_base', SOURCE)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

require = base.require

# lab-09-style forge: sets ONLY the packet mark (after the -85 reset), never the
# conntrack mark. Against the conntrack INPUT guard it must not authorize.
CT_FORGE = '''table inet vsr_tcp_ct_forge {{
 chain prerouting {{ type filter hook prerouting priority -84; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} tcp dport 19090 meta mark set meta mark | 0x200 counter
 }}
}}'''


def validate_fixture(policies):
    require(policies.get('__tproxy_interception__') is True,
            'requires opt-in --tproxy-interception fixture')
    require(policies.get('__input_proof__') is None
            and policies.get('__ct_proof__') is None
            and policies.get('__mark_collision__') is None,
            'interception fixture must not carry a lab proof/collision mode')
    for case in ('allow', 'allow_first', 'deny_first', 'default_deny'):
        for suffix in ('', '_firewall', '_guard', '_interception'):
            require(isinstance(policies.get(case + suffix), str),
                    f'missing generated policy: {case + suffix}')
        require('priority -90' in policies[case],
                'expected generated preauth priority -90')
        require('priority -10' in policies[case + '_guard'],
                'expected generated FORWARD containment priority -10')
        capture = policies[case + '_interception']
        require('priority -85' in capture, 'expected generated reset priority -85')
        require('priority -80' in capture, 'expected generated capture priority -80')
        require('priority -20' in capture, 'expected generated INPUT guard priority -20')
        require('tproxy ip to 127.0.0.1:51272' in capture,
                'expected generated TCP TProxy target 51272')
        require('meta mark set 0x100' in capture,
                'expected generated TProxy routing mark 0x100')
        require('ct mark set ct mark | 0x200' in capture,
                'expected generated conntrack proof set')
        require('ct mark set ct mark & 0xfffffdff' in capture,
                'expected generated conntrack proof reset')
        require('ct mark & 0x200 == 0' in capture and 'tproxy_input_denied' in capture,
                'expected generated conntrack INPUT guard')
        require('meta mark set meta mark | 0x200' not in capture,
                'capture must never set the forgeable packet proof bit')
        require('ct status dnat return' in capture, 'expected DNAT exemption')
    for key in ('off', 'off_guard', 'off_interception', 'allow_singbox'):
        require(isinstance(policies.get(key), str), f'missing generated policy: {key}')
    require(policies['off'] == 'destroy table inet vs_router_tproxy_preauth\n',
            'unexpected preauth off text')
    require(policies['off_guard'] == 'destroy table inet vs_router_tproxy_guard\n',
            'unexpected containment off text')
    require(policies['off_interception'] ==
            'destroy table inet vs_router_tproxy_ct_reset\n'
            'destroy table inet vs_router_tproxy_interception\n'
            'destroy table inet vs_router_tproxy_input\n',
            'unexpected capture off text')
    config = json.loads(policies['allow_singbox'])
    require(any(i.get('type') == 'tproxy' and i.get('network') == 'tcp'
                and i.get('listen') == '127.0.0.1' and i.get('listen_port') == 51272
                for i in config.get('inbounds', [])), 'expected TCP TProxy listener 51272')


class InterceptionLab(base.Lab):
    """Real firewall/preauth/containment plus the generated TProxy capture."""

    def __init__(self, policies, folder):
        super().__init__(policies, folder)
        require(not self.proof_mode and not self.mark_collision_mode,
                'interception probe is standalone')
        # The product-generated capture replaces the lab INTERCEPT text; every
        # reinstall during recovery uses the same generated table.
        self.intercept = policies['allow_interception']

    def ct_input_guard_proof(self):
        """(c) INPUT authorization is by conntrack mark, not the packet mark.

        Establish a healthy proxied flow, then remove ONLY the generated capture
        table (reset + INPUT guard stay). Subsequent packets of the established
        conntrack no longer get the ct proof re-set, so the guard drops them.
        A lab-09 packet-mark forge running after the reset must still be dropped:
        it writes ``meta mark`` only, never ``ct mark``.
        """
        guard = lambda: self.counter('vs_router_tproxy_input', 'input',
                                     'tproxy_input_denied')
        guard_before = guard()
        client, port = self.positive('ct-guard-healthy', retain=True)
        self.nft('flush chain inet vsr_tcp_observe established\n'
                 'add rule inet vsr_tcp_observe established iifname "lan0" '
                 'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                 'tcp dport 19090 ct state established counter\n'.format(port=port))
        token, result = self.exchange(client, 'ct-guard-established')
        require(result['reply'] == token and
                self.counter('vsr_tcp_observe', 'established') > 0,
                'ct-guard: healthy conntrack tuple was not established')
        require(guard() == guard_before,
                'ct guard dropped a healthy authorized flow')
        try:
            # Remove only the generated capture table; -85 reset and -20 guard
            # remain, exactly the lab-26 shape.
            self.nft('destroy table inet vs_router_tproxy_interception\n')
            self.nft(CT_FORGE.format(port=port))
            before = self.counters()
            guard_start = guard()
            forge_start = self.counter('vsr_tcp_ct_forge', 'prerouting')
            payload, result = self.exchange(client, 'ct-guard-post-fault')
            time.sleep(base.WINDOW)
            self.settle()
            after = self.counters()
            delta = {k: after[k] - before[k] for k in before}
            guard_delta = guard() - guard_start
            forge_delta = self.counter('vsr_tcp_ct_forge', 'prerouting') - forge_start
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
        print(json.dumps(dict(case='ct-guard', priority=-84, source_port=port,
                              token=payload, sender=result, ingress_records=ingress,
                              origin_wire_records=origin, origin_records=received,
                              delivered=delivered, echoed=result['reply'] == payload,
                              forge_delta=forge_delta, input_guard_drop_delta=guard_delta,
                              counters=delta, observation_seconds=base.WINDOW,
                              scope='lab-only observational')), flush=True)
        require(result['sent'] == len(payload) and ingress,
                'ct-guard: token lacks exact client ingress proof')
        require(forge_delta > 0, 'ct-guard: packet-mark forge injector was not reached')
        require(guard_delta > 0, 'ct-guard: conntrack INPUT guard was not reached')
        require(not delivered and result['reply'] != payload,
                'packet-mark forge bypassed conntrack INPUT authorization')
        self.nft('destroy table inet vsr_tcp_ct_forge\n')
        self.nft(self.intercept)
        self.start_proxy()
        self.positive('ct-guard-recovered')

    def execute(self):
        self.setup()
        # (a) allowed first-match traverses the proxy.
        self.positive('allow')
        # (b) fresh SYN under active capture never reaches origin: preauth -90
        #     runs before capture -80 and default-deny still holds.
        for case in ('deny_first', 'default_deny'):
            self.install(case)
            self.negative_syn(case + '-fresh')
        # (a) explicit pass-before-block ordering.
        self.install('allow_first')
        self.positive('pass-before-block')
        self.install('allow')
        # (c) INPUT authorization is by conntrack mark: a lab-09 packet-mark
        #     forge after the reset must not authorise the flow.
        self.ct_input_guard_proof()
        # (b) established flows are rechecked by preauth; no established shortcut.
        for case in ('deny_first', 'default_deny'):
            self.fault(case)
        self.proxy.stop()
        # (d) explicit off: remove the generated capture table, then the
        #     generated guards, restore ordinary forwarding.
        self.nft(self.policies['off_interception'] + self.policies['off']
                 + self.policies['off_guard'] + self.policies['allow_firewall'])
        self.policy_rule('del')
        self.policy_route('del')
        self.off = True
        self.positive('off-allow', proxied=False)
        self.nft(self.policies['default_deny_firewall'])
        self.negative_syn('off-default-deny-fresh')
        require(not self.violations, f'interception violations: {self.violations}')
        print('PASS: generated TProxy capture diverts allowed traffic through the '
              'proxy; deny/default-deny are never bypassed (preauth -90 before '
              'capture -80); explicit off restored ordinary routing.', flush=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_interception_probe.py '
                         'generated-tproxy-interception.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    validate_fixture(policies)
    require(os.geteuid() == 0, 'root required in authorized disposable VM')
    require(sys.flags.optimize == 0, 'run without Python optimization')
    with tempfile.TemporaryDirectory(prefix='vsr-tproxy-intercept-', dir='/var/cache') as folder:
        lab = InterceptionLab(policies, Path(folder))
        try:
            lab.execute()
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
