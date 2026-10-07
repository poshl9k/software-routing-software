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

SOURCE = Path(__file__).with_name('tproxy_tcp_probe.py')
_spec = importlib.util.spec_from_file_location('vsr_interception_base', SOURCE)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

require = base.require


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
        require('priority -80' in capture, 'expected generated capture priority -80')
        require('tproxy ip to 127.0.0.1:51272' in capture,
                'expected generated TCP TProxy target 51272')
        require('meta mark set 0x100' in capture,
                'expected generated TProxy routing mark 0x100')
        require('0x200' not in capture, 'capture must never set a proof bit')
        require('ct status dnat return' in capture, 'expected DNAT exemption')
    for key in ('off', 'off_guard', 'off_interception', 'allow_singbox'):
        require(isinstance(policies.get(key), str), f'missing generated policy: {key}')
    require(policies['off'] == 'destroy table inet vs_router_tproxy_preauth\n',
            'unexpected preauth off text')
    require(policies['off_guard'] == 'destroy table inet vs_router_tproxy_guard\n',
            'unexpected containment off text')
    require(policies['off_interception'] ==
            'destroy table inet vs_router_tproxy_interception\n',
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
