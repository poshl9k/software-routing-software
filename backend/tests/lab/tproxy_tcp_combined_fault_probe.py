"""Root-only, disposable-VM TCP namespace experiment. No product enablement.

Bounded observations do not provide an automatic health detector. A forged INPUT
proof remains possible; OUTPUT revocation only covers this destination and UID.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import time

import importlib.util

SOURCE = Path(__file__).with_name('tproxy_tcp_uid_probe.py')
_spec = importlib.util.spec_from_file_location('vsr_tcp_combined_uid', SOURCE)
uid = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uid)
base = uid.base


class CombinedLab(uid.UidLab):
    def established_client(self, label):
        client, port = self.positive(label + '-healthy', retain=True)
        self.nft('flush chain inet vsr_tcp_observe established\n'
                 'add rule inet vsr_tcp_observe established iifname "lan0" '
                 f'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                 'tcp dport 19090 ct state established counter\n')
        token, result = self.exchange(client, label + '-established')
        established = self.counter('vsr_tcp_observe', 'established')
        base.require(result['reply'] == token and established > 0,
                     'exact established client tuple was not proved')
        counts = self.uid_counts()
        base.require(counts['proxy'] > 0 and counts['input'] > 0,
                     'healthy proxy UID and INPUT path missing')
        return client, port, established

    def observe_fault(self, client, port, established, label):
        before = self.uid_counts()
        ordinary_before = self.counters()
        proof_before = self.counter('vsr_tcp_input_proof', 'input')
        inject_before = self.counter('vsr_tcp_mark_collision', 'prerouting')
        token, sender = self.exchange(client, label + '-post-fault')
        time.sleep(base.WINDOW)
        self.settle()
        after = self.uid_counts()
        ordinary_after = self.counters()
        ingress = [e for e in self.frames(self.ingress, token)
                   if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                   and e['sport'] == port and e['dport'] == 19090]
        evidence = dict(case=label, source_port=port, token=token, sender=sender,
                        established_control_packets=established,
                        ingress_records=ingress,
                        injector_delta=self.counter('vsr_tcp_mark_collision', 'prerouting') - inject_before,
                        input_proof_drop_delta=self.counter('vsr_tcp_input_proof', 'input') - proof_before,
                        uid_counters={k: after[k] - before[k] for k in before},
                        established_delta=ordinary_after['established'] - ordinary_before['established'],
                        forward_guard_delta=ordinary_after['guard'] - ordinary_before['guard'],
                        origin_wire_records=self.frames(self.origin_wire, token),
                        origin_records=self.frames(self.receiver, token),
                        observation_seconds=base.WINDOW)
        base.require(sender['sent'] == len(token) and ingress,
                     'post-fault token lacks exact client ingress')
        base.require(evidence['injector_delta'] > 0 and evidence['established_delta'] > 0,
                     'injector or established path not reached')
        base.require(evidence['input_proof_drop_delta'] == 0 and
                     evidence['uid_counters']['input'] > 0 and
                     evidence['forward_guard_delta'] == 0,
                     'forged INPUT bypass or FORWARD containment evidence failed')
        return evidence

    def stop_old(self, client):
        try:
            client.stop(abort=True)
        finally:
            self.proxy.stop()
        self.settle()

    def collision_trial(self):
        client, port, established = self.established_client('combined-collision')
        try:
            self.nft('destroy table inet vsr_tcp_intercept\n')
            self.nft(base.collision_injector(port, -84))
            evidence = self.observe_fault(client, port, established, 'combined-collision')
        finally:
            self.stop_old(client)
        evidence['origin_wire_records'] = self.frames(self.origin_wire, evidence['token'])
        evidence['origin_records'] = self.frames(self.receiver, evidence['token'])
        print(json.dumps(evidence), flush=True)
        base.require(evidence['uid_counters']['proxy'] > 0 and
                     evidence['uid_counters']['drop'] == 0 and
                     evidence['sender']['reply'] == evidence['token'] and
                     any(e.get('src') == '10.212.2.1' for e in evidence['origin_wire_records']) and
                     evidence['origin_records'] and
                     evidence['origin_records'][0]['peer'][0] == '10.212.2.1',
                     'baseline collision did not leak through proxy')
        self.nft('destroy table inet vsr_tcp_mark_collision\n')
        self.nft(self.intercept)
        self.start_proxy()

    def combined_trial(self):
        client, port, established = self.established_client('combined-revoked')
        self.revoke()
        try:
            self.nft('destroy table inet vsr_tcp_intercept\n')
            self.nft(base.collision_injector(port, -84))
            evidence = self.observe_fault(client, port, established, 'combined-revoked')
        finally:
            self.stop_old(client)
        # Keep the receiver and both fault rules in place through the other-UID control.
        base.require(evidence['uid_counters']['drop'] > 0 and
                     evidence['sender']['reply'] != evidence['token'],
                     'proxy UID OUTPUT revocation did not block echo')
        other_token = 'vsr-tcp-combined-other-' + base.uuid.uuid4().hex + '\n'
        before = self.uid_counts()
        other = json.loads(base.ns(
            base.ROUTER, 'setpriv', '--reuid=29091', '--regid=29091',
            '--clear-groups', 'python3', '-c', uid.OTHER_CLIENT, other_token).stdout)
        self.settle()
        after = self.uid_counts()
        received = self.frames(self.receiver, other_token)
        evidence['other_uid'] = dict(token=other_token, sender=other,
                                     observer_delta=after['other'] - before['other'],
                                     proxy_drop_delta=after['drop'] - before['drop'],
                                     origin_records=received,
                                     origin_wire_records=self.frames(self.origin_wire, other_token))
        evidence['origin_wire_records'] = self.frames(self.origin_wire, evidence['token'])
        evidence['origin_records'] = self.frames(self.receiver, evidence['token'])
        print(json.dumps(evidence), flush=True)
        base.require(not evidence['origin_wire_records'] and not evidence['origin_records'],
                     'revoked token reached origin after controls')
        base.require(other['reply'] == other_token and
                     other['peer'] == ['198.18.0.2', 19090] and
                     len(received) == 1 and received[0]['peer'][0] == '10.212.2.1' and
                     evidence['other_uid']['origin_wire_records'] and
                     evidence['other_uid']['observer_delta'] > 0 and
                     evidence['other_uid']['proxy_drop_delta'] == 0,
                     'same-destination other UID control failed')
        self.receiver.stop()
        self.settle_without_receiver()
        self.nft('destroy table inet vsr_tcp_mark_collision\n')
        self.restore()
        self.nft(self.intercept)
        self.receiver = base.Child(self, base.ORIGIN, 'python3', '-u', '-c', base.RECEIVER)
        base.require(self.receiver.next()['kind'] == 'ready', 'receiver restart failed')
        self.monitors[-1] = self.receiver
        self.start_proxy()
        self.positive('combined-recovered')

    def execute(self):
        self.setup()
        self.collision_trial()
        self.combined_trial()
        self.proxy.stop()
        self.nft('destroy table inet vsr_tcp_uid_guard\n'
                 'destroy table inet vsr_tcp_output_input\n'
                 'destroy table inet vsr_tcp_input_proof\n'
                 'destroy table inet vsr_tcp_proof_reset\n'
                 'destroy table inet vsr_tcp_intercept\n'
                 + self.policies['off'] + self.policies['off_guard']
                 + self.policies['allow_firewall'])
        self.policy_rule('del')
        self.policy_route('del')
        self.off = True
        self.positive('off-ordinary-forward', proxied=False)
        self.nft(self.policies['default_deny_firewall'])
        self.negative_syn('off-default-deny')
        print('PASS: bounded destination+UID OUTPUT revocation; forged INPUT proof '
              'persists; no automatic health detector or product enablement.', flush=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_tcp_combined_fault_probe.py generated-tcp-proof.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    uid.validate_fixture(policies)
    base.require(policies.get('__mark_collision__') is None,
                 'requires --tcp-proof fixture without collision mode')
    base.require(os.geteuid() == 0, 'root required in authorized disposable VM')
    base.require(sys.flags.optimize == 0, 'run without Python optimization')
    with tempfile.TemporaryDirectory(prefix='vsr-tcp-combined-', dir='/var/cache') as folder:
        lab = CombinedLab(policies, Path(folder))
        try:
            lab.execute()
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
