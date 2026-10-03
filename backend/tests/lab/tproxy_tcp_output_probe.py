"""VM-only TCP OUTPUT revocation experiment; run only in a disposable guest.

Generate JSON with --tcp --tcp-proof or --tcp --tcp-mark-collision, then run
python3 tproxy_tcp_output_probe.py CASES.json as root in that guest. This is a
bounded destination guard, not proxy owner identification or a product design.
It cannot attribute original client packets separately from proxy outbound.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time


SOURCE = Path(__file__).with_name('tproxy_tcp_probe.py')
_spec = importlib.util.spec_from_file_location('vsr_tcp_probe_base', SOURCE)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

# OUTPUT has a route by this hook, so oifname can be matched. If route
# resolution changes, the positive guard counter requirement fails closed.
# This chain has no established accept shortcut. Revocation is inserted before
# ordinary firewall OUTPUT (priority 0), including its established accept.
OUTPUT_GUARD = '''table inet vsr_tcp_output_guard {
 chain output { type filter hook output priority -20; policy accept;
  ip daddr 198.18.0.2 oifname "wan0" tcp dport 19090 counter comment "scoped_output"
 }
}'''
OUTPUT_REVOKE = ('insert rule inet vsr_tcp_output_guard output '
                 'ip daddr 198.18.0.2 oifname "wan0" tcp dport 19090 '
                 'counter drop comment "revoked_output"')
UNRELATED_SERVER = r'''
import json, socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('198.18.0.2', 19091))
s.listen(4)
print(json.dumps({'kind': 'ready'}), flush=True)
while True:
    c, _ = s.accept()
    with c:
        c.settimeout(2)
        data = c.recv(256)
        c.sendall(data)
'''
UNRELATED_CLIENT = r'''
import socket, sys
s = socket.create_connection(('198.18.0.2', 19091), timeout=2)
s.settimeout(2)
s.sendall(sys.argv[1].encode('ascii'))
print(s.recv(256).decode('ascii'))
s.close()
'''
INPUT_OBSERVE = '''table inet vsr_tcp_output_input {
 chain input { type filter hook input priority -15; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2
  tcp dport 19090 counter comment "accepted_input_path"
 }
}'''


def validate_fixture(policies):
    base.require(policies.get('__input_proof__') is True,
                 'requires opt-in --tcp --tcp-proof or --tcp --tcp-mark-collision fixture')
    base.require(policies.get('__mark_collision__') in (None, True),
                 'invalid mark collision fixture')
    for key in ('allow_singbox', 'off', 'off_guard'):
        base.require(isinstance(policies.get(key), str), f'missing generated policy: {key}')
    for case in ('allow', 'allow_first', 'deny_first', 'default_deny'):
        for suffix in ('', '_firewall', '_guard'):
            base.require(isinstance(policies.get(case + suffix), str), 'missing generated policy')
        base.require('priority -90' in policies[case], 'expected generated preauth')
        base.require('priority -10' in policies[case + '_guard'], 'expected generated FORWARD guard')
    config = json.loads(policies['allow_singbox'])
    base.require(any(i.get('type') == 'tproxy' and i.get('network') == 'tcp'
                     and i.get('listen') == '127.0.0.1' and i.get('listen_port') == 51272
                     for i in config.get('inbounds', [])), 'expected TCP sing-box fixture')


class OutputLab(base.Lab):
    def setup(self):
        super().setup()
        self.nft(OUTPUT_GUARD)
        self.nft(INPUT_OBSERVE)
        self.unrelated = base.Child(self, base.ORIGIN, 'python3', '-u', '-c', UNRELATED_SERVER)
        base.require(self.unrelated.next()['kind'] == 'ready', 'unrelated server readiness failed')

    def guard_counts(self):
        return dict(scoped=self.counter('vsr_tcp_output_guard', 'output', 'scoped_output'),
                    revoked=self.counter('vsr_tcp_output_guard', 'output', 'revoked_output'),
                    input=self.counter('vsr_tcp_output_input', 'input', 'accepted_input_path'))

    def revoke(self):
        # The only runtime switch: add an earlier drop to this independent table.
        self.nft(OUTPUT_REVOKE + '\n')

    def restore(self):
        self.nft('flush chain inet vsr_tcp_output_guard output\n'
                 'add rule inet vsr_tcp_output_guard output '
                 'ip daddr 198.18.0.2 oifname "wan0" tcp dport 19090 '
                 'counter comment "scoped_output"\n')

    def output_trial(self):
        client, port = self.positive('output-healthy', retain=True)
        self.nft('flush chain inet vsr_tcp_observe established\n'
                 'add rule inet vsr_tcp_observe established iifname "lan0" '
                 f'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                 'tcp dport 19090 ct state established counter\n')
        token, result = self.exchange(client, 'output-established')
        established = self.counter('vsr_tcp_observe', 'established')
        base.require(result['reply'] == token and established > 0,
                     'exact tuple lacked established control')
        before = self.guard_counts()
        base.require(before['scoped'] > 0 and before['input'] > 0,
                     'healthy path did not reach OUTPUT and INPUT observers')
        self.revoke()
        blocked = None
        try:
            unrelated_token = 'unrelated-' + base.uuid.uuid4().hex
            unrelated_reply = base.ns(base.ROUTER, 'python3', '-c', UNRELATED_CLIENT,
                                      unrelated_token).stdout.strip()
            base.require(unrelated_reply == unrelated_token, 'unrelated router egress failed')
            token, result = self.exchange(client, 'output-revoked')
            time.sleep(base.WINDOW)
            self.settle()
            after = self.guard_counts()
            ingress = [e for e in self.frames(self.ingress, token)
                       if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                       and e['sport'] == port and e['dport'] == 19090]
            blocked = dict(case='output-revoked', source_port=port, token=token,
                           sender=result, ingress_records=ingress,
                           established_control_packets=established,
                           counters={k: after[k] - before[k] for k in before},
                           origin_wire_records=self.frames(self.origin_wire, token),
                           origin_records=self.frames(self.receiver, token),
                           observation_seconds=base.WINDOW,
                           unrelated_router_egress=unrelated_reply,
                           scope='destination-only lab guard; proxy owner and client attribution unresolved')
        finally:
            # Kill both endpoints and sing-box while OUTPUT remains revoked.
            client.stop(abort=True)
            self.receiver.stop()
            self.proxy.stop()
            self.unrelated.stop()
        self.settle_without_receiver()
        base.require(blocked is not None, 'revocation observation incomplete')
        print(json.dumps(blocked), flush=True)
        base.require(blocked['sender']['sent'] == len(token) and blocked['ingress_records'],
                     'queued send is not sender ingress wire evidence')
        base.require(blocked['counters']['input'] > 0, 'independent INPUT path not seen')
        base.require(blocked['counters']['revoked'] > 0, 'OUTPUT drop not reached')
        base.require(not blocked['origin_wire_records'] and not blocked['origin_records']
                     and blocked['sender']['reply'] != token, 'revoked token leaked')
        self.restore()
        self.receiver = base.Child(self, base.ORIGIN, 'python3', '-u', '-c', base.RECEIVER)
        base.require(self.receiver.next()['kind'] == 'ready', 'receiver restart failed')
        self.monitors[-1] = self.receiver
        self.start_proxy()
        self.positive('output-recovered')

    def settle_without_receiver(self):
        time.sleep(0.3)
        base.require(all(c.p.poll() is None for c in self.monitors[:-1]), 'capture died')

    def execute(self):
        self.setup()
        self.output_trial()
        self.proxy.stop()
        self.nft('destroy table inet vsr_tcp_output_guard\n'
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
        print('PASS: bounded destination-scoped OUTPUT lab; proxy owner identity and '
              'original client-to-proxy outbound attribution remain unresolved.', flush=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_tcp_output_probe.py generated-tcp-proof.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    validate_fixture(policies)
    base.require(os.geteuid() == 0, 'root required in authorized disposable VM')
    base.require(sys.flags.optimize == 0, 'run without Python optimization')
    with tempfile.TemporaryDirectory(prefix='vsr-tcp-output-', dir='/var/cache') as folder:
        lab = OutputLab(policies, Path(folder))
        try:
            lab.execute()
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
