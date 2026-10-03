"""VM-only, stdlib TCP experiment for a test-owned proxy UID.

Run as root in an authorized disposable guest with a generated --tcp-proof JSON
fixture. Numeric UIDs here are laboratory identities, not product architecture.
The result cannot attribute proxy output to a client policy or contain hostile root.
"""
import json
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time

SOURCE = Path(__file__).with_name('tproxy_tcp_output_probe.py')
_spec = importlib.util.spec_from_file_location('vsr_tcp_output_probe_base', SOURCE)
output = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(output)


base = output.base
PROXY_UID = 29090
OTHER_UID = 29091
NET_RAW = 1 << 13
SCOPE = 'ip daddr 198.18.0.2 oifname "wan0" tcp dport 19090'
UID_GUARD = f'''table inet vsr_tcp_uid_guard {{
 chain output {{ type filter hook output priority -20; policy accept;
  meta skuid {PROXY_UID} {SCOPE} counter comment "proxy_uid"
  meta skuid {OTHER_UID} {SCOPE} counter comment "other_uid"
 }}
}}'''
UID_REVOKE = (f'insert rule inet vsr_tcp_uid_guard output meta skuid {PROXY_UID} '
              f'{SCOPE} counter drop comment "proxy_uid_drop"')
OTHER_CLIENT = r'''
import json, socket, sys
token = sys.argv[1]
with socket.create_connection(('198.18.0.2', 19090), timeout=2) as s:
    s.settimeout(2)
    s.sendall(token.encode('ascii'))
    reply = bytearray()
    while not reply.endswith(b'\n'):
        chunk = s.recv(256)
        if not chunk:
            break
        reply.extend(chunk)
    print(json.dumps({'reply': reply.decode('ascii'), 'peer': s.getpeername()}))
'''


def validate_fixture(policies):
    output.validate_fixture(policies)
    config = json.loads(policies['allow_singbox'])
    # Only the known direct test config is allowed into the UID-readable file.
    # Exact shape also rejects future secret-bearing outbound or inbound fields.
    base.require(config == {
        'inbounds': [
            {'type': 'tproxy', 'tag': 'tproxy-udp', 'listen': '127.0.0.1',
             'listen_port': 51271, 'network': 'udp'},
            {'type': 'tproxy', 'tag': 'tproxy-tcp', 'listen': '127.0.0.1',
             'listen_port': 51272, 'network': 'tcp'},
        ],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        'route': {'rules': [], 'final': 'direct', 'auto_detect_interface': True},
    }, 'requires secret-free direct-only sing-box fixture')


class UidLab(output.OutputLab):
    def start_proxy(self):
        # The parent and config are readable only by this test UID, not world.
        config = self.folder / 'config.json'
        os.chown(self.folder, PROXY_UID, PROXY_UID)
        os.chmod(self.folder, 0o700)
        os.chown(config, PROXY_UID, PROXY_UID)
        os.chmod(config, 0o600)
        self.proxy = base.Child(
            self, base.ROUTER, 'setpriv', '--reuid=29090', '--regid=29090',
            '--clear-groups', '--bounding-set=-all,+net_raw',
            '--inh-caps=+net_raw', '--ambient-caps=+net_raw',
            base.BINARY, 'run', '-c', str(config))
        for _ in range(50):
            base.require(self.proxy.p.poll() is None,
                         f'UID proxy failed to start: {self.proxy.errors[-10:]}')
            status = Path(f'/proc/{self.proxy.p.pid}/status').read_text()
            fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
            uids = [int(part) for part in fields['Uid'].split()]
            effective = int(fields['CapEff'].strip(), 16)
            ambient = int(fields['CapAmb'].strip(), 16)
            if uids == [PROXY_UID] * 4 and effective == NET_RAW and ambient == NET_RAW:
                listeners = base.ns(base.ROUTER, 'ss', '-H', '-ltnp').stdout.splitlines()
                if any('127.0.0.1:51272' in line and
                       f'pid={self.proxy.p.pid},' in line for line in listeners):
                    return
            time.sleep(0.1)
        raise AssertionError('UID/capability-owned TCP listener readiness failed')

    def setup(self):
        # Reuse the core namespace setup, excluding OutputLab's destination
        # observer and its unrelated-port server from this same-tuple experiment.
        base.Lab.setup(self)
        self.nft(UID_GUARD)
        self.nft(output.INPUT_OBSERVE)

    def uid_counts(self):
        return dict(proxy=self.counter('vsr_tcp_uid_guard', 'output', 'proxy_uid'),
                    other=self.counter('vsr_tcp_uid_guard', 'output', 'other_uid'),
                    drop=self.counter('vsr_tcp_uid_guard', 'output', 'proxy_uid_drop'),
                    input=self.counter('vsr_tcp_output_input', 'input', 'accepted_input_path'))

    def revoke(self):
        self.nft(UID_REVOKE + '\n')

    def restore(self):
        self.nft('flush chain inet vsr_tcp_uid_guard output\n'
                 f'add rule inet vsr_tcp_uid_guard output meta skuid {PROXY_UID} '
                 f'{SCOPE} counter comment "proxy_uid"\n'
                 f'add rule inet vsr_tcp_uid_guard output meta skuid {OTHER_UID} '
                 f'{SCOPE} counter comment "other_uid"\n')

    def uid_trial(self):
        client, port = self.positive('uid-healthy', retain=True)
        self.nft('flush chain inet vsr_tcp_observe established\n'
                 'add rule inet vsr_tcp_observe established iifname "lan0" '
                 f'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                 'tcp dport 19090 ct state established counter\n')
        token, result = self.exchange(client, 'uid-established')
        established = self.counter('vsr_tcp_observe', 'established')
        base.require(result['reply'] == token and established > 0,
                     'exact client tuple lacked established control')
        before = self.uid_counts()
        base.require(before['proxy'] > 0 and before['input'] > 0 and before['other'] == 0,
                     'healthy path did not prove proxy UID and INPUT')
        self.revoke()
        blocked = None
        try:
            token, result = self.exchange(client, 'uid-revoked')
            time.sleep(base.WINDOW)
            self.settle()
            after = self.uid_counts()
            ingress = [e for e in self.frames(self.ingress, token)
                       if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                       and e['sport'] == port and e['dport'] == 19090]
            blocked = dict(case='uid-revoked', source_port=port, sender=result,
                           ingress_records=ingress, established_control_packets=established,
                           counters={k: after[k] - before[k] for k in before},
                           origin_wire_records=self.frames(self.origin_wire, token),
                           origin_records=self.frames(self.receiver, token),
                           observation_seconds=base.WINDOW)
            base.require(result['sent'] == len(token) and ingress,
                         'post-fault send lacked exact client ingress payload')
            base.require(blocked['counters']['input'] > 0 and blocked['counters']['drop'] > 0,
                         'INPUT observer or proxy UID drop absent')
            base.require(not blocked['origin_wire_records'] and not blocked['origin_records']
                         and result['reply'] != token, 'revoked proxy token reached origin')

            # Same destination and port, from an unrelated test-owned UID.
            other_token = 'vsr-tcp-other-uid-' + base.uuid.uuid4().hex + '\n'
            other_before = self.uid_counts()
            other = json.loads(base.ns(
                base.ROUTER, 'setpriv', '--reuid=29091', '--regid=29091',
                '--clear-groups', 'python3', '-c', OTHER_CLIENT, other_token
            ).stdout)
            self.settle()
            other_after = self.uid_counts()
            received = self.frames(self.receiver, other_token)
            wire = self.frames(self.origin_wire, other_token)
            base.require(other['reply'] == other_token and
                         other['peer'] == ['198.18.0.2', 19090], 'other UID echo failed')
            base.require(len(received) == 1 and received[0]['peer'][0] == '10.212.2.1'
                         and wire, 'other UID origin peer/token missing')
            base.require(other_after['other'] > other_before['other'] and
                         other_after['drop'] == other_before['drop'],
                         'other UID was not independently discriminated')
            print(json.dumps(dict(**blocked, other_uid=dict(token=other_token,
                             peer=received[0]['peer'], reply=other['reply'],
                             observer_delta=other_after['other'] - other_before['other'],
                             proxy_drop_delta=other_after['drop'] - other_before['drop']))),
                  flush=True)
        finally:
            try:
                client.stop(abort=True)
            finally:
                try:
                    self.receiver.stop()
                finally:
                    self.proxy.stop()
        self.settle_without_receiver()
        base.require(blocked is not None, 'UID revocation observation incomplete')
        self.restore()
        self.receiver = base.Child(self, base.ORIGIN, 'python3', '-u', '-c', base.RECEIVER)
        base.require(self.receiver.next()['kind'] == 'ready', 'receiver restart failed')
        self.monitors[-1] = self.receiver
        self.start_proxy()
        self.positive('uid-recovered')

    def execute(self):
        self.setup()
        self.uid_trial()
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
        print('PASS: bounded test-UID OUTPUT discrimination; no client policy attribution '
              'or adversarial-root containment claim.', flush=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_tcp_uid_probe.py generated-tcp-proof.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    validate_fixture(policies)
    base.require(os.geteuid() == 0, 'root required in authorized disposable VM')
    base.require(sys.flags.optimize == 0, 'run without Python optimization')
    with tempfile.TemporaryDirectory(prefix='vsr-tcp-uid-', dir='/var/cache') as folder:
        lab = UidLab(policies, Path(folder))
        try:
            lab.execute()
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
