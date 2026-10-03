"""VM-only stdlib UDP UID experiment, using a generated --combined fixture.

Run only as root in an authorized disposable guest. All network changes are in
three newly created namespaces. This bounded IPv4 test makes no product claim.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid

SOURCE = Path(__file__).with_name('tproxy_tcp_probe.py')
spec = importlib.util.spec_from_file_location('vsr_safe_tcp_helpers', SOURCE)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

ROUTER, CLIENT, ORIGIN = 'vsr-udp-uid-router', 'vsr-udp-uid-client', 'vsr-udp-uid-origin'
PROXY_UID, OTHER_UID = 29090, 29091
NET_RAW = 1 << 13
WINDOW = 0.3
SCOPE = 'ip daddr 198.18.0.2 oifname "wan0" udp dport 19090'
UID_GUARD = f'''table inet vsr_udp_uid_guard {{
 chain output {{ type filter hook output priority -20; policy accept;
  meta skuid {PROXY_UID} {SCOPE} counter comment "proxy_uid"
  meta skuid {OTHER_UID} {SCOPE} counter comment "other_uid"
 }}
}}'''
UID_REVOKE = (f'insert rule inet vsr_udp_uid_guard output meta skuid {PROXY_UID} '
              f'{SCOPE} counter drop comment "proxy_uid_drop"')
INTERCEPT = '''table inet vsr_udp_uid_intercept {
 chain prerouting { type filter hook prerouting priority -80; policy accept;
  iifname != "lan0" return
  fib daddr type local return
  ct status dnat return
  meta nfproto ipv4 meta l4proto udp meta mark set 0x100 tproxy ip to 127.0.0.1:51271 counter accept
 }
}'''
OBSERVE = '''table inet vsr_udp_uid_observe {
 chain established { type filter hook prerouting priority -150; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 udp sport 25000 udp dport 19090 ct state established counter comment "established_tuple"
 }
 chain input_path { type filter hook input priority -10; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 udp dport 19090 counter comment "input_observer"
 }
}'''
CAPTURE = r'''
import json, socket, struct, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((sys.argv[1], 0))
print(json.dumps({'kind': 'ready'}), flush=True)
while True:
    p, link = s.recvfrom(65535)
    if len(p) < 42 or p[12:14] != b'\x08\x00' or p[23] != 17:
        continue
    ihl = (p[14] & 15) * 4
    end = 14 + struct.unpack('!H', p[16:18])[0]
    off = 14 + ihl
    if ihl < 20 or len(p) < end or off + 8 > end:
        continue
    if struct.unpack('!H', p[20:22])[0] & 0x3fff:
        raise RuntimeError('unexpected IPv4 fragment')
    sport, dport = struct.unpack('!HH', p[off:off+4])
    if 19090 not in (sport, dport):
        continue
    payload = p[off+8:end].decode('ascii')
    print(json.dumps({'kind': 'wire', 'payload': payload,
                      'src': socket.inet_ntoa(p[26:30]),
                      'dst': socket.inet_ntoa(p[30:34]),
                      'sport': sport, 'dport': dport, 'packet_type': link[2]}), flush=True)
'''
RECEIVER = r'''
import json, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('198.18.0.2', 19090))
print(json.dumps({'kind': 'ready'}), flush=True)
while True:
    data, peer = s.recvfrom(4096)
    print(json.dumps({'kind': 'receive', 'payload': data.decode('ascii'), 'peer': peer}), flush=True)
    s.sendto(data, peer)
'''
SENDER = r'''
import json, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.212.1.2', int(sys.argv[1])))
print(json.dumps({'kind': 'ready', 'port': s.getsockname()[1]}), flush=True)
for line in sys.stdin:
    if line == 'STOP\n':
        break
    token = line.strip().encode('ascii')
    sent = s.sendto(token, ('198.18.0.2', 19090))
    reply, peer, stale = None, None, []
    deadline = time.monotonic() + 0.7
    while time.monotonic() < deadline:
        s.settimeout(max(0.001, deadline-time.monotonic()))
        try:
            data, address = s.recvfrom(4096)
        except socket.timeout:
            break
        if data == token:
            reply, peer = data.decode('ascii'), list(address)
            break
        stale.append(data.decode('ascii'))
    print(json.dumps({'kind': 'result', 'sent': sent, 'reply': reply,
                      'peer': peer, 'stale': stale, 'port': s.getsockname()[1]}), flush=True)
'''
OTHER_CLIENT = r'''
import json, socket, sys
token = sys.argv[1].encode('ascii')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.212.2.1', 0))
s.settimeout(1.5)
sent = s.sendto(token, ('198.18.0.2', 19090))
data, peer = s.recvfrom(4096)
print(json.dumps({'sent': sent, 'reply': data.decode('ascii'), 'peer': list(peer)}))
'''


def validate_fixture(policies):
    base.require(policies.get('__combined__') == 'udp', 'requires --combined UDP opt-in fixture')
    for case in ('allow', 'off', 'default_deny'):
        for key in (case, case + '_firewall', case + '_guard', case + '_singbox'):
            base.require(isinstance(policies.get(key), str), f'missing generated {key}')
    config = json.loads(policies['allow_singbox'])
    base.require(config == {
        'inbounds': [
            {'type': 'tproxy', 'tag': 'tproxy-udp', 'listen': '127.0.0.1',
             'listen_port': 51271, 'network': 'udp'},
            {'type': 'tproxy', 'tag': 'tproxy-tcp', 'listen': '127.0.0.1',
             'listen_port': 51272, 'network': 'tcp'}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        'route': {'rules': [], 'final': 'direct', 'auto_detect_interface': True},
    }, 'requires secret-free direct-only generated sing-box JSON')
    for case in ('allow', 'off', 'default_deny'):
        base.require(json.loads(policies[case + '_singbox']) == config,
                     f'{case} sing-box JSON differs')
    base.require('hook prerouting priority -90' in policies['allow'],
                 'missing generated preauthorization')
    base.require('hook forward priority -10' in policies['allow_guard'],
                 'missing generated containment')
    base.require('table inet vs_router' in policies['allow_firewall'],
                 'missing generated ordinary firewall')


class Lab:
    def __init__(self, policies, folder):
        self.policies, self.folder = policies, folder
        self.children, self.created, self.monitors = [], [], []
        self.proxy = None
        self.blocked_token = None

    def nft(self, rules):
        base.ns(ROUTER, 'nft', '-c', '-f', '-', input=rules)
        base.ns(ROUTER, 'nft', '-f', '-', input=rules)

    def count(self, table, chain, comment, *, absent_zero=False):
        state = json.loads(base.ns(ROUTER, 'nft', '-j', 'list', 'chain', 'inet', table, chain).stdout)
        matches = [expr['counter']['packets'] for item in state['nftables']
                   for rule in [item.get('rule', {})] if rule.get('comment') == comment
                   for expr in rule.get('expr', []) if 'counter' in expr]
        if absent_zero and not matches:
            return 0
        base.require(len(matches) == 1, f'missing/duplicate counter {table}:{comment}')
        return matches[0]

    def counts(self):
        return dict(established=self.count('vsr_udp_uid_observe', 'established', 'established_tuple'),
                    input=self.count('vsr_udp_uid_observe', 'input_path', 'input_observer'),
                    proxy=self.count('vsr_udp_uid_guard', 'output', 'proxy_uid'),
                    other=self.count('vsr_udp_uid_guard', 'output', 'other_uid'),
                    drop=self.count('vsr_udp_uid_guard', 'output', 'proxy_uid_drop',
                                    absent_zero=True))

    def child(self, namespace, code, *args):
        child = base.Child(self, namespace, 'python3', '-u', '-c', code, *args)
        base.require(child.next()['kind'] == 'ready', 'child readiness failed')
        self.monitors.append(child)
        return child

    def setup(self):
        for name in (ROUTER, CLIENT, ORIGIN):
            base.run('ip', 'netns', 'add', name)
            self.created.append(name)
            base.ns(name, 'ip', 'link', 'set', 'lo', 'up')
        for iface, peer, subnet in (('lan0', CLIENT, '10.212.1'), ('wan0', ORIGIN, '10.212.2')):
            base.ns(ROUTER, 'ip', 'link', 'add', iface, 'type', 'veth', 'peer', 'name',
                    'eth0', 'netns', peer)
            for name, dev, last in ((ROUTER, iface, '1'), (peer, 'eth0', '2')):
                base.ns(name, 'ip', 'addr', 'add', f'{subnet}.{last}/24', 'dev', dev)
                base.ns(name, 'ip', 'link', 'set', dev, 'up')
            base.ns(peer, 'ip', 'route', 'add', 'default', 'via', subnet + '.1')
        base.ns(ROUTER, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        base.ns(ORIGIN, 'ip', 'addr', 'add', '198.18.0.2/32', 'dev', 'lo')
        base.ns(ROUTER, 'ip', 'route', 'add', 'default', 'via', '10.212.2.2')
        self.ingress = self.child(ROUTER, CAPTURE, 'lan0')
        self.origin_wire = self.child(ORIGIN, CAPTURE, 'eth0')
        self.receiver = self.child(ORIGIN, RECEIVER)
        base.ns(ROUTER, 'ip', 'rule', 'add', 'priority', '100', 'fwmark', '0x100', 'lookup', '100')
        base.ns(ROUTER, 'ip', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
        self.nft('\n'.join((self.policies['allow_firewall'], self.policies['allow'],
                            self.policies['allow_guard'], INTERCEPT, OBSERVE, UID_GUARD)))
        base.ns(ROUTER, 'nft', 'insert', 'rule', 'inet', 'vs_router', 'input',
                'iifname', 'lan0', 'ip', 'saddr', '10.212.1.2', 'ip', 'daddr', '198.18.0.2',
                'meta', 'mark', '0x100', 'udp', 'dport', '19090', 'counter', 'accept',
                'comment', 'lab_udp_input')
        config = self.folder / 'config.json'
        config.write_text(self.policies['allow_singbox'])
        os.chown(self.folder, PROXY_UID, PROXY_UID)
        os.chmod(self.folder, 0o700)
        os.chown(config, PROXY_UID, PROXY_UID)
        os.chmod(config, 0o600)
        base.ns(ROUTER, base.BINARY, 'check', '-c', str(config))
        self.start_proxy()

    def start_proxy(self):
        self.proxy = base.Child(self, ROUTER, 'setpriv', '--reuid=29090', '--regid=29090',
                                '--clear-groups', '--bounding-set=-all,+net_raw',
                                '--inh-caps=+net_raw', '--ambient-caps=+net_raw',
                                base.BINARY, 'run', '-c', str(self.folder / 'config.json'))
        for _ in range(50):
            base.require(self.proxy.p.poll() is None, f'UID proxy exited: {self.proxy.errors[-10:]}')
            fields = dict(line.split(':', 1) for line in
                          Path(f'/proc/{self.proxy.p.pid}/status').read_text().splitlines() if ':' in line)
            uids = [int(value) for value in fields['Uid'].split()]
            effective, ambient = int(fields['CapEff'].strip(), 16), int(fields['CapAmb'].strip(), 16)
            if uids == [PROXY_UID] * 4 and effective == NET_RAW and ambient == NET_RAW:
                listeners = base.ns(ROUTER, 'ss', '-H', '-lunp').stdout.splitlines()
                if any('127.0.0.1:51271' in line and f'pid={self.proxy.p.pid},' in line
                       for line in listeners):
                    return
            time.sleep(0.1)
        raise AssertionError('UID/capability-owned UDP listener readiness failed')

    def sender(self, port):
        return self.child(CLIENT, SENDER, str(port))

    def settle(self):
        time.sleep(WINDOW)
        base.require(all(child.p.poll() is None for child in self.monitors),
                     'capture/receiver/sender exited')

    @staticmethod
    def records(child, token):
        return [event for event in child.events if event.get('payload') == token]

    def exchange(self, sender, case, *, allowed, proxied=True, fixed_port=None):
        token = 'vsr-udp-uid-' + case + '-' + uuid.uuid4().hex
        before = self.counts()
        sender.write(token + '\n')
        result = sender.next()
        base.require(result['kind'] == 'result' and result['sent'] == len(token),
                     f'{case}: missing sender result')
        self.settle()
        after = self.counts()
        delta = {key: after[key] - before[key] for key in before}
        port = result['port']
        if fixed_port is not None:
            base.require(port == fixed_port, 'client socket tuple changed')
        ingress = [e for e in self.records(self.ingress, token)
                   if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                   and e['sport'] == port and e['dport'] == 19090]
        origin_wire = self.records(self.origin_wire, token)
        received = self.records(self.receiver, token)
        base.require(ingress, f'{case}: no exact client ingress evidence')
        if allowed:
            expected = '10.212.2.1' if proxied else '10.212.1.2'
            base.require(result['reply'] == token and result['peer'] == ['198.18.0.2', 19090]
                         and len(received) == 1 and received[0]['peer'][0] == expected
                         and origin_wire, f'{case}: positive path unproved')
            base.require((delta['proxy'] > 0 and delta['input'] > 0) if proxied else
                         (delta['proxy'] == 0 and delta['input'] == 0),
                         f'{case}: wrong output/input path')
            if not proxied:
                base.require(received[0]['peer'][1] == port, 'off changed client source port')
        else:
            base.require(result['reply'] is None and not received and not origin_wire,
                         f'{case}: blocked token delivered')
        report = dict(case=case, token=token, sender=result, ingress=len(ingress),
                      origin_wire=len(origin_wire), origin_echo=len(received), counters=delta,
                      observation_seconds=0.7 + WINDOW)
        print(json.dumps(report), flush=True)
        return report

    def trial(self):
        old = self.sender(25000)
        healthy = self.exchange(old, 'healthy', allowed=True, fixed_port=25000)
        base.require(healthy['counters']['proxy'] > 0, 'healthy proxy owner counter absent')
        established = self.exchange(old, 'established-control', allowed=True, fixed_port=25000)
        base.require(established['counters']['established'] > 0,
                     'exact original tuple lacks established control')
        self.nft(UID_REVOKE + '\n')
        blocked = self.exchange(old, 'revoked', allowed=False, fixed_port=25000)
        self.blocked_token = blocked['token']
        base.require(blocked['counters']['established'] > 0 and
                     blocked['counters']['input'] > 0 and blocked['counters']['drop'] > 0,
                     'revoked packet lacks established, INPUT or UID drop evidence')
        base.require(self.proxy.p.poll() is None, 'proxy stopped during revocation')
        other_token = 'vsr-udp-uid-other-' + uuid.uuid4().hex
        before = self.counts()
        other = json.loads(base.ns(ROUTER, 'setpriv', '--reuid=29091', '--regid=29091',
                                  '--clear-groups', 'python3', '-c', OTHER_CLIENT, other_token).stdout)
        self.settle()
        after = self.counts()
        received = self.records(self.receiver, other_token)
        wire = self.records(self.origin_wire, other_token)
        base.require(other['sent'] == len(other_token) and other['reply'] == other_token
                     and other['peer'] == ['198.18.0.2', 19090] and len(received) == 1
                     and received[0]['peer'][0] == '10.212.2.1' and wire
                     and after['other'] > before['other'] and after['drop'] == before['drop'],
                     'other UID same-destination control failed')
        print(json.dumps(dict(case='other-uid', token=other_token, result=other,
                              origin_wire=len(wire), origin_echo=len(received),
                              other_delta=after['other']-before['other'],
                              proxy_drop_delta=after['drop']-before['drop'])), flush=True)
        old.stop(abort=True)
        self.monitors.remove(old)
        self.proxy.stop()
        self.nft('flush chain inet vsr_udp_uid_guard output\n'
                 f'add rule inet vsr_udp_uid_guard output meta skuid {PROXY_UID} {SCOPE} counter comment "proxy_uid"\n'
                 f'add rule inet vsr_udp_uid_guard output meta skuid {OTHER_UID} {SCOPE} counter comment "other_uid"\n')
        self.start_proxy()
        fresh = self.sender(25001)
        recovered = self.exchange(fresh, 'recovered', allowed=True, fixed_port=25001)
        base.require(recovered['counters']['proxy'] > 0, 'recovered proxy owner absent')
        fresh.stop(abort=True)
        self.monitors.remove(fresh)
        base.require(not self.records(self.origin_wire, self.blocked_token)
                     and not self.records(self.receiver, self.blocked_token),
                     'blocked token arrived after recovery')
        self.proxy.stop()
        self.nft('destroy table inet vsr_udp_uid_intercept\n'
                 'destroy table inet vsr_udp_uid_guard\n'
                 'destroy table inet vsr_udp_uid_observe\n'
                 + self.policies['off'] + self.policies['off_guard'] +
                 self.policies['allow_firewall'])
        base.ns(ROUTER, 'ip', 'rule', 'del', 'priority', '100')
        base.ns(ROUTER, 'ip', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
        off = self.sender(25002)
        self.off_exchange(off, 'off-ordinary-allow', allowed=True)
        off.stop(abort=True)
        self.monitors.remove(off)
        self.nft(self.policies['default_deny_firewall'])
        denied = self.sender(25003)
        self.off_exchange(denied, 'off-fresh-default-deny', allowed=False)
        denied.stop(abort=True)
        self.monitors.remove(denied)
        base.require(not self.records(self.origin_wire, self.blocked_token)
                     and not self.records(self.receiver, self.blocked_token),
                     'blocked token arrived during off controls')

    def off_exchange(self, sender, case, *, allowed):
        token = 'vsr-udp-uid-' + case + '-' + uuid.uuid4().hex
        sender.write(token + '\n')
        result = sender.next()
        self.settle()
        ingress = [e for e in self.records(self.ingress, token)
                   if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                   and e['sport'] == result['port'] and e['dport'] == 19090]
        wire, echo = self.records(self.origin_wire, token), self.records(self.receiver, token)
        base.require(result['sent'] == len(token) and ingress, f'{case}: missing fresh ingress')
        if allowed:
            base.require(result['reply'] == token and result['peer'] == ['198.18.0.2', 19090]
                         and len(echo) == 1 and echo[0]['peer'] == ['10.212.1.2', result['port']]
                         and wire, 'ordinary forwarding control failed')
        else:
            base.require(result['reply'] is None and not wire and not echo,
                         'fresh default deny failed')
        print(json.dumps(dict(case=case, token=token, sender=result,
                              ingress=len(ingress), origin_wire=len(wire), origin_echo=len(echo))),
              flush=True)

    def cleanup(self):
        errors = []
        for child in reversed(self.children):
            try:
                child.stop()
            except Exception as exc:
                errors.append(repr(exc))
        for name in reversed(self.created):
            try:
                base.run('ip', 'netns', 'delete', name)
            except Exception as exc:
                errors.append(repr(exc))
        base.require(not errors, f'cleanup failed: {errors}')


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_udp_uid_probe.py generated-combined.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    validate_fixture(policies)
    base.require(os.geteuid() == 0, 'root required in authorized disposable VM')
    base.require(sys.flags.optimize == 0, 'run without Python optimization')
    with tempfile.TemporaryDirectory(prefix='vsr-udp-uid-', dir='/var/cache') as folder:
        lab = Lab(policies, Path(folder))
        try:
            lab.setup()
            lab.trial()
            print('PASS: bounded UDP socket-UID observation in disposable namespaces', flush=True)
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
