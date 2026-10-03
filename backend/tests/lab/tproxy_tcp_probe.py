"""Standalone stdlib TCP experiment, ONLY for an authorized disposable Debian VM.

Never run on the development host or a router. Needs root, ip/nft/ss/sysctl,
/var/cache/vsr-singbox-probe and generated --tcp JSON (argv or POLICIES global).
No downloads, product enablement, or changes to the guest root network namespace.
Negative evidence is bounded; this is not a production fail-closed guarantee.
"""
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import uuid

NAMES = ('vsr-tcp-router', 'vsr-tcp-client', 'vsr-tcp-origin')
ROUTER, CLIENT, ORIGIN = NAMES
BINARY = '/var/cache/vsr-singbox-probe'
WINDOW = 1.5

# Packet reassembly is sequence-aware, including retransmission and segmentation.
# Only this lab's untagged, unfragmented IPv4 TCP frames are expected.
CAPTURE = r'''
import json, socket, struct, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((sys.argv[1], 0))
streams = {}
print(json.dumps({'kind': 'ready'}), flush=True)
while True:
    p, link = s.recvfrom(65535)
    if len(p) < 54 or p[12:14] != b'\x08\x00' or p[23] != 6:
        continue
    ihl = (p[14] & 15) * 4
    end = 14 + struct.unpack('!H', p[16:18])[0]
    t = 14 + ihl
    if ihl < 20 or len(p) < end or t + 20 > end:
        continue
    if struct.unpack('!H', p[20:22])[0] & 0x3fff:
        raise RuntimeError('unexpected IPv4 fragment')
    sport, dport, seq = struct.unpack('!HHI', p[t:t+8])
    if 19090 not in (sport, dport):
        continue
    h = (p[t+12] >> 4) * 4
    if h < 20 or t+h > end:
        continue
    flags = p[t+13]
    src, dst = socket.inet_ntoa(p[26:30]), socket.inet_ntoa(p[30:34])
    event = dict(kind='wire', src=src, dst=dst, sport=sport, dport=dport,
                 flags=flags, packet_type=link[2], seq=seq)
    print(json.dumps(event), flush=True)
    key = (src, dst, sport, dport)
    if flags & 2 and key not in streams:
        streams[key] = [seq+1, {}, bytearray()]
    data = p[t+h:end]
    if not data:
        continue
    if key not in streams:
        raise RuntimeError('capture missed TCP SYN')
    state = streams[key]
    start = seq + bool(flags & 2)
    for i, b in enumerate(data):
        pos = start+i
        if pos >= state[0]:
            state[1][pos] = b
    while state[0] in state[1]:
        state[2].append(state[1].pop(state[0]))
        state[0] += 1
        if state[2][-1] == 10:
            event.update(kind='frame', payload=bytes(state[2]).decode('ascii'))
            print(json.dumps(event), flush=True)
            state[2].clear()
'''

RECEIVER = r'''
import json, socket, threading
lock = threading.Lock()
def emit(e):
    with lock:
        print(json.dumps(e), flush=True)
def echo(s, peer):
    buf = bytearray()
    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            buf.extend(data)
            while b'\n' in buf:
                line, _, rest = buf.partition(b'\n')
                buf[:] = rest
                payload = bytes(line) + b'\n'
                emit(dict(kind='receive', payload=payload.decode('ascii'), peer=peer))
                s.sendall(payload)
    except (ConnectionError, OSError) as exc:
        emit(dict(kind='session_end', peer=peer, error=repr(exc)))
    finally:
        s.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('198.18.0.2', 19090))
s.listen(16)
emit(dict(kind='ready'))
while True:
    c, peer = s.accept()
    emit(dict(kind='accept', peer=peer))
    threading.Thread(target=echo, args=(c, peer), daemon=True).start()
'''

SENDER = r'''
import json, socket, struct, sys, time
s = socket.socket()
s.settimeout(1.5)
s.bind(('10.212.1.2', int(sys.argv[1])))
try:
    s.connect(('198.18.0.2', 19090))
    print(json.dumps(dict(kind='connected', peer=s.getpeername())), flush=True)
except OSError as exc:
    print(json.dumps(dict(kind='connect_error', error=repr(exc))), flush=True)
    s.close()
    sys.exit(0)
try:
    for line in sys.stdin:
        if line == 'ABORT\n':
            break
        sent = 0
        reply = bytearray()
        error = None
        reset = False
        deadline = time.monotonic() + 1.5
        try:
            data = line.encode('ascii')
            while sent < len(data):
                s.settimeout(max(0.001, deadline-time.monotonic()))
                sent += s.send(data[sent:])
            while not reply.endswith(b'\n'):
                s.settimeout(max(0.001, deadline-time.monotonic()))
                chunk = s.recv(4096)
                if not chunk:
                    error = 'EOF'
                    break
                reply.extend(chunk)
        except OSError as exc:
            error = repr(exc)
            reset = isinstance(exc, (ConnectionResetError, BrokenPipeError))
        print(json.dumps(dict(kind='result', sent=sent, reply=reply.decode('ascii'),
                              error=error, reset=reset)), flush=True)
finally:
    # Abort queued TCP bytes before the parent restores authorization.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    s.close()
'''

INTERCEPT = '''destroy table inet vsr_tcp_intercept
table inet vsr_tcp_intercept {
 chain prerouting { type filter hook prerouting priority -80; policy accept;
  iifname != "lan0" return
  fib daddr type local return
  ct status dnat return
  meta nfproto ipv4 meta l4proto tcp meta mark set 0x100 tproxy ip to 127.0.0.1:51272 counter accept
 }
}'''
OBSERVE = '''table inet vsr_tcp_observe {
 chain output { type filter hook output priority -10; policy accept;
  ip daddr 198.18.0.2 tcp dport 19090 counter
 }
 chain established { type filter hook prerouting priority -150; policy accept; }
 chain input_path { type filter hook input priority -10; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp dport 19090 counter comment "nonlocal_input"
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp dport 19090 meta mark 0 counter comment "unmarked_input"
 }
}'''


# Separate lab experiment: preserve the reproducibly red FORWARD-only baseline.
INTERCEPT_PROOF = '''destroy table inet vsr_tcp_intercept
table inet vsr_tcp_intercept {
 chain prerouting { type filter hook prerouting priority -80; policy accept;
  iifname != "lan0" return
  fib daddr type local return
  ct status dnat return
  meta nfproto ipv4 meta l4proto tcp meta mark set 0x100 tproxy ip to 127.0.0.1:51272 meta mark set meta mark | 0x200 counter accept
 }
}'''
INPUT_PROOF = '''table inet vsr_tcp_proof_reset {
 chain prerouting { type filter hook prerouting priority -85; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp dport 19090 meta mark set meta mark & 0xfffffdff
 }
}
table inet vsr_tcp_input_proof {
 chain input { type filter hook input priority -20; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp dport 19090 meta mark & 0x200 == 0 counter drop
 }
}'''


def collision_injector(port, priority):
    """Exact live client tuple; forge only proof, never the routing bit."""
    require(priority in (-86, -84), 'invalid collision priority')
    require(type(port) is int and 1 <= port <= 65535, 'invalid client port')
    return f'''table inet vsr_tcp_mark_collision {{
 chain prerouting {{ type filter hook prerouting priority {priority}; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} tcp dport 19090 meta mark set meta mark | 0x200 counter
 }}
}}'''


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=10, **kwargs)


def ns(name, *args, **kwargs):
    return run('ip', 'netns', 'exec', name, *args, **kwargs)


class Child:
    def __init__(self, lab, namespace, *args):
        self.events = []
        self.messages = queue.Queue()
        self.errors = []
        self.p = subprocess.Popen(['ip', 'netns', 'exec', namespace, *args],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        lab.children.append(self)
        self.threads = []
        for stream, reader in ((self.p.stdout, self.read), (self.p.stderr, self.read_errors)):
            thread = threading.Thread(target=reader, args=(stream,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def read(self, stream):
        for line in stream:
            try:
                event = json.loads(line)
            except ValueError:
                event = {'kind': 'log', 'text': line}
            self.events.append(event)
            self.messages.put(event)

    def read_errors(self, stream):
        for line in stream:
            self.errors.append(line)

    def next(self):
        try:
            return self.messages.get(timeout=5)
        except queue.Empty:
            raise AssertionError(f'child timed out: {self.errors[-10:]}') from None

    def write(self, line):
        self.p.stdin.write(line)
        self.p.stdin.flush()

    def stop(self, abort=False):
        if self.p.poll() is None:
            if abort:
                try:
                    self.write('ABORT\n')
                    self.p.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if self.p.poll() is None:
                self.p.kill()
                self.p.wait(timeout=3)
        for thread in self.threads:
            thread.join(timeout=2)
            require(not thread.is_alive(), 'child reader did not stop')
        for stream in (self.p.stdin, self.p.stdout, self.p.stderr):
            stream.close()


class Lab:
    def __init__(self, policies, folder):
        self.policies, self.folder = policies, folder
        self.children, self.created, self.monitors = [], [], []
        self.port = 26000
        self.proxy = None
        self.violations = []
        self.off = False
        self.proof_mode = policies.get('__input_proof__') is True
        self.mark_collision_mode = policies.get('__mark_collision__') is True
        require(not self.mark_collision_mode or self.proof_mode,
                'mark collision experiment requires __input_proof__ true')
        self.intercept = INTERCEPT_PROOF if self.proof_mode else INTERCEPT

    def nft(self, text):
        ns(ROUTER, 'nft', '-c', '-f', '-', input=text)
        ns(ROUTER, 'nft', '-f', '-', input=text)

    def install(self, case):
        self.nft(''.join(self.policies[case + suffix] for suffix in ('_firewall', '', '_guard')))
        ns(ROUTER, 'nft', 'insert', 'rule', 'inet', 'vs_router', 'input',
           'iifname', 'lan0', 'ip', 'saddr', '10.212.1.2', 'ip', 'daddr', '198.18.0.2',
           'meta', 'mark', '0x300' if self.proof_mode else '0x100',
           'tcp', 'dport', '19090', 'counter', 'accept',
           'comment', 'lab_tcp_input')

    def counter(self, table, chain, comment=None):
        state = json.loads(ns(ROUTER, 'nft', '-j', 'list', 'chain', 'inet', table, chain).stdout)
        return sum(e['counter']['packets'] for item in state['nftables']
                   for rule in [item.get('rule', {})]
                   if comment is None or rule.get('comment') == comment
                   for e in rule.get('expr', []) if 'counter' in e)

    def counters(self):
        return dict(input=self.counter('vs_router', 'input', 'lab_tcp_input'),
                    output=self.counter('vsr_tcp_observe', 'output'),
                    guard=0 if self.off else self.counter('vs_router_tproxy_guard', 'forward'),
                    established=self.counter('vsr_tcp_observe', 'established'),
                    local_in=self.counter('vsr_tcp_observe', 'input_path', 'nonlocal_input'),
                    unmarked_in=self.counter('vsr_tcp_observe', 'input_path', 'unmarked_input'))

    def policy_route(self, action):
        ns(ROUTER, 'ip', 'route', action, 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')

    def policy_rule(self, action):
        ns(ROUTER, 'ip', 'rule', action, 'priority', '100', 'fwmark',
           '0x100/0x100' if self.proof_mode else '0x100', 'lookup', '100')

    def start_proxy(self):
        self.proxy = Child(self, ROUTER, BINARY, 'run', '-c', str(self.folder / 'config.json'))
        for _ in range(50):
            require(self.proxy.p.poll() is None, f'proxy exited: {self.proxy.errors[-10:]}')
            listeners = ns(ROUTER, 'ss', '-H', '-ltn').stdout.splitlines()
            if any('127.0.0.1:51272' in line.split() for line in listeners):
                return
            time.sleep(0.1)
        raise AssertionError('TCP proxy listener readiness timed out')

    def setup(self):
        for name in NAMES:
            run('ip', 'netns', 'add', name)
            self.created.append(name)
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        for iface, peer, subnet in (('lan0', CLIENT, '10.212.1'), ('wan0', ORIGIN, '10.212.2')):
            # Create both ends INSIDE namespaces, never in the guest root netns.
            ns(ROUTER, 'ip', 'link', 'add', iface, 'type', 'veth', 'peer', 'name',
               'eth0', 'netns', peer)
            for name, dev, last in ((ROUTER, iface, '1'), (peer, 'eth0', '2')):
                ns(name, 'ip', 'addr', 'add', f'{subnet}.{last}/24', 'dev', dev)
                ns(name, 'ip', 'link', 'set', dev, 'up')
            ns(peer, 'ip', 'route', 'add', 'default', 'via', subnet + '.1')
        ns(ROUTER, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        ns(ORIGIN, 'ip', 'addr', 'add', '198.18.0.2/32', 'dev', 'lo')
        ns(ROUTER, 'ip', 'route', 'add', 'default', 'via', '10.212.2.2')
        for name, iface in ((CLIENT, 'eth0'), (ROUTER, 'lan0'), (ORIGIN, 'eth0')):
            child = Child(self, name, 'python3', '-u', '-c', CAPTURE, iface)
            require(child.next()['kind'] == 'ready', 'capture readiness failed')
            self.monitors.append(child)
        self.client_wire, self.ingress, self.origin_wire = self.monitors
        self.receiver = Child(self, ORIGIN, 'python3', '-u', '-c', RECEIVER)
        require(self.receiver.next()['kind'] == 'ready', 'receiver readiness failed')
        self.monitors.append(self.receiver)
        self.policy_rule('add')
        self.policy_route('add')
        self.install('allow')
        self.nft(self.intercept)
        self.nft(OBSERVE)
        if self.proof_mode:
            self.nft(INPUT_PROOF)
        (self.folder / 'config.json').write_text(self.policies['allow_singbox'])
        ns(ROUTER, BINARY, 'check', '-c', str(self.folder / 'config.json'))
        self.start_proxy()

    def settle(self):
        time.sleep(0.3)
        require(all(c.p.poll() is None for c in self.monitors), 'capture/receiver died')

    def connect(self):
        self.port += 1
        child = Child(self, CLIENT, 'python3', '-u', '-c', SENDER, str(self.port))
        return child, self.port, child.next()

    @staticmethod
    def frames(child, payload):
        return [e for e in child.events if e.get('payload') == payload]

    def exchange(self, client, case):
        payload = 'vsr-tcp-' + case + '-' + uuid.uuid4().hex + '\n'
        client.write(payload)
        result = client.next()
        require(result['kind'] == 'result', f'unexpected sender response: {result}')
        self.settle()
        return payload, result

    def positive(self, case, proxied=True, retain=False):
        before = self.counters()
        client, port, status = self.connect()
        require(status['kind'] == 'connected', f'{case}: {status}')
        require(status['peer'] == ['198.18.0.2', 19090], 'wrong destination tuple')
        payload, result = self.exchange(client, case)
        require(result['reply'] == payload and result['sent'] == len(payload), f'{case}: {result}')
        expected = '10.212.2.1' if proxied else '10.212.1.2'
        received = self.frames(self.receiver, payload)
        require(len(received) == 1 and received[0]['peer'][0] == expected, 'wrong origin peer/payload')
        if not proxied:
            require(received[0]['peer'][1] == port, 'off changed client source port')
        for capture in (self.client_wire, self.ingress, self.origin_wire):
            require(self.frames(capture, payload), 'missing positive wire payload')
        after = self.counters()
        delta = {k: after[k]-before[k] for k in before}
        require(delta['guard'] == 0, 'positive hit containment')
        require((delta['input'] > 0 and delta['output'] > 0) if proxied else
                (delta['input'] == 0 and delta['output'] == 0), 'wrong INPUT/OUTPUT path')
        print(json.dumps(dict(case=case, source_port=port, peer=received[0]['peer'], counters=delta)), flush=True)
        if retain:
            return client, port
        client.stop(abort=True)
        self.settle()

    def negative_syn(self, case):
        self.settle()
        wire_start, accept_start = len(self.origin_wire.events), len(self.receiver.events)
        client, port, status = self.connect()
        self.settle()
        require(status['kind'] == 'connect_error', f'{case}: handshake unexpectedly succeeded')
        for capture in (self.client_wire, self.ingress):
            require(any(e.get('src') == '10.212.1.2' and e.get('dst') == '198.18.0.2'
                        and e.get('sport') == port and e.get('dport') == 19090
                        and e.get('flags', 0) & 2 for e in capture.events), 'missing fresh client SYN')
        require(not any(e.get('dst') == '198.18.0.2' and e.get('dport') == 19090
                        and e.get('flags', 0) & 2 for e in self.origin_wire.events[wire_start:]),
                'origin saw SYN during denied handshake')
        require(not any(e['kind'] == 'accept' for e in self.receiver.events[accept_start:]),
                'origin accepted denied connection')
        print(json.dumps(dict(case=case, source_port=port, result=status)), flush=True)
        client.stop()

    def fault(self, case):
        client, port = self.positive(case + '-healthy', retain=True)
        self.nft('flush chain inet vsr_tcp_observe established\n'
                 'add rule inet vsr_tcp_observe established iifname "lan0" '
                 f'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                 'tcp dport 19090 ct state established counter\n')
        # Prove this exact live socket is established before introducing the fault.
        payload, result = self.exchange(client, case + '-established')
        require(result['reply'] == payload, 'established control failed')
        require(self.counter('vsr_tcp_observe', 'established') > 0, 'no established tuple evidence')
        if case in ('deny_first', 'default_deny'):
            self.install(case)
        elif case == 'sigkill':
            self.proxy.stop()
        elif case == 'interception_deleted':
            self.nft('destroy table inet vsr_tcp_intercept\n')
        elif case == 'local_route_deleted':
            self.policy_route('del')
        elif case == 'policy_rule_deleted':
            self.policy_rule('del')
        before = self.counters()
        proof_before = self.counter('vsr_tcp_input_proof', 'input') if self.proof_mode else 0
        payload, result = self.exchange(client, case + '-blocked')
        time.sleep(WINDOW)
        self.settle()
        after = self.counters()
        delta = {k: after[k]-before[k] for k in before}
        ingress = [e for e in self.frames(self.ingress, payload)
                   if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                   and e['sport'] == port and e['dport'] == 19090]
        # send() success only means queued locally; demand actual ingress evidence.
        # SIGKILL may reset the old socket before bytes can reach the wire.
        reset_exception = case == 'sigkill' and result['reset']
        require((result['sent'] == len(payload) and ingress) or reset_exception,
                f'no ingress payload proof or SIGKILL reset: {result}')
        if ingress:
            require(delta['established'] > 0, 'blocked packet was not established before preauth')
        delivered = bool(self.frames(self.origin_wire, payload) or self.frames(self.receiver, payload))
        violation = delivered or result['reply'] == payload
        if violation:
            self.violations.append(case)
        proof_delta = self.counter('vsr_tcp_input_proof', 'input') - proof_before if self.proof_mode else 0
        if case == 'interception_deleted':
            if self.proof_mode:
                require(proof_delta > 0, 'independent INPUT proof guard was not reached')
            elif delta['guard'] == 0:
                self.violations.append(case + ':guard_not_reached')
        print(json.dumps(dict(case=case, source_port=port, sender=result,
                              ingress_frames=len(ingress), counters=delta,
                              observation_seconds=WINDOW, reset_exception=reset_exception,
                              violation=violation,
                              input_proof_drop_delta=proof_delta, proof_mode=self.proof_mode,
                              origin_records=self.frames(self.receiver, payload))), flush=True)
        if case == 'interception_deleted' and violation:
            # Narrow differential experiment after preserving the red result.
            # Cached/local socket delivery still traverses INPUT: require the
            # current packet's interception mark before ordinary established accept.
            self.nft('''table inet vsr_tcp_input_candidate {
 chain input { type filter hook input priority -20; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp dport 19090 meta mark != 0x100 counter drop
 }
}''')
            candidate_before = self.counter('vsr_tcp_input_candidate', 'input')
            candidate_payload, candidate_result = self.exchange(client, case + '-input-guard-candidate')
            time.sleep(WINDOW)
            self.settle()
            candidate_delta = self.counter('vsr_tcp_input_candidate', 'input') - candidate_before
            require(self.frames(self.ingress, candidate_payload), 'candidate lacks ingress evidence')
            require(candidate_delta > 0, 'candidate INPUT guard was not reached')
            require(candidate_result['reply'] != candidate_payload and
                    not self.frames(self.origin_wire, candidate_payload) and
                    not self.frames(self.receiver, candidate_payload), 'candidate INPUT guard did not block')
            print(json.dumps(dict(case='input_guard_candidate', drop_delta=candidate_delta,
                                  sender=candidate_result, scope='lab-only, baseline remains red')), flush=True)
        # TCP queues may retransmit after allow is restored. Abort both endpoints
        # of the proxy session BEFORE restoring anything; recovery uses a fresh flow.
        client.stop(abort=True)
        self.proxy.stop()
        self.settle()
        if not delivered and (self.frames(self.origin_wire, payload) or self.frames(self.receiver, payload)):
            self.violations.append(case + ':late_before_restore')
        if case == 'local_route_deleted':
            self.policy_route('add')
        if case == 'policy_rule_deleted':
            self.policy_rule('add')
        self.nft('destroy table inet vsr_tcp_input_candidate\n')
        self.install('allow')
        self.nft(self.intercept)
        self.start_proxy()
        self.positive(case + '-recovered')

    def mark_collision(self, priority):
        require(self.mark_collision_mode and self.proof_mode, 'collision mode not enabled')
        case = 'mark_collision_' + ('before_reset' if priority == -86 else 'after_reset')
        client, port = self.positive(case + '-healthy', retain=True)
        try:
            self.nft('flush chain inet vsr_tcp_observe established\n'
                     'add rule inet vsr_tcp_observe established iifname "lan0" '
                     f'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                     'tcp dport 19090 ct state established counter\n')
            control, control_result = self.exchange(client, case + '-established')
            established = self.counter('vsr_tcp_observe', 'established')
            require(control_result['reply'] == control and established > 0,
                    'collision lacks healthy established control')
            self.nft('destroy table inet vsr_tcp_intercept\n')
            self.nft(collision_injector(port, priority))
            before = self.counters()
            proof_before = self.counter('vsr_tcp_input_proof', 'input')
            injector_before = self.counter('vsr_tcp_mark_collision', 'prerouting')
            payload, result = self.exchange(client, case + '-post-fault')
            time.sleep(WINDOW)
            self.settle()
            after = self.counters()
            delta = {k: after[k] - before[k] for k in before}
            injector_delta = self.counter('vsr_tcp_mark_collision', 'prerouting') - injector_before
            proof_delta = self.counter('vsr_tcp_input_proof', 'input') - proof_before
            # End both old endpoints while the fault and injector still apply.
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
        # Observational results, including late delivery before restore. Neither
        # injection position is assumed to bypass (or reach) the INPUT guard.
        print(json.dumps(dict(case=case, priority=priority, source_port=port,
                              token=payload, sender=result, ingress_records=ingress,
                              origin_wire_records=origin, origin_records=received,
                              delivered=bool(origin or received), echoed=result['reply'] == payload,
                              injector_delta=injector_delta, input_proof_drop_delta=proof_delta,
                              counters=delta, established_control_packets=established,
                              observation_seconds=WINDOW, scope='lab-only observational')),
              flush=True)
        require(result['sent'] == len(payload) and ingress, 'collision lacks ingress token')
        require(injector_delta > 0, 'collision injector was not reached')
        require(delta['established'] > 0, 'collision packet lacks established evidence')
        self.nft('destroy table inet vsr_tcp_mark_collision\n')
        self.nft(self.intercept)
        self.start_proxy()
        self.positive(case + '-recovered')

    def execute(self):
        self.setup()
        self.positive('allow')
        for case in ('deny_first', 'default_deny'):
            self.install(case)
            self.negative_syn(case + '-fresh')
        self.install('allow_first')
        self.positive('pass-before-block')
        self.install('allow')
        for case in ('deny_first', 'default_deny', 'sigkill', 'interception_deleted',
                     'local_route_deleted', 'policy_rule_deleted'):
            self.fault(case)
        if self.mark_collision_mode:
            for priority in (-86, -84):
                self.mark_collision(priority)
        self.proxy.stop()
        if self.proof_mode:
            self.nft('destroy table inet vsr_tcp_input_proof\ndestroy table inet vsr_tcp_proof_reset\n')
        self.nft('destroy table inet vsr_tcp_intercept\n' + self.policies['off']
                 + self.policies['off_guard'] + self.policies['allow_firewall'])
        self.policy_rule('del')
        self.policy_route('del')
        self.off = True
        # Observer is measurement only, retained for off INPUT/OUTPUT assertions.
        self.positive('off-allow', proxied=False)
        self.nft(self.policies['default_deny_firewall'])
        self.negative_syn('off-default-deny-fresh')
        require(not self.violations, f'TCP containment violations: {self.violations}')
        print('PASS: bounded TCP windows; old sessions aborted before restore; '
              'queued retransmission after restored allow is not tested as a guard leak.', flush=True)

    def cleanup(self):
        errors = []
        for child in reversed(self.children):
            try:
                child.stop()
            except Exception as exc:
                errors.append(repr(exc))
        for name in reversed(self.created):
            try:
                run('ip', 'netns', 'delete', name)
            except Exception as exc:
                errors.append(repr(exc))
        require(not errors, f'cleanup failed: {errors}')


def main():
    policies = globals().get('POLICIES')
    if not policies:
        if len(sys.argv) != 2:
            raise SystemExit('VM ONLY: tproxy_tcp_probe.py generated-tcp.json')
        policies = json.loads(Path(sys.argv[1]).read_text())
    for key in ('off', 'off_guard', 'allow_singbox'):
        require(isinstance(policies.get(key), str), f'missing generated policy: {key}')
    require(os.geteuid() == 0, 'root required in authorized disposable VM')
    require(sys.flags.optimize == 0, 'run without Python optimization')
    for case in ('allow', 'allow_first', 'deny_first', 'default_deny'):
        for suffix in ('', '_firewall', '_guard'):
            require(isinstance(policies.get(case + suffix), str), 'missing generated policy')
        require('priority -90' in policies[case], 'expected generated preauth priority -90')
        require('priority -10' in policies[case + '_guard'], 'expected generated guard priority -10')
    config = json.loads(policies['allow_singbox'])
    require(any(i.get('type') == 'tproxy' and i.get('listen') == '127.0.0.1'
                and i.get('listen_port') == 51272 and i.get('network') in (None, 'tcp')
                for i in config.get('inbounds', [])), 'expected TCP TProxy listener 51272')
    with tempfile.TemporaryDirectory(prefix='vsr-tcp-', dir='/var/cache') as folder:
        lab = Lab(policies, Path(folder))
        try:
            lab.execute()
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
