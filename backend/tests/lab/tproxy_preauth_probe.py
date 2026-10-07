"""Manual VM-only UDP packet probe; not part of pytest or product apply.

Run via QGA on an explicitly authorized disposable Debian VM with POLICIES
injected as a dict of generated nft texts. All networking lives in three new
network namespaces; no host/guest production rules or routes are changed.
"""
import json
from pathlib import Path
import select
import subprocess
import sys
import threading
import time
import tempfile

POLICIES: dict[str, str] = globals().get("POLICIES", {})
if not POLICIES and len(sys.argv) == 2:
    POLICIES = json.loads(Path(sys.argv[1]).read_text())
if not POLICIES:
    raise SystemExit("Inject generated POLICIES via the disposable-VM probe driver")

NAMES = ("vsr-pa-router", "vsr-pa-client", "vsr-pa-origin")
processes = []
created = []
probe_number = 0
forbidden_tokens = set()


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=15, **kwargs)


def ns(name, *args, **kwargs):
    return run("ip", "netns", "exec", name, *args, **kwargs)


CAPTURE = r'''
import json, re, select, socket, struct, sys
iface, receive = sys.argv[1], sys.argv[2] == 'yes'
wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
wire.bind((iface, 0))
sockets = [wire]
if receive:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((sys.argv[3], 19090))
    sockets.append(udp)
print('READY', flush=True)
while True:
    for s in select.select(sockets, [], [], 1)[0]:
        if s is wire:
            data, link = s.recvfrom(65535)
            # This probe uses plain Ethernet/IPv4 UDP, no VLANs or fragments.
            if len(data) < 42 or data[12:14] != b'\x08\x00' or data[23] != 17:
                continue
            offset = 14 + (data[14] & 15) * 4
            if len(data) < offset + 8:
                continue
            sport, dport = struct.unpack('!HH', data[offset:offset + 4])
            tokens = re.findall(rb'vsr-pa-[a-z0-9-]+', data)
            for token in tokens:
                print(json.dumps({'kind': 'wire', 'token': token.decode(), 'packet_type': link[2],
                                  'src': socket.inet_ntoa(data[26:30]),
                                  'dst': socket.inet_ntoa(data[30:34]),
                                  'sport': sport, 'dport': dport}), flush=True)
        else:
            data, addr = s.recvfrom(4096)
            print(json.dumps({'kind': 'receive', 'token': data.decode(), 'peer': list(addr)}), flush=True)
            s.sendto(data, addr)
'''


def monitor(namespace, iface, receive, listen_address):
    process = subprocess.Popen(["ip", "netns", "exec", namespace, "python3", "-u", "-c",
                                CAPTURE, iface, "yes" if receive else "no", listen_address],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    processes.append(process)
    assert process.stdout is not None
    assert select.select([process.stdout], [], [], 5)[0], "capture readiness timed out"
    assert process.stdout.readline().strip() == "READY", "capture readiness failed"
    events = []

    def read():
        assert process.stdout is not None
        for line in process.stdout:
            events.append(json.loads(line))

    threading.Thread(target=read, daemon=True).start()
    return events


SENDER = r'''
import json, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.7)
s.bind(('0.0.0.0', int(sys.argv[4])))
payload = sys.argv[1].encode()
sent = s.sendto(payload, (sys.argv[2], int(sys.argv[3])))
try:
    data, peer = s.recvfrom(4096)
    reply = data.decode()
except socket.timeout:
    reply, peer = None, None
print(json.dumps({'sent_bytes': sent, 'reply': reply, 'peer': peer,
                  'source_port': s.getsockname()[1]}))
'''


def probe(case, allowed, sender_ns, destination, port, sender_events, receiver_events,
          local_input=False, translated_destination=None, proxied=False, persistent_sender=None):
    global probe_number
    probe_number += 1
    token = "vsr-pa-" + case.replace("_", "-")
    if persistent_sender is None:
        sender = json.loads(ns(sender_ns, "python3", "-c", SENDER, token, destination,
                               str(port), str(24000 + probe_number)).stdout)
    else:
        sender = persistent_sender(token)
    time.sleep(0.2)
    assert all(p.poll() is None for p in processes), "capture/receiver exited during probe"
    source_wire = sum(e["token"] == token and e["kind"] == "wire" for e in sender_events)
    target_wire = sum(e["token"] == token and e["kind"] == "wire" for e in receiver_events)
    received = sum(e["token"] == token and e["kind"] == "receive" for e in receiver_events)
    print(json.dumps(dict(case=case, source_wire=source_wire, target_wire=target_wire,
                         received=received, **sender)), flush=True)
    if (sender["reply"] == token) != allowed:
        print(ns(NAMES[0], "nft", "list", "ruleset").stdout, flush=True)
    assert sender["sent_bytes"] == len(token) and source_wire > 0
    if allowed:
        assert sender["reply"] == token and received == 1 and target_wire > 0
        assert sender['peer'] == [destination, port], 'reply did not preserve original destination tuple'
        expected_src = '10.212.2.1' if proxied else ('10.212.1.2' if sender_ns == NAMES[1] else '10.212.2.2')
        assert any(e['kind'] == 'wire' and e['token'] == token and
                   e['src'] == expected_src and (proxied or e['sport'] == sender['source_port']) and
                   e['dst'] == (translated_destination or destination) and e['dport'] == 19090
                   for e in receiver_events), 'translated receiver tuple missing'
    else:
        forbidden_tokens.add(token)
        assert sender["reply"] is None and received == 0
        # INPUT drop occurs after ingress AF_PACKET; local wire is still visible.
        assert target_wire > 0 if local_input else target_wire == 0


def apply_rules(rules):
    ns(NAMES[0], "nft", "-c", "-f", "-", input=rules)
    ns(NAMES[0], "nft", "-f", "-", input=rules)


def combined_probe(ingress, origin):
    """VM-only lab interception scaffolding; not a shipped generator or apply path."""
    binary = '/var/cache/vsr-singbox-probe'
    interception = '''destroy table inet vsr_pa_intercept
table inet vsr_pa_intercept {
    chain prerouting { type filter hook prerouting priority -80; policy accept;
        iifname != "lan0" return
        fib daddr type local return
        ct status dnat return
        meta nfproto ipv4 meta l4proto udp meta mark set 0x100 tproxy ip to 127.0.0.1:51271 counter accept
    }
}'''
    # Lab-only INPUT exception. A product needs provenance/mark ownership checks.
    def install(case):
        apply_rules(POLICIES[case + '_firewall'] + POLICIES[case] + POLICIES[case + '_guard'])
        ns(NAMES[0], 'nft', 'insert', 'rule', 'inet', 'vs_router', 'input',
           'iifname', 'lan0', 'ip', 'saddr', '10.212.1.2', 'ip', 'daddr', '198.18.0.2',
           'meta', 'mark', '0x100', 'meta', 'l4proto', 'udp',
           'udp', 'dport', '19090', 'counter', 'accept', 'comment', 'lab_tproxy_input')

    ns(NAMES[0], 'ip', 'route', 'add', 'default', 'via', '10.212.2.2')
    ns(NAMES[0], 'ip', 'rule', 'add', 'priority', '100', 'fwmark', '0x100', 'lookup', '100')
    ns(NAMES[0], 'ip', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
    install('allow')
    apply_rules(interception)
    apply_rules('''table inet vsr_pa_observe {
        chain output { type filter hook output priority -10; policy accept;
            ip daddr 198.18.0.2 udp dport 19090 counter
        }
        chain established { type filter hook prerouting priority -150; policy accept;
            iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 udp sport 25000 udp dport 19090 ct state established counter
        }
    }''')
    with tempfile.TemporaryDirectory(prefix='vsr-singbox-', dir='/var/cache') as folder:
        config = Path(folder) / 'config.json'
        config.write_text(POLICIES['allow_singbox'])
        ns(NAMES[0], binary, 'check', '-c', str(config))

        def start():
            log = open(Path(folder) / 'singbox.log', 'w+')
            process = subprocess.Popen(['ip', 'netns', 'exec', NAMES[0], binary, 'run', '-c', str(config)],
                                       stdout=log, stderr=log)
            processes.append(process)
            for attempt in range(50):
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read())
                if '127.0.0.1:51271' in ns(NAMES[0], 'ss', '-H', '-lun').stdout:
                    log.close()
                    return process
                time.sleep(0.1)
            raise AssertionError('sing-box UDP listener readiness timed out')

        def counter(table, chain):
            state = json.loads(ns(NAMES[0], 'nft', '-j', 'list', 'chain', 'inet', table, chain).stdout)
            return sum(expr['counter']['packets'] for item in state['nftables']
                       for expr in item.get('rule', {}).get('expr', []) if 'counter' in expr)

        persistent_code = r'''
import json, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.212.1.2', 25000))
print('READY', flush=True)
for line in sys.stdin:
    payload = line.strip().encode()
    sent = s.sendto(payload, ('198.18.0.2', 19090))
    reply, peer = None, None
    deadline = time.monotonic() + 0.7
    while time.monotonic() < deadline:
        s.settimeout(deadline - time.monotonic())
        try:
            data, address = s.recvfrom(4096)
        except socket.timeout:
            break
        if data == payload:
            reply, peer = data.decode(), address
            break
    print(json.dumps({'sent_bytes': sent, 'reply': reply, 'peer': peer,
                      'source_port': s.getsockname()[1]}), flush=True)
'''
        persistent = subprocess.Popen(['ip', 'netns', 'exec', NAMES[1], 'python3', '-u', '-c', persistent_code],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(persistent)
        persistent_input, persistent_output = persistent.stdin, persistent.stdout
        assert persistent_input is not None and persistent_output is not None
        assert select.select([persistent_output], [], [], 5)[0]
        assert persistent_output.readline().strip() == 'READY'

        def send_persistent(token):
            persistent_input.write(token + '\n')
            persistent_input.flush()
            assert select.select([persistent_output], [], [], 5)[0], 'persistent sender timed out'
            response = json.loads(persistent_output.readline())
            assert response['source_port'] == 25000
            return response

        persistent_warmed = False

        def request(case, allowed, proxied=False, guard_expected=False):
            nonlocal persistent_warmed
            before = counter('vs_router_tproxy_guard', 'forward') if guard_expected else 0
            before_output = counter('vsr_pa_observe', 'output')
            probe(case, allowed, NAMES[1], '198.18.0.2', 19090, ingress, origin, proxied=proxied)
            # Ordinary explicit-off firewall intentionally accepts established
            # connections; its default-deny control therefore uses a fresh tuple.
            if case != 'combined_off_default_deny':
                established_before = counter('vsr_pa_observe', 'established')
                probe(case + '_persistent', allowed, NAMES[1], '198.18.0.2', 19090,
                      ingress, origin, proxied=proxied, persistent_sender=send_persistent)
                established_delta = counter('vsr_pa_observe', 'established') - established_before
                if persistent_warmed:
                    assert established_delta > 0, 'reused UDP tuple was not established before preauth'
                persistent_warmed = persistent_warmed or allowed
                print(json.dumps({'case': case, 'persistent_established_delta': established_delta}), flush=True)
            output_delta = counter('vsr_pa_observe', 'output') - before_output
            assert output_delta > 0 if proxied else output_delta == 0
            print(json.dumps({'case': case, 'proxy_output_delta': output_delta}), flush=True)
            if guard_expected:
                delta = counter('vs_router_tproxy_guard', 'forward') - before
                assert delta > 0, 'failure packet did not reach independent forwarding guard'
                print(json.dumps({'case': case, 'guard_drop_delta': delta}), flush=True)
            if proxied:
                assert counter('vsr_pa_intercept', 'prerouting') > 0
                assert counter('vs_router_tproxy_guard', 'forward') == 0

        process = start()
        request('combined_allow', True, True)
        for case in ('deny_first', 'default_deny'):
            install(case)
            request('combined_' + case, False)
        install('allow')
        request('combined_allow_control', True, True)
        process.kill()
        process.wait(timeout=5)
        processes.remove(process)
        request('combined_crash', False)
        process = start()
        install('allow')
        request('combined_recovered', True, True)
        apply_rules('destroy table inet vsr_pa_intercept\n')
        request('combined_interception_lost', False, guard_expected=True)
        apply_rules(interception)
        install('allow')
        request('combined_interception_restored', True, True)
        ns(NAMES[0], 'ip', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
        # A successful TProxy socket assignment can die before FORWARD if its
        # local policy route vanishes. Do not attribute this to guard without a counter.
        request('combined_policy_route_lost', False)
        ns(NAMES[0], 'ip', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
        install('allow')
        request('combined_route_restored', True, True)
        ns(NAMES[0], 'ip', 'rule', 'del', 'priority', '100')
        request('combined_policy_rule_lost', False)
        ns(NAMES[0], 'ip', 'rule', 'add', 'priority', '100', 'fwmark', '0x100', 'lookup', '100')
        install('allow')
        request('combined_rule_restored', True, True)
        apply_rules('destroy table inet vsr_pa_intercept\n' + POLICIES['off'] + POLICIES['off_guard']
                    + POLICIES['allow_firewall'])
        ns(NAMES[0], 'ip', 'rule', 'del', 'priority', '100')
        ns(NAMES[0], 'ip', 'route', 'flush', 'table', '100')
        process.kill()
        process.wait(timeout=5)
        processes.remove(process)
        request('combined_explicit_off', True)
        apply_rules(POLICIES['default_deny_firewall'])
        request('combined_off_default_deny', False)
        assert not any(e['token'] in forbidden_tokens for e in origin), 'delayed blocked token reached origin'
        assert persistent.poll() is None, 'persistent UDP socket owner exited during experiment'
        print('PASS: same UDP socket/source port retained; no blocked token appeared during later controls')
    print('PASS: combined UDP preauth/TProxy/containment, crash, interception/route loss, explicit off')


# A TProxy capture that sets the routing packet mark but NOT the conntrack proof,
# simulating a capture that omits the ct mark (or a stale/forged packet mark).
# The reset chain leaves the conntrack bit clear, so the INPUT guard must drop
# the intercepted packet: the packet mark alone must never authorize INPUT.
CT_FORGE_UDP = '''table inet vsr_pa_ct_forge {{
 chain prerouting {{ type filter hook prerouting priority -80; policy accept;
  iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 udp sport {port} udp dport 19090 meta mark set 0x100 tproxy ip to 127.0.0.1:51271 counter
 }}
}}'''


def interception_ct_probe(ingress, origin):
    """Generated TProxy capture + conntrack-mark INPUT guard, over UDP.

    Lab-only scaffolding in three network namespaces. The capture/reset/guard text
    is the byte-for-byte product generator output in
    ``POLICIES['allow_interception']``; only the lab INPUT accept and the forge
    injector are lab rules. Proves (a) allowed flow via proxy, (b) denied flow
    dropped, (c) INPUT authorization by conntrack mark (a TProxy rule that sets
    only the routing packet mark is dropped), (d) explicit off restores ordinary
    routing.
    """
    binary = '/var/cache/vsr-singbox-probe'
    interception = POLICIES['allow_interception']

    def install(case):
        apply_rules(POLICIES[case + '_firewall'] + POLICIES[case] + POLICIES[case + '_guard'])
        ns(NAMES[0], 'nft', 'insert', 'rule', 'inet', 'vs_router', 'input',
           'iifname', 'lan0', 'ip', 'saddr', '10.212.1.2', 'ip', 'daddr', '198.18.0.2',
           'meta', 'mark', '0x100', 'meta', 'l4proto', 'udp',
           'udp', 'dport', '19090', 'counter', 'accept', 'comment', 'lab_tproxy_input')

    ns(NAMES[0], 'ip', 'route', 'add', 'default', 'via', '10.212.2.2')
    ns(NAMES[0], 'ip', 'rule', 'add', 'priority', '100', 'fwmark', '0x100', 'lookup', '100')
    ns(NAMES[0], 'ip', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
    install('allow')
    apply_rules(interception)
    apply_rules('''table inet vsr_pa_observe {
        chain output { type filter hook output priority -10; policy accept;
            ip daddr 198.18.0.2 udp dport 19090 counter
        }
        chain established { type filter hook prerouting priority -150; policy accept;
            iifname "lan0" ip saddr 10.212.1.2 ip daddr 198.18.0.2 udp sport 25000 udp dport 19090 ct state established counter
        }
    }''')
    with tempfile.TemporaryDirectory(prefix='vsr-singbox-', dir='/var/cache') as folder:
        config = Path(folder) / 'config.json'
        config.write_text(POLICIES['allow_singbox'])
        ns(NAMES[0], binary, 'check', '-c', str(config))

        def start():
            log = open(Path(folder) / 'singbox.log', 'w+')
            process = subprocess.Popen(['ip', 'netns', 'exec', NAMES[0], binary, 'run', '-c', str(config)],
                                       stdout=log, stderr=log)
            processes.append(process)
            for _ in range(50):
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read())
                if '127.0.0.1:51271' in ns(NAMES[0], 'ss', '-H', '-lun').stdout:
                    log.close()
                    return process
                time.sleep(0.1)
            raise AssertionError('sing-box UDP listener readiness timed out')

        def counter(table, chain):
            state = json.loads(ns(NAMES[0], 'nft', '-j', 'list', 'chain', 'inet', table, chain).stdout)
            total = 0
            for item in state['nftables']:
                for expr in item.get('rule', {}).get('expr', []):
                    if 'counter' in expr:
                        total += expr['counter']['packets']
            return total

        persistent_code = r'''
import json, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.212.1.2', 25000))
print('READY', flush=True)
for line in sys.stdin:
    payload = line.strip().encode()
    sent = s.sendto(payload, ('198.18.0.2', 19090))
    reply, peer = None, None
    deadline = time.monotonic() + 0.7
    while time.monotonic() < deadline:
        s.settimeout(deadline - time.monotonic())
        try:
            data, address = s.recvfrom(4096)
        except socket.timeout:
            break
        if data == payload:
            reply, peer = data.decode(), address
            break
    print(json.dumps({'sent_bytes': sent, 'reply': reply, 'peer': peer,
                      'source_port': s.getsockname()[1]}), flush=True)
'''
        persistent = subprocess.Popen(['ip', 'netns', 'exec', NAMES[1], 'python3', '-u', '-c', persistent_code],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(persistent)
        persistent_input, persistent_output = persistent.stdin, persistent.stdout
        assert persistent_input is not None and persistent_output is not None
        assert select.select([persistent_output], [], [], 5)[0]
        assert persistent_output.readline().strip() == 'READY'

        def send_persistent(token):
            persistent_input.write(token + '\n')
            persistent_input.flush()
            assert select.select([persistent_output], [], [], 5)[0], 'persistent sender timed out'
            response = json.loads(persistent_output.readline())
            assert response['source_port'] == 25000
            return response

        def request(case, allowed, proxied=False):
            before_output = counter('vsr_pa_observe', 'output')
            probe(case, allowed, NAMES[1], '198.18.0.2', 19090, ingress, origin, proxied=proxied)
            output_delta = counter('vsr_pa_observe', 'output') - before_output
            assert output_delta > 0 if proxied else output_delta == 0
            print(json.dumps({'case': case, 'proxy_output_delta': output_delta}), flush=True)
            if proxied:
                assert counter('vs_router_tproxy_interception', 'prerouting') > 0
                assert counter('vs_router_tproxy_guard', 'forward') == 0

        process = start()
        # (a) allowed flow traverses the proxy.
        request('ct_allow', True, proxied=True)
        # (b) denied flows never reach the origin (preauth -90 before capture -80).
        for case in ('deny_first', 'default_deny'):
            install(case)
            request('ct_' + case, False)
        install('allow')
        request('ct_allow_control', True, proxied=True)
        # (c) conntrack INPUT authorization: hold one established UDP tuple,
        #     remove ONLY the generated capture table, then forge the packet mark.
        warm = send_persistent('vsr-pa-ct-guard-warm')
        assert warm['reply'] == 'vsr-pa-ct-guard-warm', 'ct guard: warm-up failed'
        healthy = send_persistent('vsr-pa-ct-guard-healthy')
        assert healthy['reply'] == 'vsr-pa-ct-guard-healthy', 'ct guard: healthy flow failed'
        assert counter('vsr_pa_observe', 'established') > 0, 'ct guard: tuple not established'
        guard_before = counter('vs_router_tproxy_input', 'input')
        apply_rules('destroy table inet vs_router_tproxy_interception\n')
        apply_rules(CT_FORGE_UDP.format(port=25000))
        established_before = counter('vsr_pa_observe', 'established')
        output_before = counter('vsr_pa_observe', 'output')
        forged = send_persistent('vsr-pa-ct-guard-forged')
        time.sleep(0.2)
        guard_delta = counter('vs_router_tproxy_input', 'input') - guard_before
        established_delta = counter('vsr_pa_observe', 'established') - established_before
        output_delta = counter('vsr_pa_observe', 'output') - output_before
        print(json.dumps({'case': 'ct_guard_forge', 'sender': forged,
                          'input_guard_drop_delta': guard_delta,
                          'established_delta': established_delta,
                          'proxy_output_delta': output_delta}), flush=True)
        assert forged['reply'] is None, 'packet-mark-only TProxy was answered through the proxy'
        assert guard_delta > 0, 'conntrack INPUT guard was not reached'
        assert established_delta > 0, 'packet was not established before the guard'
        assert output_delta == 0, 'packet-mark-only packet reached proxy OUTPUT'
        forbidden_tokens.add('vsr-pa-ct-guard-forged')
        # recovery: restore the generated capture and confirm the flow proxies again.
        apply_rules('destroy table inet vsr_pa_ct_forge\n')
        apply_rules(interception)
        recovered = send_persistent('vsr-pa-ct-guard-recovered')
        assert recovered['reply'] == 'vsr-pa-ct-guard-recovered', 'ct guard: recovery failed'
        # (d) explicit off removes every generator table and restores ordinary routing.
        apply_rules(POLICIES['off_interception'] + POLICIES['off'] + POLICIES['off_guard']
                    + POLICIES['allow_firewall'])
        ns(NAMES[0], 'ip', 'rule', 'del', 'priority', '100')
        ns(NAMES[0], 'ip', 'route', 'flush', 'table', '100')
        process.kill()
        process.wait(timeout=5)
        processes.remove(process)
        request('ct_off', True)
        apply_rules(POLICIES['default_deny_firewall'])
        request('ct_off_default_deny', False)
        assert not any(e['token'] in forbidden_tokens for e in origin), 'delayed blocked token reached origin'
        assert persistent.poll() is None, 'persistent UDP socket owner exited during experiment'
        print('PASS: generated TProxy UDP capture + conntrack INPUT guard; packet-mark '
              'forge dropped; explicit off restored ordinary routing')
    print('PASS: UDP interception with conntrack-mark INPUT authorization')


try:
    for name in NAMES:
        run("ip", "netns", "add", name)
        created.append(name)
        ns(name, "ip", "link", "set", "lo", "up")
    for left, right, peer_ns, subnet in (
        ("lan0", "pa-client", NAMES[1], "10.212.1"),
        ("wan0", "pa-origin", NAMES[2], "10.212.2"),
    ):
        run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
        run("ip", "link", "set", left, "netns", NAMES[0])
        run("ip", "link", "set", right, "netns", peer_ns)
        ns(NAMES[0], "ip", "addr", "add", subnet + ".1/24", "dev", left)
        ns(NAMES[0], "ip", "link", "set", left, "up")
        ns(peer_ns, "ip", "link", "set", right, "name", "eth0")
        ns(peer_ns, "ip", "addr", "add", subnet + ".2/24", "dev", "eth0")
        ns(peer_ns, "ip", "link", "set", "eth0", "up")
        ns(peer_ns, "ip", "route", "add", "default", "via", subnet + ".1")
    ns(NAMES[0], "sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns(NAMES[2], "ip", "addr", "add", "198.18.0.2/32", "dev", "lo")
    ns(NAMES[0], "ip", "route", "add", "198.18.0.2/32", "via", "10.212.2.2")
    ingress = monitor(NAMES[0], "lan0", True, "10.212.1.1")
    origin = monitor(NAMES[2], "eth0", True, "198.18.0.2")
    client = monitor(NAMES[1], "eth0", True, "10.212.1.2")
    if POLICIES.get('__tproxy_interception_udp__'):
        interception_ct_probe(ingress, origin)
        raise SystemExit(0)
    if POLICIES.get('__combined__'):
        combined_probe(ingress, origin)
        raise SystemExit(0)
    for case, allowed in (("baseline", True), ("allow", True), ("deny_first", False),
                          ("default_deny", False), ("allow_first", True), ("off", True)):
        rules = POLICIES["off" if case == "baseline" else case]
        apply_rules(rules)
        probe(case, allowed, NAMES[1], "198.18.0.2", 19090, ingress, origin)
    # Combine real generated INPUT/FORWARD/NAT with preauth, not a permissive lab firewall.
    apply_rules(POLICIES['local_firewall'] + POLICIES['local_preauth'])
    probe('local_allowed', True, NAMES[1], '10.212.1.1', 19090, client, ingress, local_input=True)
    apply_rules(POLICIES['local_denied_firewall'] + POLICIES['local_denied_preauth'])
    probe('local_denied', False, NAMES[1], '10.212.1.1', 19090, client, ingress, local_input=True)
    apply_rules(POLICIES['pf_firewall'] + POLICIES['pf_preauth'])
    probe('associated_dnat', True, NAMES[2], '10.212.2.1', 19091, origin, client,
          translated_destination='10.212.1.2')
    forward = json.loads(ns(NAMES[0], 'nft', '-j', 'list', 'chain', 'inet', 'vs_router', 'forward').stdout)
    auto_packets = sum(expr['counter']['packets'] for item in forward['nftables']
                       if item.get('rule', {}).get('comment') == 'auto_wan_udp'
                       for expr in item['rule']['expr'] if 'counter' in expr)
    assert auto_packets > 0, 'associated DNAT did not reach the generated auto-accept'
    print('generated port-forward auto-accept packets:', auto_packets, flush=True)
    # New external port and fresh sender socket avoid an established-flow shortcut.
    apply_rules(POLICIES['local_firewall'] + POLICIES['local_preauth'])
    apply_rules('''table ip vsr_pa_unassociated {
        chain nat { type nat hook prerouting priority -100; policy accept;
            iifname "wan0" ip daddr 10.212.2.1 udp dport 19092 dnat to 10.212.1.2:19090
            iifname "lan0" ip daddr 10.212.1.1 udp dport 19093 dnat to 198.18.0.2:19090
        }
        chain observe { type filter hook prerouting priority -80; policy accept;
            iifname "lan0" ct status dnat counter comment "selected_dnat_after_preauth"
            iifname "wan0" ct status dnat ip daddr 10.212.1.2 udp dport 19090 counter comment "wan_dnat_after_preauth"
        }
    }''')
    probe('unassociated_dnat', False, NAMES[2], '10.212.2.1', 19092, origin, client)
    probe('selected_unassociated_dnat', False, NAMES[1], '10.212.1.1', 19093, client, origin)
    observed = json.loads(ns(NAMES[0], 'nft', '-j', 'list', 'chain', 'ip',
                             'vsr_pa_unassociated', 'observe').stdout)
    bypass_packets = sum(expr['counter']['packets'] for item in observed['nftables']
                         if item.get('rule', {}).get('comment') == 'selected_dnat_after_preauth'
                         for expr in item['rule']['expr'] if 'counter' in expr)
    assert bypass_packets > 0, 'selected DNAT did not pass the preauth exemption'
    print('selected DNAT reached post-preauth observer, packets:', bypass_packets, flush=True)
    wan_packets = sum(expr['counter']['packets'] for item in observed['nftables']
                      if item.get('rule', {}).get('comment') == 'wan_dnat_after_preauth'
                      for expr in item['rule']['expr'] if 'counter' in expr)
    assert wan_packets > 0, 'negative WAN DNAT was not translated before ordinary FORWARD'
    print('WAN DNAT translated before ordinary FORWARD, packets:', wan_packets, flush=True)
    # Post-negative positive control, with both ordinary firewall and preauth reloaded.
    apply_rules(POLICIES['pf_firewall'] + POLICIES['pf_preauth'])
    probe('associated_dnat_control', True, NAMES[2], '10.212.2.1', 19091, origin, client,
          translated_destination='10.212.1.2')
    probe('local_control', True, NAMES[1], '10.212.1.1', 19090, client, ingress, local_input=True)
    print("PASS: UDP ordering, default-deny, off, local INPUT and associated/unassociated DNAT")
finally:
    for process in processes:
        process.terminate()
        process.wait(timeout=5)
    for name in reversed(created):
        run("ip", "netns", "delete", name)
