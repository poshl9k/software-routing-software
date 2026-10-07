"""Standalone TCP proof: real interception + preauthorization never bypasses
default-deny FORWARD. AUTHORIZED DISPOSABLE DEBIAN VM ONLY, as root.

Run with a generated --tcp-preauth-combined JSON fixture, never on the host or a
product router. Everything lives in three freshly created network namespaces; the
guest root namespace, its routes and its firewall are untouched. Needs the
reviewed sing-box binary at /var/cache/vsr-singbox-probe and a test UID carrying
effective/ambient CAP_NET_RAW.

Real ordinary firewall, preauth and containment text and the sing-box JSON come
from the product generators. The TProxy interception, INPUT proof and UID OUTPUT
observer are LAB-ONLY rules scoped to this experiment; this is not a product
enablement path and does not reopen tproxy.not_available. Bounded observation:
sender timeout 1.5s plus a 1.5s window per negative case; counters include
ACK/retransmissions, not independent payloads.

OUTPUT-authorization bound (see output_authorization): while the UID-scoped
OUTPUT drop is active and the proxy's outbound socket is still open, a new token
never reaches origin, and an unrelated test UID to the same destination is not
affected (the policy discriminates by socket UID, not by destination). Known
limitation: once bytes have been accepted into the proxy outbound socket's send
buffer, tearing the flow down (client abort / proxy stop) can still flush those
buffered bytes to origin as a FIN+data segment; that teardown flush appears in
the OUTPUT hook without an attributable socket UID, so a ``meta skuid`` drop does
not catch it. This is recorded as an observation, not asserted away, and is
outside the active-window revocation claim.
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
_spec = importlib.util.spec_from_file_location('vsr_tcp_preauth_combined_base', SOURCE)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

ROUTER = base.ROUTER
PROXY_UID = 29090
OTHER_UID = 29091
NET_RAW = 1 << 13
SCOPE = 'ip daddr 198.18.0.2 oifname "wan0" tcp dport 19090'
# Lab-only independent OUTPUT guard: authorizes proxy egress separately from
# FORWARD, by socket UID. Not a product ownership model.
UID_GUARD = f'''table inet vsr_tcp_preauth_uid_guard {{
 chain output {{ type filter hook output priority -20; policy accept;
  meta skuid {PROXY_UID} {SCOPE} counter comment "proxy_uid"
  meta skuid {OTHER_UID} {SCOPE} counter comment "other_uid"
 }}
}}'''
UID_REVOKE = (f'insert rule inet vsr_tcp_preauth_uid_guard output meta skuid {PROXY_UID} '
              f'{SCOPE} counter drop comment "proxy_uid_drop"')
UID_RESTORE = ('flush chain inet vsr_tcp_preauth_uid_guard output\n'
               f'add rule inet vsr_tcp_preauth_uid_guard output meta skuid {PROXY_UID} '
               f'{SCOPE} counter comment "proxy_uid"\n'
               f'add rule inet vsr_tcp_preauth_uid_guard output meta skuid {OTHER_UID} '
               f'{SCOPE} counter comment "other_uid"\n')
# Independent-scope control: same destination/port tuple from a different UID.
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


def require(ok, message):
    base.require(ok, message)


def validate_fixture(policies):
    require(policies.get('__tcp_preauth_combined__') == 'tcp',
            'requires opt-in --tcp-preauth-combined fixture')
    require(policies.get('__input_proof__') is True,
            'combined fixture must carry the INPUT proof mode')
    for case in ('allow', 'allow_first', 'deny_first', 'default_deny'):
        for suffix in ('', '_firewall', '_guard'):
            require(isinstance(policies.get(case + suffix), str),
                    f'missing generated policy: {case + suffix}')
        require('priority -90' in policies[case], 'expected generated preauth priority -90')
        require('priority -10' in policies[case + '_guard'],
                'expected generated FORWARD containment priority -10')
    for key in ('off', 'off_guard', 'allow_singbox'):
        require(isinstance(policies.get(key), str), f'missing generated policy: {key}')
    require(policies['off'] == 'destroy table inet vs_router_tproxy_preauth\n',
            'unexpected preauth off text')
    require(policies['off_guard'] == 'destroy table inet vs_router_tproxy_guard\n',
            'unexpected containment off text')
    config = json.loads(policies['allow_singbox'])
    require(any(i.get('type') == 'tproxy' and i.get('network') == 'tcp'
                and i.get('listen') == '127.0.0.1' and i.get('listen_port') == 51272
                for i in config.get('inbounds', [])), 'expected TCP TProxy listener 51272')
    require(config.get('outbounds') == [{'type': 'direct', 'tag': 'direct'}],
            'expected secret-free direct-only sing-box fixture')


class CombinedLab(base.Lab):
    """Real firewall/preauth/containment plus test-UID TCP interception."""

    def start_proxy(self):
        config = self.folder / 'config.json'
        os.chown(self.folder, PROXY_UID, PROXY_UID)
        os.chmod(self.folder, 0o700)
        os.chown(config, PROXY_UID, PROXY_UID)
        os.chmod(config, 0o600)
        self.proxy = base.Child(
            self, ROUTER, 'setpriv', f'--reuid={PROXY_UID}', f'--regid={PROXY_UID}',
            '--clear-groups', '--bounding-set=-all,+net_raw',
            '--inh-caps=+net_raw', '--ambient-caps=+net_raw',
            base.BINARY, 'run', '-c', str(config))
        for _ in range(50):
            require(self.proxy.p.poll() is None,
                    f'UID proxy failed to start: {self.proxy.errors[-10:]}')
            status = Path(f'/proc/{self.proxy.p.pid}/status').read_text()
            fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
            uids = [int(part) for part in fields['Uid'].split()]
            effective = int(fields['CapEff'].strip(), 16)
            ambient = int(fields['CapAmb'].strip(), 16)
            if uids == [PROXY_UID] * 4 and effective == NET_RAW and ambient == NET_RAW:
                listeners = base.ns(ROUTER, 'ss', '-H', '-ltnp').stdout.splitlines()
                if any('127.0.0.1:51272' in line and f'pid={self.proxy.p.pid},' in line
                       for line in listeners):
                    return
            time.sleep(0.1)
        raise AssertionError('UID/capability-owned TCP listener readiness failed')

    def setup(self):
        super().setup()
        self.nft(UID_GUARD)

    def uid_counts(self):
        return dict(proxy=self.counter('vsr_tcp_preauth_uid_guard', 'output', 'proxy_uid'),
                    other=self.counter('vsr_tcp_preauth_uid_guard', 'output', 'other_uid'),
                    drop=self.counter('vsr_tcp_preauth_uid_guard', 'output', 'proxy_uid_drop'))

    def positive(self, case, proxied=True, retain=False):
        # After explicit off the lab UID guard table is gone; the off control
        # proves ordinary routing, not UID attribution, so skip the observer.
        if self.off:
            return super().positive(case, proxied=proxied, retain=retain)
        before = self.uid_counts()['proxy']
        outcome = super().positive(case, proxied=proxied, retain=retain)
        delta = self.uid_counts()['proxy'] - before
        if proxied:
            require(delta > 0, f'{case}: proxy UID OUTPUT was never attributed separately')
        else:
            require(delta == 0, f'{case}: explicit off reached proxy UID OUTPUT')
        return outcome

    def other_uid_control(self):
        """Same destination from a different UID must survive the UID revocation.

        A destination-scoped guard could not pass this control, so an unaffected
        second UID is what shows the OUTPUT policy is keyed on the socket UID.
        """
        token = 'vsr-tcp-other-uid-' + uuid.uuid4().hex + '\n'
        before = self.uid_counts()
        result = json.loads(base.ns(
            ROUTER, 'setpriv', f'--reuid={OTHER_UID}', f'--regid={OTHER_UID}',
            '--clear-groups', 'python3', '-c', OTHER_CLIENT, token).stdout)
        self.settle()
        after = self.uid_counts()
        received = self.frames(self.receiver, token)
        require(result['reply'] == token and len(received) == 1
                and received[0]['peer'][0] == '10.212.2.1',
                'unrelated UID egress was wrongly revoked')
        require(after['other'] > before['other'],
                'unrelated UID OUTPUT was not attributed separately')
        return dict(observer_delta=after['other'] - before['other'],
                    drop_delta=after['drop'] - before['drop'], echoed=True)

    def output_authorization(self, case):
        """Proxy OUTPUT is enforced by an independent UID-scoped policy, not FORWARD.

        Bounded claim: while the UID-scoped OUTPUT drop is active and the proxy
        outbound socket is still open, a new token never reaches origin, and an
        unrelated UID to the same destination still does (independent scope).
        Bytes already accepted into the proxy socket's send buffer can flush to
        origin during later teardown; that teardown flush is recorded, not
        asserted, because LOCAL_OUT gives it no attributable socket UID.
        """
        client, port = self.positive(case + '-healthy', retain=True)
        self.nft('flush chain inet vsr_tcp_observe established\n'
                 'add rule inet vsr_tcp_observe established iifname "lan0" '
                 f'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport {port} '
                 'tcp dport 19090 ct state established counter\n')
        token, result = self.exchange(client, case + '-established')
        established = self.counter('vsr_tcp_observe', 'established')
        require(result['reply'] == token and established > 0,
                'proxy OUTPUT trial lacks an established healthy control')
        before = self.uid_counts()
        require(before['proxy'] > 0, 'healthy proxy OUTPUT was never observed by UID')
        self.nft(UID_REVOKE + '\n')
        blocked_token, blocked_result = self.exchange(client, case + '-revoked')
        # Active-window snapshot, taken before any teardown, while the proxy
        # process is alive and its outbound socket is still established.
        active_origin = self.frames(self.origin_wire, blocked_token)
        active_received = self.frames(self.receiver, blocked_token)
        ingress = [e for e in self.frames(self.ingress, blocked_token)
                   if e['src'] == '10.212.1.2' and e['dst'] == '198.18.0.2'
                   and e['sport'] == port and e['dport'] == 19090]
        require((blocked_result['sent'] == len(blocked_token) and ingress)
                or blocked_result.get('reset'),
                'revoked trial lacks client ingress evidence')
        other = self.other_uid_control()
        require(not active_origin and not active_received
                and blocked_result['reply'] != blocked_token,
                'revoked proxy OUTPUT token reached origin while authorization was active')
        # Tear both endpoints down with the revocation still active, then record
        # any teardown flush of already-buffered bytes (documented limitation).
        client.stop(abort=True)
        self.proxy.stop()
        time.sleep(base.WINDOW)
        self.settle()
        after = self.uid_counts()
        require(after['drop'] - before['drop'] > 0, 'proxy UID OUTPUT drop was never reached')
        teardown_wire = self.frames(self.origin_wire, blocked_token)
        teardown_received = self.frames(self.receiver, blocked_token)
        print(json.dumps(dict(case=case, source_port=port, sender=blocked_result,
                              ingress=len(ingress), active_window_block=True,
                              uid_counters={k: after[k] - before[k] for k in before},
                              other_uid=other,
                              teardown_buffer_flush=bool(teardown_wire or teardown_received),
                              teardown_wire=len(teardown_wire),
                              teardown_echo=len(teardown_received),
                              observation_seconds=base.WINDOW)), flush=True)
        self.nft(UID_RESTORE)
        self.start_proxy()
        self.positive(case + '-recovered')

    def execute(self):
        self.setup()
        # (a)+(c) allowed first-match traverses the proxy; proxy OUTPUT attributed separately.
        self.positive('allow')
        # (b) fresh SYN under active interception must never reach origin.
        for case in ('deny_first', 'default_deny'):
            self.install(case)
            self.negative_syn(case + '-fresh')
        # (a) explicit pass-before-block ordering.
        self.install('allow_first')
        self.positive('pass-before-block')
        self.install('allow')
        # (b) established flows rechecked by preauth; no established shortcut.
        for case in ('deny_first', 'default_deny'):
            self.fault(case)
        # (c) independent proxy OUTPUT authorization.
        self.output_authorization('proxy-output')
        self.proxy.stop()
        # (d) explicit off restores ordinary routing; (e) cleanup removes lab tables.
        self.nft('destroy table inet vsr_tcp_preauth_uid_guard\n'
                 'destroy table inet vsr_tcp_input_proof\n'
                 'destroy table inet vsr_tcp_proof_reset\n'
                 'destroy table inet vsr_tcp_intercept\n'
                 + self.policies['off'] + self.policies['off_guard']
                 + self.policies['allow_firewall'])
        self.policy_rule('del')
        self.policy_route('del')
        self.off = True
        self.positive('off-allow', proxied=False)
        self.nft(self.policies['default_deny_firewall'])
        self.negative_syn('off-default-deny-fresh')
        require(not self.violations, f'TCP preauth combined violations: {self.violations}')
        print('PASS: real interception plus preauthorization never bypassed default-deny '
              'FORWARD; proxy OUTPUT was authorized separately while active; explicit off '
              'restored ordinary routing.', flush=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_tcp_preauth_combined_probe.py '
                         'generated-tcp-preauth-combined.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    validate_fixture(policies)
    require(os.geteuid() == 0, 'root required in authorized disposable VM')
    require(sys.flags.optimize == 0, 'run without Python optimization')
    with tempfile.TemporaryDirectory(prefix='vsr-tcp-preauth-combined-', dir='/var/cache') as folder:
        lab = CombinedLab(policies, Path(folder))
        try:
            lab.execute()
        finally:
            lab.cleanup()


if __name__ == '__main__':
    main()
