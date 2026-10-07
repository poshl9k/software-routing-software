"""Full-stack TProxy end-to-end matrix probe. AUTHORIZED DISPOSABLE DEBIAN VM ONLY.

Runs the *entire* generated TProxy tract as one unit inside fresh temporary
network namespaces (router / selected-client / ordinary-client / origin):

* the ordinary product firewall (``generate_nftables``);
* the guards phase: FORWARD containment + PREROUTING preauthorization + the
  three DNS guards (ingress PREROUTING ``-110``, listener INPUT ``-10``,
  resolver OUTPUT ``-20``), byte-for-byte from the generators;
* the interception phase: ct-mark reset ``-85`` + TProxy capture ``-80`` +
  conntrack INPUT guard ``-20`` (``generate_tproxy_interception``);
* the generated sing-box JSON, run as a test UID with ``CAP_NET_ADMIN``/
  ``CAP_NET_RAW``;
* two real Unbound instances (selected UID 29092 / ordinary UID 29093) plus a
  loopback DNS stub ``127.0.0.1:15353``;
* the owned policy route (``ip rule fwmark 0x100 -> table 100`` +
  ``ip route local 0.0.0.0/0 dev lo table 100``) from ``marks.POLICY_ROUTES``.

It then drives the norm, fault, recovery, emulated-reboot and off matrix. Each
scenario records PASS or a hard failure; the process exits non-zero on any hard
failure or cleanup error.

The public gate ``tproxy.not_available`` stays closed: the enabled configuration
is only the offline ``model_copy`` fixture produced by
``generate_tproxy_e2e_cases.py``. Nothing here touches the guest root network
namespace, its routes or its firewall; ``vsr-live-403ab3a`` is never involved.

lab-31 (F4): capture is gated on the preauth stamp (``meta mark & 0x400``). With
the preauth table removed the mark is absent, capture does not fire and selected
transit falls through to FORWARD, where the independent containment (``-10``)
holds it. Both allowed and denied selected flows therefore fail closed instead of
being diverted into LOCAL_IN -> sing-box -> origin.

LAB SCAFFOLD (explicit, not generator output): the product firewall default-denies
INPUT, and the interception generator only supplies an INPUT *drop* guard, not an
INPUT *accept* for intercepted traffic. To let the intercepted flow reach the
sing-box listener this probe inserts one accept rule into the product INPUT chain
keyed on the product's own conntrack proof token (``ct mark & 0x200``). It is a
companion/modeled authorization, not shipped generator text, and is labelled as
such in the report.
"""

import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

NAMES = ("vsr-e2e-router", "vsr-e2e-selected", "vsr-e2e-ordinary", "vsr-e2e-origin")
ROUTER, SELECTED, ORDINARY, ORIGIN = NAMES

SINGBOX = "/var/cache/vsr-singbox-probe"
SELECTED_UID = 29092
ORDINARY_UID = 29093
SINGBOX_UID = 29091

SELECTED_IP = "10.212.1.1"
ORDINARY_IP = "10.212.3.1"
WAN_IP = "10.212.2.1"
SELECTED_CLIENT_IP = "10.212.1.2"
ORDINARY_CLIENT_IP = "10.212.3.2"
ORIGIN_IP_EXPLICIT = "198.18.0.2"   # explicit-forward upstream (selected)
ORIGIN_IP_DEFAULT = "198.18.0.3"    # ordinary WAN upstream
ECHO_PORT = 19090                   # firewall-allowed
DENY_PORT = 19091                   # no firewall rule -> denied
STUB_PORT = 15353
PROOF_BIT = 0x200
ROUTE_TABLE = 100
ROUTE_PRIORITY = 100
ROUTE_FWMARK = 0x100

# Lab INPUT accept keyed on the product conntrack proof token (see module docstring).
LAB_INPUT_ACCEPT = (
    'add rule inet vs_router input iifname "lan0" meta nfproto ipv4 '
    'meta l4proto { tcp, udp } ct mark & 0x200 == 0x200 counter accept '
    'comment "e2e_lab_tproxy_input"'
)


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=20, **kwargs)


def ns(name, *args, **kwargs):
    return run("ip", "netns", "exec", name, *args, **kwargs)


# --------------------------------------------------------------------------
# child processes (JSON-line protocol), modelled on the base lab probes
# --------------------------------------------------------------------------
CAPTURE = r'''
import json, re, socket, struct, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((sys.argv[1], 0))
token_re = re.compile(rb'vsr-e2e-[a-z0-9-]+')
print(json.dumps({'kind': 'ready'}), flush=True)
while True:
    p, link = s.recvfrom(65535)
    if len(p) < 34 or p[12:14] != b'\x08\x00':
        continue
    ihl = (p[14] & 15) * 4
    if ihl < 20 or len(p) < 14 + ihl:
        continue
    if struct.unpack_from('!H', p, 20)[0] & 0x3fff:
        continue
    proto = p[23]
    src = socket.inet_ntoa(p[26:30]); dst = socket.inet_ntoa(p[30:34])
    sport = dport = None
    if proto in (6, 17) and len(p) >= 14 + ihl + 4:
        sport, dport = struct.unpack_from('!HH', p, 14 + ihl)
    tokens = [t.decode() for t in token_re.findall(p)]
    if not tokens and not (dport == 53 or sport == 53):
        continue
    print(json.dumps({'kind': 'wire', 'proto': proto, 'src': src, 'dst': dst,
                      'sport': sport, 'dport': dport, 'tokens': tokens,
                      'packet_type': link[2]}), flush=True)
'''

ECHO = r'''
import json, socket, select, sys, threading
IP = sys.argv[1]
PORTS = (19090, 19091)
def emit(e):
    print(json.dumps(e), flush=True)
def handle(c, peer):
    buf = bytearray()
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break
            buf.extend(data)
            emit({'kind': 'receive', 'proto': 'tcp', 'data': bytes(buf).decode('ascii', 'replace'),
                  'peer': peer[0]})
            c.sendall(data)
    except OSError:
        pass
    finally:
        c.close()
listeners = []
for port in PORTS:
    t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind((IP, port)); t.listen(16); t.setblocking(False)
    listeners.append(t)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind((IP, 19090))
udp2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp2.bind((IP, 19091))
emit({'kind': 'ready'})
while True:
    r, _, _ = select.select(listeners, [], [], 0.2)
    for t in r:
        c, peer = t.accept(); threading.Thread(target=handle, args=(c, peer), daemon=True).start()
    for u in (udp, udp2):
        u.settimeout(0.001)
        try:
            data, peer = u.recvfrom(4096)
        except (socket.timeout, BlockingIOError):
            continue
        emit({'kind': 'receive', 'proto': 'udp', 'data': data.decode('ascii', 'replace'),
              'peer': peer[0]})
        u.sendto(data, peer)
'''

DNS_SERVER = r'''
import json, socket, struct, sys, threading
ip, port, answer = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def respond(data):
    if len(data) < 17:
        return None
    labels = []; i = 12
    try:
        while True:
            n = data[i]; i += 1
            if n == 0:
                break
            if n > 63:
                return None
            labels.append(data[i:i+n].decode('ascii').lower()); i += n
        if data[i:i+4] != b'\x00\x01\x00\x01':
            return None
    except (IndexError, UnicodeDecodeError):
        return None
    name = '.'.join(labels) + '.'
    print(json.dumps({'kind': 'receive', 'name': name, 'peer': 'server'}), flush=True)
    return (data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + data[12:i+4]
            + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(answer))
def tcp_client(client, peer):
    try:
        client.settimeout(2)
        def exact(n):
            b = b''
            while len(b) < n:
                part = client.recv(n - len(b))
                if not part:
                    raise EOFError()
                b += part
            return b
        length = struct.unpack('!H', exact(2))[0]
        reply = respond(exact(length))
        if reply:
            client.sendall(struct.pack('!H', len(reply)) + reply)
    except (OSError, EOFError):
        pass
    finally:
        client.close()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind((ip, port)); udp.settimeout(0.2)
tcp = socket.socket(); tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((ip, port)); tcp.listen(8); tcp.settimeout(0.2)
print(json.dumps({'kind': 'ready'}), flush=True)
while True:
    try:
        data, peer = udp.recvfrom(4096); reply = respond(data)
        if reply:
            udp.sendto(reply, peer)
    except socket.timeout:
        pass
    try:
        c, peer = tcp.accept(); threading.Thread(target=tcp_client, args=(c, peer), daemon=True).start()
    except socket.timeout:
        pass
'''

MGMT = r'''
import json, socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 443)); s.listen(16)
print(json.dumps({'kind': 'ready'}), flush=True)
while True:
    c, peer = s.accept()
    print(json.dumps({'kind': 'accept', 'peer': peer[0]}), flush=True)
    c.close()
'''

CLIENT_DNS = r'''
import json, socket, struct, sys
transport, target, name, ident = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
q = b''.join(bytes([len(x)]) + x.encode() for x in name.rstrip('.').split('.')) + b'\x00\x00\x01\x00\x01'
data = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + q
result = {'timeout': False}
try:
    if transport == 'udp':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.9)
        s.sendto(data, (target, 53)); result['response'] = s.recv(4096).hex()
    else:
        s = socket.create_connection((target, 53), 0.9); s.settimeout(0.9)
        s.sendall(struct.pack('!H', len(data)) + data)
        def exact(n):
            b = b''
            while len(b) < n:
                p = s.recv(n - len(b))
                if not p:
                    raise EOFError()
                b += p
            return b
        result['response'] = exact(struct.unpack('!H', exact(2))[0]).hex()
except (socket.timeout, ConnectionError, OSError, EOFError):
    result['timeout'] = True
finally:
    try:
        s.close()
    except NameError:
        pass
print(json.dumps(result))
'''

SENDER_TCP = r'''
import json, socket, struct, sys, time
token, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
result = {'connected': False, 'reply': None, 'error': None}
s = socket.socket(); s.settimeout(1.5)
try:
    s.connect((dst, port)); result['connected'] = True
except OSError as exc:
    result['error'] = repr(exc); print(json.dumps(result)); sys.exit(0)
try:
    data = token.encode()
    s.sendall(data)
    s.settimeout(1.2)
    reply = b''
    deadline = time.monotonic() + 1.2
    while len(reply) < len(data):
        s.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        reply += chunk
    result['reply'] = reply.decode('ascii', 'replace')
except OSError as exc:
    result['error'] = repr(exc)
finally:
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    except OSError:
        pass
    s.close()
print(json.dumps(result))
'''

SENDER_UDP = r'''
import json, socket, sys
token, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.9)
sent = s.sendto(token.encode(), (dst, port))
reply = None
try:
    data, peer = s.recvfrom(4096)
    reply = data.decode('ascii', 'replace')
except socket.timeout:
    pass
s.close()
print(json.dumps({'sent_bytes': sent, 'reply': reply}))
'''


class Child:
    def __init__(self, namespace, code, *args, popen_argv=None):
        if popen_argv is None:
            popen_argv = ["ip", "netns", "exec", namespace, sys.executable, "-u", "-c", code, *args]
        self.process = subprocess.Popen(popen_argv, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        self.events = []
        self.messages = queue.Queue()
        self.errors = []
        self.threads = []
        for stream, reader in ((self.process.stdout, self._read), (self.process.stderr, self._errors)):
            t = threading.Thread(target=reader, args=(stream,), daemon=True)
            t.start(); self.threads.append(t)

    def _read(self, stream):
        for line in stream:
            try:
                event = json.loads(line)
            except ValueError:
                event = {'kind': 'log', 'text': line}
            self.events.append(event); self.messages.put(event)

    def _errors(self, stream):
        for line in stream:
            self.errors.append(line)

    def ready(self):
        event = self.next()
        require(event.get('kind') == 'ready', f'child not ready: {event} {self.errors[-5:]}')

    def next(self, timeout=5):
        try:
            return self.messages.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError(f'child timed out: {self.errors[-8:]}') from None

    def drain(self):
        out = []
        while True:
            try:
                out.append(self.messages.get_nowait())
            except queue.Empty:
                return out

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=3)
        for t in self.threads:
            t.join(timeout=2)


class E2ELab:
    def __init__(self, fixture, folder):
        self.fx = fixture
        self.folder = Path(folder)
        self.created = []
        self.children = []
        self.results = []
        self.singbox = None
        self.unbound = {}
        self.stub = None
        self.uid_start = 0

    # ------------------------------------------------------------------ setup
    def nft(self, text):
        ns(ROUTER, "nft", "-c", "-f", "-", input=text)
        ns(ROUTER, "nft", "-f", "-", input=text)

    def full_stack_text(self):
        fw = self.fx["ordinary_firewall"] + "\n" + LAB_INPUT_ACCEPT + "\n"
        guards = self.fx["containment"] + self.fx["preauth"]
        dns = (self.fx["dns_guards"]["ingress"] + self.fx["dns_guards"]["listener"]
               + self.fx["dns_guards"]["output"])
        return fw + guards + dns + self.fx["interception"]

    def guards_text(self):
        guards = self.fx["containment"] + self.fx["preauth"]
        dns = (self.fx["dns_guards"]["ingress"] + self.fx["dns_guards"]["listener"]
               + self.fx["dns_guards"]["output"])
        return self.fx["ordinary_firewall"] + "\n" + LAB_INPUT_ACCEPT + "\n" + guards + dns

    def apply_full_stack(self):
        self.nft(self.full_stack_text())

    def policy_route(self, action):
        ns(ROUTER, "ip", "route", action, "local", "0.0.0.0/0", "dev", "lo",
           "table", str(ROUTE_TABLE))
        ns(ROUTER, "ip", "rule", action, "priority", str(ROUTE_PRIORITY),
           "fwmark", hex(ROUTE_FWMARK), "lookup", str(ROUTE_TABLE))

    def setup(self):
        for name in NAMES:
            run("ip", "netns", "add", name)
            self.created.append(name)
            ns(name, "ip", "link", "set", "lo", "up")
        links = (("lan0", SELECTED, "10.212.1", "10.212.1.2"),
                 ("lan1", ORDINARY, "10.212.3", "10.212.3.2"),
                 ("wan0", ORIGIN, "10.212.2", "10.212.2.2"))
        for iface, peer, subnet, peer_ip in links:
            ns(ROUTER, "ip", "link", "add", iface, "type", "veth", "peer", "name",
               "eth0", "netns", peer)
            ns(ROUTER, "ip", "addr", "add", f"{subnet}.1/24", "dev", iface)
            ns(ROUTER, "ip", "link", "set", iface, "up")
            ns(peer, "ip", "addr", "add", f"{peer_ip}/24", "dev", "eth0")
            ns(peer, "ip", "link", "set", "eth0", "up")
            ns(peer, "ip", "route", "add", "default", "via", f"{subnet}.1")
        ns(ROUTER, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        ns(ROUTER, "sysctl", "-qw", "net.ipv4.ip_unprivileged_port_start=0")
        ns(ROUTER, "ip", "route", "add", "default", "via", "10.212.2.2")
        ns(ORIGIN, "ip", "addr", "add", f"{ORIGIN_IP_EXPLICIT}/32", "dev", "eth0")
        ns(ORIGIN, "ip", "addr", "add", f"{ORIGIN_IP_DEFAULT}/32", "dev", "eth0")
        for ip in (ORIGIN_IP_EXPLICIT, ORIGIN_IP_DEFAULT):
            ns(ROUTER, "ip", "route", "add", f"{ip}/32", "via", "10.212.2.2")
        for subnet in ("10.212.1.0/24", "10.212.3.0/24"):
            ns(ORIGIN, "ip", "route", "add", subnet, "via", "10.212.2.1")
        # wire captures
        for namespace, iface in ((ROUTER, "lan0"), (ROUTER, "lan1"), (ROUTER, "wan0"),
                                 (ORIGIN, "eth0")):
            child = Child(namespace, CAPTURE, iface)
            child.ready(); self.children.append(child)
            setattr(self, f"cap_{namespace.split('-')[-1]}_{iface}", child)
        # origin echo (TCP+UDP 19090/19091) and two DNS servers
        self.echo = Child(ORIGIN, ECHO, ORIGIN_IP_EXPLICIT)
        self.echo.ready(); self.children.append(self.echo)
        self.dns_explicit = Child(ORIGIN, DNS_SERVER, ORIGIN_IP_EXPLICIT, "53", "203.0.113.7")
        self.dns_explicit.ready(); self.children.append(self.dns_explicit)
        self.dns_default = Child(ORIGIN, DNS_SERVER, ORIGIN_IP_DEFAULT, "53", "203.0.113.7")
        self.dns_default.ready(); self.children.append(self.dns_default)
        # router-side management listener + loopback DNS stub
        self.mgmt = Child(ROUTER, MGMT); self.mgmt.ready(); self.children.append(self.mgmt)
        self.start_stub()
        self.write_unbound()
        self.apply_full_stack()
        self.policy_route("add")
        self.start_singbox()
        self.start_unbound("selected")
        self.start_unbound("ordinary")

    def start_stub(self):
        self.stub = Child(ROUTER, DNS_SERVER, "127.0.0.1", str(STUB_PORT), "203.0.113.8")
        self.stub.ready(); self.children.append(self.stub)

    def stop_stub(self):
        if self.stub is not None:
            self.stub.stop()
            if self.stub in self.children:
                self.children.remove(self.stub)
            self.stub = None

    def write_unbound(self):
        self.unbound_conf = {}
        for key in ("selected", "ordinary"):
            text = self.fx["unbound"][key]
            text = text.replace('    username: "unbound"', '    username: ""')
            text = text.replace('server:', 'server:\n    directory: "/etc/unbound"\n'
                                '    pidfile: ""\n    auto-trust-anchor-file: ""\n'
                                '    root-hints: ""\n', 1)
            path = Path("/etc/unbound") / f"vsr-e2e-{uuid.uuid4().hex[:8]}-{key}.conf"
            require(not path.exists(), "lab config path already exists")
            path.write_text(text)
            ns(ROUTER, "unbound-checkconf", str(path))
            self.unbound_conf[key] = path

    def start_unbound(self, key):
        path = self.unbound_conf[key]
        address, uid = ((SELECTED_IP, SELECTED_UID) if key == "selected"
                        else (ORDINARY_IP, ORDINARY_UID))
        process = subprocess.Popen(
            ["ip", "netns", "exec", ROUTER, "setpriv", f"--reuid={uid}", f"--regid={uid}",
             "--clear-groups", "unbound", "-d", "-c", str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.unbound[key] = process
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError(f"{key} Unbound exited: {process.stderr.read()}")
            if f"{address}:53" in ns(ROUTER, "ss", "-lntu").stdout:
                return
            time.sleep(0.1)
        raise RuntimeError(f"{key} Unbound listener not ready")

    def stop_unbound(self, key):
        process = self.unbound.pop(key, None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate()

    def start_singbox(self):
        self.folder.chmod(0o755)
        config = self.folder / "singbox.json"
        config.write_text(self.fx["singbox"])
        config.chmod(0o644)
        ns(ROUTER, SINGBOX, "check", "-c", str(config))
        log = open(self.folder / "singbox.log", "w+")
        argv = ["ip", "netns", "exec", ROUTER, "setpriv", f"--reuid={SINGBOX_UID}",
                f"--regid={SINGBOX_UID}", "--clear-groups",
                "--bounding-set=+net_admin,+net_raw",
                "--inh-caps=+net_admin,+net_raw",
                "--ambient-caps=+net_admin,+net_raw",
                SINGBOX, "run", "-c", str(config)]
        process = subprocess.Popen(argv, stdout=log, stderr=log)
        self.singbox = process
        for _ in range(50):
            if process.poll() is not None:
                log.seek(0); raise AssertionError("sing-box exited: " + log.read())
            listeners = ns(ROUTER, "ss", "-H", "-lntu").stdout
            if "127.0.0.1:51272" in listeners and "127.0.0.1:51271" in listeners:
                return
            time.sleep(0.1)
        raise AssertionError("sing-box listener readiness timed out")

    def kill_singbox(self):
        if self.singbox is not None and self.singbox.poll() is None:
            self.singbox.kill()
            self.singbox.wait(timeout=5)

    # -------------------------------------------------------------- counters
    def count(self, table, chain, comment=None):
        state = json.loads(ns(ROUTER, "nft", "-j", "list", "chain", "inet", table, chain).stdout)
        total = 0
        for item in state.get("nftables", []):
            rule = item.get("rule", {})
            if comment is not None and rule.get("comment") != comment:
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    total += expr["counter"]["packets"]
        return total

    # --------------------------------------------------------------- actions
    def send_tcp(self, namespace, dst, port, token):
        child = Child(namespace, SENDER_TCP, token, dst, str(port))
        event = child.next(timeout=6)
        child.stop()
        return event

    def send_udp(self, namespace, dst, port, token):
        child = Child(namespace, SENDER_UDP, token, dst, str(port))
        event = child.next(timeout=6)
        child.stop()
        return event

    def dns(self, namespace, target, name, transport="udp"):
        ident = int.from_bytes(os.urandom(2), "big")
        child = Child(namespace, CLIENT_DNS, transport, target, name, str(ident))
        result = child.next(timeout=6)
        child.stop()
        self.last_dns = {"name": name, "target": target, "timeout": result["timeout"]}
        if result["timeout"]:
            return None, []
        raw = bytes.fromhex(result["response"])
        self.last_dns["hex"] = result["response"]
        return _parse_response(raw, ident)

    def mgmt_connect(self, namespace, target):
        code = ("import socket,sys\n"
                "s=socket.socket();s.settimeout(1.5)\n"
                "try:\n s.connect((sys.argv[1],443));print('OK')\n"
                "except OSError as e:\n print('FAIL',e)\n")
        child = Child(namespace, code, target)
        line = child.next(timeout=6)
        child.stop()
        return line.get('text', '').strip()

    def wire_tokens(self, capture, token):
        return [e for e in capture.events
                if e.get("kind") == "wire" and token in e.get("tokens", [])]

    def origin_receives(self, token):
        return [e for e in self.echo.events
                if e.get("kind") == "receive" and token in e.get("data", "")]

    def dns_receives(self, server, name):
        return [e for e in server.events
                if e.get("kind") == "receive" and e.get("name") == name]

    # --------------------------------------------------------------- matrix
    def record(self, name, status, detail):
        self.results.append((name, status, detail))
        print(json.dumps({"scenario": name, "status": status, "detail": detail}), flush=True)

    def scenario(self, name, func):
        try:
            detail = func()
            self.record(name, "PASS", detail or "")
        except AssertionError as exc:
            self.record(name, "FAIL", str(exc))
            self.diag(name)
            raise

    def diag(self, label):
        """On-failure diagnostics: engine log, key counters, listeners."""
        info = {"label": label}
        try:
            log = self.folder / "singbox.log"
            info["singbox_log"] = log.read_text()[-3000:] if log.exists() else ""
        except Exception as exc:
            info["singbox_log"] = repr(exc)
        info["singbox_alive"] = bool(self.singbox and self.singbox.poll() is None)
        for table, chain, comment in (
            ("vs_router_tproxy_interception", "prerouting", "tproxy_tcp"),
            ("vs_router_tproxy_interception", "prerouting", "tproxy_udp"),
            ("vs_router_tproxy_input", "input", "tproxy_input_denied"),
            ("vs_router_tproxy_guard", "forward", "tproxy_containment"),
            ("vs_router_tproxy_preauth", "transit", None),
            ("vs_router", "input", "e2e_lab_tproxy_input"),
        ):
            try:
                info[f"{table}:{chain}:{comment}"] = self.count(table, chain, comment)
            except Exception:
                info[f"{table}:{chain}:{comment}"] = "n/a"
        try:
            info["listeners"] = ns(ROUTER, "ss", "-H", "-lntu").stdout.strip().splitlines()
            info["ip_rule"] = ns(ROUTER, "ip", "rule").stdout.strip().splitlines()
            info["route100"] = ns(ROUTER, "ip", "route", "show", "table", "100").stdout.strip()
        except Exception as exc:
            info["netinfo_error"] = repr(exc)
        try:
            info["last_dns"] = getattr(self, "last_dns", None)
            info["stub_events"] = self.stub.drain()[-6:] if self.stub else []
            info["dns_explicit_events"] = self.dns_explicit.drain()[-4:]
            info["dns_default_events"] = self.dns_default.drain()[-4:]
        except Exception as exc:
            info["dns_error"] = repr(exc)
        try:
            info["echo_alive"] = self.echo.process.poll() is None
            info["echo_events"] = self.echo.drain()[-8:]
            origin_cap = getattr(self, "cap_origin_eth0", None)
            wan_cap = getattr(self, "cap_router_wan0", None)
            info["origin_wire"] = ([e for e in origin_cap.events if e.get("kind") == "wire"][-8:]
                                   if origin_cap else [])
            info["wan_wire"] = ([e for e in wan_cap.events if e.get("kind") == "wire"][-8:]
                                if wan_cap else [])
            lan_cap = getattr(self, "cap_router_lan0", None)
            client_cap = getattr(self, "cap_selected_eth0", None)
            info["lan0_wire"] = ([e for e in lan_cap.events if e.get("kind") == "wire"][-12:]
                                 if lan_cap else [])
            info["client_wire"] = ([e for e in client_cap.events if e.get("kind") == "wire"][-12:]
                                   if client_cap else [])
        except Exception as exc:
            info["event_error"] = repr(exc)
        print(json.dumps({"diag": info}), flush=True)

    def new_token(self, case):
        return f"vsr-e2e-{case}-{uuid.uuid4().hex[:8]}"

    def norm(self):
        # N1 allowed TCP via proxy
        def n1():
            token = self.new_token("n1tcp")
            tproxy_before = self.count("vs_router_tproxy_interception", "prerouting", "tproxy_tcp")
            res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
            require(res["connected"], f"N1 not connected: {res}")
            require(res["reply"] == token, f"N1 reply mismatch: {res}")
            recv = self.origin_receives(token)
            require(len(recv) == 1 and recv[0]["peer"] == WAN_IP,
                    f"N1 origin peer not router (not proxied): {recv}")
            require(self.count("vs_router_tproxy_interception", "prerouting", "tproxy_tcp")
                    > tproxy_before, "N1 capture counter did not increase")
            require(self.count("vs_router_tproxy_guard", "forward") == 0,
                    "N1 allowed flow hit containment")
            return f"reply ok, origin_peer={recv[0]['peer']} (proxied)"
        self.scenario("norm_allow_tcp_selected", n1)

        # N2 allowed UDP via proxy
        def n2():
            token = self.new_token("n2udp")
            tproxy_before = self.count("vs_router_tproxy_interception", "prerouting", "tproxy_udp")
            res = self.send_udp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
            require(res["reply"] == token, f"N2 reply mismatch: {res}")
            recv = self.origin_receives(token)
            require(len(recv) == 1 and recv[0]["peer"] == WAN_IP,
                    f"N2 origin peer not router (not proxied): {recv}")
            require(self.count("vs_router_tproxy_interception", "prerouting", "tproxy_udp")
                    > tproxy_before, "N2 capture counter did not increase")
            return f"reply ok, origin_peer={recv[0]['peer']} (proxied)"
        self.scenario("norm_allow_udp_selected", n2)

        # N3 unselected ordinary client is not intercepted (direct)
        def n3():
            token = self.new_token("n3direct")
            tproxy_before = self.count("vs_router_tproxy_interception", "prerouting", "tproxy_tcp")
            res = self.send_tcp(ORDINARY, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
            require(res["connected"] and res["reply"] == token, f"N3 not delivered: {res}")
            recv = self.origin_receives(token)
            require(len(recv) == 1 and recv[0]["peer"] == ORDINARY_CLIENT_IP,
                    f"N3 unselected flow was intercepted: {recv}")
            require(self.count("vs_router_tproxy_interception", "prerouting", "tproxy_tcp")
                    == tproxy_before, "N3 unselected flow hit capture")
            return f"direct, origin_peer={recv[0]['peer']}"
        self.scenario("norm_unselected_direct", n3)

        # N4 denied selected flow never reaches origin
        def n4():
            token = self.new_token("n4deny")
            preauth_before = self.count("vs_router_tproxy_preauth", "transit")
            res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, DENY_PORT, token)
            require(res["reply"] is None, f"N4 denied flow delivered: {res}")
            require(not self.origin_receives(token), "N4 denied token reached origin")
            require(self.count("vs_router_tproxy_preauth", "transit") > preauth_before,
                    "N4 preauth transit drop not reached")
            return "blocked at preauth, origin empty"
        self.scenario("norm_denied_selected_blocked", n4)

        # N5 denied unselected flow blocked by ordinary firewall
        def n5():
            token = self.new_token("n5deny")
            res = self.send_tcp(ORDINARY, ORIGIN_IP_EXPLICIT, DENY_PORT, token)
            require(res["reply"] is None, f"N5 denied flow delivered: {res}")
            require(not self.origin_receives(token), "N5 denied token reached origin")
            return "blocked by FORWARD default-deny, origin empty"
        self.scenario("norm_denied_unselected_blocked", n5)

        # N6/N7/N8/N9 DNS
        self.scenario("norm_dns_selected_stub", self._dns_selected_stub)
        self.scenario("norm_dns_ordinary_origin", self._dns_ordinary_origin)
        self.scenario("norm_dns_local_record", self._dns_local_record)
        self.scenario("norm_dns_explicit_forward", self._dns_explicit_forward)

        # N10 management-like local access preserved
        def n10():
            require(self.mgmt_connect(SELECTED, SELECTED_IP).startswith("OK"),
                    "N10 selected management access lost")
            require(self.mgmt_connect(ORDINARY, ORDINARY_IP).startswith("OK"),
                    "N10 ordinary management access lost")
            return "panel TCP/443 reachable from both lan clients"
        self.scenario("norm_mgmt_local_preserved", n10)

    def _dns_selected_stub(self):
        name = f"unmatched-{uuid.uuid4().hex[:6]}.vsrprobe.org."
        self.stub.drain(); self.dns_explicit.drain(); self.dns_default.drain()
        rcode, ips = self.dns(SELECTED, SELECTED_IP, name)
        require(rcode == 0 and "203.0.113.8" in ips, f"selected unmatched not from stub: {rcode} {ips}")
        require(self.dns_receives(self.stub, name), "stub did not receive selected query")
        require(not self.dns_receives(self.dns_explicit, name) and
                not self.dns_receives(self.dns_default, name), "selected query leaked to WAN")
        return "selected unmatched -> stub 203.0.113.8, no WAN"

    def _dns_ordinary_origin(self):
        name = f"ordinary-{uuid.uuid4().hex[:6]}.vsrprobe.org."
        self.stub.drain(); self.dns_explicit.drain(); self.dns_default.drain()
        rcode, ips = self.dns(ORDINARY, ORDINARY_IP, name)
        require(rcode == 0 and "203.0.113.7" in ips, f"ordinary unmatched failed: {rcode} {ips}")
        require(self.dns_receives(self.dns_default, name), "ordinary did not reach WAN origin")
        require(not self.dns_receives(self.stub, name), "ordinary query reached selected stub")
        return "ordinary unmatched -> WAN 203.0.113.7, stub untouched"

    def _dns_local_record(self):
        for target, source in ((SELECTED_IP, SELECTED), (ORDINARY_IP, ORDINARY)):
            self.stub.drain(); self.dns_explicit.drain(); self.dns_default.drain()
            rcode, ips = self.dns(source, target, "router.test.")
            require(rcode == 0 and "192.0.2.77" in ips, f"local record failed at {target}: {ips}")
            require(not (self.stub.drain() + self.dns_explicit.drain() + self.dns_default.drain()),
                    "local record escaped upstream")
        return "router.test. = 192.0.2.77 on both resolvers, no upstream"

    def _dns_explicit_forward(self):
        for target, source in ((SELECTED_IP, SELECTED), (ORDINARY_IP, ORDINARY)):
            name = f"fwd-{uuid.uuid4().hex[:6]}.forward.vsrprobe.org."
            self.stub.drain(); self.dns_explicit.drain(); self.dns_default.drain()
            rcode, ips = self.dns(source, target, name)
            require(rcode == 0 and "203.0.113.7" in ips, f"explicit forward failed at {target}: {ips}")
            require(self.dns_receives(self.dns_explicit, name),
                    "explicit forward did not reach 198.18.0.2")
        return "*.forward.vsrprobe.org -> 198.18.0.2 on both resolvers"

    # ------------------------------------------------------------- faults
    def healthy_tcp(self, case):
        token = self.new_token(case)
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
        require(res["connected"] and res["reply"] == token, f"healthy control failed: {res}")
        return token

    def _fault_kill_singbox(self):
        self.kill_singbox()
        token = self.new_token("f1")
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
        require(res["reply"] is None, f"F1 flow served with engine down: {res}")
        require(not self.origin_receives(token), "F1 leaked to origin with engine down")
        dtoken = self.new_token("f1d")
        dres = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, DENY_PORT, dtoken)
        require(dres["reply"] is None and not self.origin_receives(dtoken),
                "F1 denied flow reached origin")
        require(self.mgmt_connect(SELECTED, SELECTED_IP).startswith("OK"),
                "F1 management access lost")
        self.start_singbox()
        self.healthy_tcp("f1recover")
        return "engine SIGKILL -> fail-closed (no leak), deny held, mgmt kept, recovery ok"

    def _fault_interception_deleted(self):
        self.nft(self.fx["off"]["interception"])
        guard_before = self.count("vs_router_tproxy_guard", "forward", "tproxy_containment")
        token = self.new_token("f2")
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
        require(res["reply"] is None, f"F2 allowed flow delivered after capture loss: {res}")
        require(not self.origin_receives(token), "F2 allowed token leaked after capture loss")
        require(self.count("vs_router_tproxy_guard", "forward", "tproxy_containment") > guard_before,
                "F2 containment guard did not catch the un-captured selected flow")
        dtoken = self.new_token("f2d")
        dres = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, DENY_PORT, dtoken)
        require(dres["reply"] is None and not self.origin_receives(dtoken),
                "F2 deny bypassed after capture loss")
        require(self.mgmt_connect(SELECTED, SELECTED_IP).startswith("OK"),
                "F2 management access lost")
        self.nft(self.fx["interception"])
        self.healthy_tcp("f2recover")
        return ("capture loss -> selected transit fail-closed at containment (-10) "
                "(independent of preauth); deny held; mgmt kept; recovery ok")

    def _fault_policy_route_lost(self):
        self.policy_route("del")
        token = self.new_token("f3")
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
        require(res["reply"] is None, f"F3 flow delivered without policy route: {res}")
        require(not self.origin_receives(token), "F3 leaked to origin without policy route")
        dtoken = self.new_token("f3d")
        require(self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, DENY_PORT, dtoken)["reply"] is None,
                "F3 deny bypassed")
        require(self.mgmt_connect(SELECTED, SELECTED_IP).startswith("OK"),
                "F3 management access lost")
        self.policy_route("add")
        self.healthy_tcp("f3recover")
        return "policy route loss -> fail-closed (no leak), deny held, mgmt kept, recovery ok"

    def _fault_preauth_lost(self):
        # lab-31: capture is gated on the preauth stamp. Losing preauth removes
        # the mark, so capture does not fire and selected transit falls through
        # to the ordinary FORWARD path, where the independent containment (-10)
        # holds it. Allowed AND denied selected flows must fail closed.
        self.nft(self.fx["off"]["preauth"])
        guard_before = self.count("vs_router_tproxy_guard", "forward", "tproxy_containment")
        token = self.new_token("f4")
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
        require(res["reply"] is None, f"F4 allowed flow delivered with preauth absent: {res}")
        require(not self.origin_receives(token),
                "F4 allowed selected token leaked to origin with preauth absent")
        require(self.count("vs_router_tproxy_guard", "forward", "tproxy_containment") > guard_before,
                "F4 containment did not catch the un-authorized selected transit")
        dtoken = self.new_token("f4d")
        dres = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, DENY_PORT, dtoken)
        require(dres["reply"] is None and not self.origin_receives(dtoken),
                "F4 deny bypassed with preauth absent")
        require(self.mgmt_connect(SELECTED, SELECTED_IP).startswith("OK"),
                "F4 management access lost")
        self.nft(self.fx["preauth"])
        self.healthy_tcp("f4recover")
        return ("preauth loss -> capture gate holds: allowed+denied selected "
                "transit fail-closed at the independent containment (-10) "
                "(capture requires the live preauth stamp); mgmt kept; recovery ok")

    def _fault_dns_stub_down(self):
        self.stop_stub()
        name = f"loss-{uuid.uuid4().hex[:6]}.vsrprobe.org."
        self.dns_explicit.drain(); self.dns_default.drain()
        rcode, ips = self.dns(SELECTED, SELECTED_IP, name)
        require(rcode != 0 and not ips, f"F5 selected answered without stub: {ips}")
        require(not self.dns_receives(self.dns_explicit, name) and
                not self.dns_receives(self.dns_default, name),
                "F5 selected query leaked to WAN after stub loss")
        rc, ipp = self.dns(ORDINARY, ORDINARY_IP, f"ord-{uuid.uuid4().hex[:6]}.vsrprobe.org.")
        require(rc == 0 and "203.0.113.7" in ipp, f"F5 ordinary DNS broke: {ipp}")
        require(self.dns(SELECTED, SELECTED_IP, "router.test.")[1] == ["192.0.2.77"],
                "F5 local record lost")
        self.start_stub()
        rec_name = f"rec-{uuid.uuid4().hex[:6]}.vsrprobe.org."
        recovered = False
        for _ in range(4):
            rc2, ips2 = self.dns(SELECTED, SELECTED_IP, rec_name)
            if rc2 == 0 and "203.0.113.8" in ips2:
                recovered = True
                break
            time.sleep(1)
        require(recovered, "F5 selected DNS did not recover after stub restart")
        return "stub loss -> selected denied (no WAN leak), ordinary/local alive, recovery ok"

    def _fault_unbound_killed(self):
        self.stop_unbound("selected")
        name = f"nokill-{uuid.uuid4().hex[:6]}.vsrprobe.org."
        self.dns_explicit.drain(); self.dns_default.drain()
        rcode, ips = self.dns(SELECTED, SELECTED_IP, name)
        require(rcode is None or (rcode != 0 and not ips),
                f"F6 selected answered with resolver down: {ips}")
        require(not self.dns_receives(self.dns_explicit, name) and
                not self.dns_receives(self.dns_default, name),
                "F6 selected query leaked to WAN with resolver down")
        rc, ipp = self.dns(ORDINARY, ORDINARY_IP, f"ord2-{uuid.uuid4().hex[:6]}.vsrprobe.org.")
        require(rc == 0 and "203.0.113.7" in ipp, f"F6 ordinary DNS broke: {ipp}")
        require(self.mgmt_connect(SELECTED, SELECTED_IP).startswith("OK"),
                "F6 management access lost")
        self.start_unbound("selected")
        rec_name = f"rec2-{uuid.uuid4().hex[:6]}.vsrprobe.org."
        recovered = False
        for _ in range(4):
            rc2, ips2 = self.dns(SELECTED, SELECTED_IP, rec_name)
            if rc2 == 0 and "203.0.113.8" in ips2:
                recovered = True
                break
            time.sleep(1)
        require(recovered, "F6 selected DNS did not recover after resolver restart")
        return "selected resolver loss -> denied (no WAN leak), ordinary alive, mgmt kept, recovery ok"

    # ------------------------------------------------------------- reboot
    def _reboot(self):
        # Emulate a re-apply, NOT a real reboot (a real reboot cannot be staged here).
        self.kill_singbox()
        self.stop_unbound("selected"); self.stop_unbound("ordinary")
        self.nft(self.fx["off"]["interception"] + self.fx["off"]["preauth"]
                 + self.fx["off"]["containment"] + self.fx["off"]["dns_ingress"]
                 + self.fx["off"]["dns_listener"] + self.fx["off"]["dns_output"])
        self.policy_route("del")
        # phase guards first: protective tables must come up before any tract
        self.nft(self.guards_text())
        dtoken = self.new_token("reb-deny")
        dres = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, DENY_PORT, dtoken)
        require(dres["reply"] is None and not self.origin_receives(dtoken),
                "reboot: guards did not deny before interception")
        require(self.mgmt_connect(SELECTED, SELECTED_IP).startswith("OK"),
                "reboot: management access lost before interception")
        # phase readiness: policy route + engine + resolvers
        self.policy_route("add")
        self.start_singbox()
        self.start_unbound("selected"); self.start_unbound("ordinary")
        # phase interception last
        self.nft(self.fx["interception"])
        self.healthy_tcp("reb-recover")
        self._dns_selected_stub()
        return ("re-apply: guards deny before any tract, then readiness, then capture; "
                "NOT a real reboot (only artifact re-application was staged)")

    # ------------------------------------------------------------- off
    def _off(self):
        self.kill_singbox()
        self.stop_unbound("selected"); self.stop_unbound("ordinary")
        self.nft(self.fx["off"]["interception"] + self.fx["off"]["preauth"]
                 + self.fx["off"]["containment"] + self.fx["off"]["dns_ingress"]
                 + self.fx["off"]["dns_listener"] + self.fx["off"]["dns_output"]
                 + self.fx["ordinary_firewall"])
        self.policy_route("del")
        token = self.new_token("off")
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
        recv = self.origin_receives(token)
        require(res["reply"] == token and len(recv) == 1 and recv[0]["peer"] == SELECTED_CLIENT_IP,
                f"off: ordinary routing not restored: {res} {recv}")
        self.nft(self.fx["default_deny_firewall"])
        dtoken = self.new_token("offdeny")
        dres = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, dtoken)
        require(dres["reply"] is None and not self.origin_receives(dtoken),
                "off: default deny not preserved")
        return "all own tables/policy-route removed -> ordinary routing; default deny kept"

    def execute(self):
        self.norm()
        for name, func in (
            ("fault_sigkill_singbox", self._fault_kill_singbox),
            ("fault_interception_deleted", self._fault_interception_deleted),
            ("fault_policy_route_lost", self._fault_policy_route_lost),
            ("fault_preauth_lost", self._fault_preauth_lost),
            ("fault_dns_stub_down", self._fault_dns_stub_down),
            ("fault_unbound_killed", self._fault_unbound_killed),
            ("emulated_reboot_reapply", self._reboot),
            ("off_restores_ordinary", self._off),
        ):
            self.scenario(name, func)

    # ------------------------------------------------------------- cleanup
    def cleanup(self):
        errors = []
        try:
            self.kill_singbox()
        except Exception as exc:
            errors.append(repr(exc))
        for key in list(self.unbound):
            try:
                self.stop_unbound(key)
            except Exception as exc:
                errors.append(repr(exc))
        for child in reversed(self.children):
            try:
                child.stop()
            except Exception as exc:
                errors.append(repr(exc))
        self.children = []
        for name in reversed(self.created):
            try:
                subprocess.run(["ip", "netns", "del", name], check=False,
                               capture_output=True, text=True, timeout=20)
            except Exception as exc:
                errors.append(repr(exc))
        self.created = []
        for path in getattr(self, "unbound_conf", {}).values():
            try:
                path.unlink(missing_ok=True)
            except Exception as exc:
                errors.append(repr(exc))
        self.unbound_conf = {}
        # verify empty
        def capture(*argv):
            return subprocess.run(argv, check=False, capture_output=True, text=True,
                                  timeout=20).stdout

        netns = capture("ip", "netns", "list")
        tables = capture("nft", "list", "tables")
        rules = capture("ip", "rule")
        routes = capture("ip", "route", "show", "table", str(ROUTE_TABLE))
        require(not any(n in netns for n in NAMES), f"cleanup: netns remain: {netns}")
        require("vs_router" not in tables, f"cleanup: nft tables remain: {tables}")
        require(not routes.strip(), f"cleanup: route table {ROUTE_TABLE} not empty: {routes}")
        require(not errors, f"cleanup errors: {errors}")
        print("CLEANUP: netns/nft/ip-rule/route-table empty", flush=True)


def _parse_response(data, ident):
    def read_name(offset, depth=0):
        require(depth < 8, "DNS compression loop")
        labels = []
        while True:
            require(offset < len(data), "short DNS name")
            n = data[offset]
            if n & 0xc0 == 0xc0:
                require(offset + 1 < len(data), "short pointer")
                sub, _ = read_name(((n & 0x3f) << 8) | data[offset + 1], depth + 1)
                if sub and sub != ".":
                    labels.append(sub.rstrip("."))
                return ".".join(filter(None, labels)) + ".", offset + 2
            require(n < 64 and offset + n + 1 <= len(data), "invalid label")
            offset += 1
            if not n:
                return ".".join(labels) + ".", offset
            labels.append(data[offset:offset+n].decode("ascii").lower())
            offset += n
    require(len(data) >= 12, "short DNS response")
    rid, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", data)
    require(rid == ident and flags & 0x8000, "DNS response identity/header mismatch")
    _, offset = read_name(12)
    offset += 4
    result = []
    for _ in range(answers):
        _, offset = read_name(offset)
        require(offset + 10 <= len(data), "short RR")
        kind, cls, _, size = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if kind == 1 and cls == 1 and size == 4:
            result.append(socket.inet_ntoa(data[offset:offset+size]))
        offset += size
    return flags & 15, result


def main():
    if len(sys.argv) != 2:
        raise SystemExit("VM ONLY: tproxy_e2e_probe.py generated-e2e.json")
    require(os.geteuid() == 0, "root required in authorized disposable VM")
    require(sys.flags.optimize == 0, "run without Python optimization")
    for binary in ("ip", "nft", "unbound", "unbound-checkconf", "setpriv", "ss"):
        require(shutil.which(binary), f"missing installed binary: {binary}")
    require(os.path.exists(SINGBOX), f"missing sing-box binary {SINGBOX}")
    fixture = json.loads(Path(sys.argv[1]).read_text())
    require(fixture.get("kind") == "tproxy_e2e_vm_v1", "wrong fixture kind")
    with tempfile.TemporaryDirectory(prefix="vsr-e2e-", dir="/var/cache") as folder:
        lab = E2ELab(fixture, Path(folder))
        failure = None
        try:
            lab.setup()
            lab.execute()
        except BaseException as exc:  # noqa: BLE001 - report then re-raise
            failure = exc
        try:
            lab.cleanup()
        except Exception as cleanup_exc:
            print(json.dumps({"cleanup_error": repr(cleanup_exc)}), flush=True)
            if failure is None:
                failure = cleanup_exc
        passed = sum(1 for _, s, _ in lab.results if s == "PASS")
        residual = sum(1 for _, s, _ in lab.results if s == "RESIDUAL")
        failed = [n for n, s, _ in lab.results if s == "FAIL"]
        print(json.dumps({"summary": {"pass": passed, "residual": residual,
                                      "failed": failed}}), flush=True)
        if failure is not None:
            raise failure
        if failed:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
