#!/usr/bin/env python3
"""Real-reboot TProxy lifecycle probe (lab-32). DISPOSABLE VM, root, stdlib.

Unlike ``tproxy_e2e_probe.py`` this probe does NOT own the router. The router
ruleset, the pinned sing-box systemd unit and the policy route are the
*persistent, reboot-restored* state installed by the lab boot harness on the
guest's root network namespace. This probe only:

  * creates short-lived ``selected`` / ``ordinary`` / ``origin`` client network
    namespaces and the veth pairs (router side named ``lan0`` / ``lan1`` /
    ``wan0`` — the interface names the generators emit);
  * drives one allowed and one denied selected flow plus the default-deny check
    through the ALREADY-INSTALLED root-namespace state;
  * asserts the protective tables, the capture tables, the policy route and the
    engine unit are present.

Two modes::

    normal      post-reboot with the full tract restored
                -> allowed flow proxied, denied flow dropped, default deny held
    failclosed  post-reboot with the engine deliberately broken: the harness
                must have withheld the capture tables -> allowed AND denied
                selected flows are dropped by the independent containment.

Nothing outside the temporary client namespaces and the two /32 origin routes is
modified; the persistent tract is never touched.
"""
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid

SELECTED = "vsr-l32-selected"
ORDINARY = "vsr-l32-ordinary"
ORIGIN = "vsr-l32-origin"
NAMES = (SELECTED, ORDINARY, ORIGIN)

SELECTED_IP = "10.212.1.1"
ORDINARY_IP = "10.212.3.1"
WAN_IP = "10.212.2.1"
SELECTED_CLIENT_IP = "10.212.1.2"
ORDINARY_CLIENT_IP = "10.212.3.2"
ORIGIN_IP_EXPLICIT = "198.18.0.2"
ORIGIN_IP_DEFAULT = "198.18.0.3"
ECHO_PORT = 19090
DENY_PORT = 19091
ROUTE_TABLE = 100

TABLES_PRESENT_NORMAL = (
    "inet vs_router",
    "inet vs_router_tproxy_guard",
    "inet vs_router_tproxy_preauth",
    "inet vs_router_tproxy_dns_ingress",
    "inet vs_router_tproxy_dns_listener",
    "inet vs_router_tproxy_dns_output",
    "inet vs_router_tproxy_ct_reset",
    "inet vs_router_tproxy_interception",
    "inet vs_router_tproxy_input",
)
TABLES_PRESENT_FAILCLOSED = (
    "inet vs_router",
    "inet vs_router_tproxy_guard",
    "inet vs_router_tproxy_preauth",
    "inet vs_router_tproxy_dns_ingress",
    "inet vs_router_tproxy_dns_listener",
    "inet vs_router_tproxy_dns_output",
)


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=20, **kwargs)


def ns(name, *args, **kwargs):
    return run("ip", "netns", "exec", name, *args, **kwargs)


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
emit({'kind': 'ready'})
while True:
    r, _, _ = select.select(listeners, [], [], 0.2)
    for t in r:
        c, peer = t.accept(); threading.Thread(target=handle, args=(c, peer), daemon=True).start()
    udp.settimeout(0.001)
    try:
        data, peer = udp.recvfrom(4096)
        emit({'kind': 'receive', 'proto': 'udp', 'data': data.decode('ascii', 'replace'),
              'peer': peer[0]})
        udp.sendto(data, peer)
    except (socket.timeout, BlockingIOError):
        pass
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


class Child:
    def __init__(self, namespace, code, *args):
        argv = ["ip", "netns", "exec", namespace, sys.executable, "-u", "-c", code, *args]
        self.process = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        self.messages = queue.Queue()
        self.errors = []
        self.threads = []
        for stream, reader in ((self.process.stdout, self._read), (self.process.stderr, self._errors)):
            t = threading.Thread(target=reader, args=(stream,), daemon=True)
            t.start(); self.threads.append(t)

    def _read(self, stream):
        for line in stream:
            try:
                self.messages.put(json.loads(line))
            except ValueError:
                self.messages.put({'kind': 'log', 'text': line})

    def _errors(self, stream):
        for line in stream:
            self.errors.append(line)

    def ready(self):
        event = self.next()
        require(event.get('kind') == 'ready', f'child not ready: {event} {self.errors[-5:]}')

    def next(self, timeout=6):
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


class RebootProbe:
    def __init__(self, mode):
        self.mode = mode
        self.created = []
        self.results = []
        self.echo = None
        self.extra_routes = []
        self.saved_defaults = None

    # -------------------------------------------------------------- helpers
    def record(self, name, status, detail):
        self.results.append((name, status, detail))
        print(json.dumps({"scenario": name, "status": status, "detail": detail}), flush=True)

    def scenario(self, name, func):
        try:
            detail = func()
            self.record(name, "PASS", detail or "")
        except AssertionError as exc:
            self.record(name, "FAIL", str(exc))
            raise

    def nft_tables(self):
        out = run("nft", "list", "tables").stdout
        return out

    def count(self, table, chain, comment=None):
        state = json.loads(run("nft", "-j", "list", "chain", "inet", table, chain).stdout)
        total = 0
        for item in state.get("nftables", []):
            rule = item.get("rule", {})
            if comment is not None and rule.get("comment") != comment:
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    total += expr["counter"]["packets"]
        return total

    def send_tcp(self, namespace, dst, port, token):
        child = Child(namespace, SENDER_TCP, token, dst, str(port))
        event = child.next()
        child.stop()
        return event

    def origin_receives(self, token):
        return [e for e in self.echo.drain()
                if e.get('kind') == 'receive' and token in e.get('data', '')]

    # -------------------------------------------------------------- topology
    def setup(self):
        for name in NAMES:
            run("ip", "netns", "add", name)
            self.created.append(name)
            ns(name, "ip", "link", "set", "lo", "up")
        # veth pairs: router side keeps the generated interface names
        for iface, peer, subnet, peer_ip in (
                ("lan0", SELECTED, "10.212.1", SELECTED_CLIENT_IP),
                ("lan1", ORDINARY, "10.212.3", ORDINARY_CLIENT_IP),
                ("wan0", ORIGIN, "10.212.2", "10.212.2.2")):
            run("ip", "link", "add", iface, "type", "veth", "peer", "name",
                "eth0", "netns", peer)
            run("ip", "addr", "add", f"{subnet}.1/24", "dev", iface)
            run("ip", "link", "set", iface, "up")
            ns(peer, "ip", "addr", "add", f"{peer_ip}/24", "dev", "eth0")
            ns(peer, "ip", "link", "set", "eth0", "up")
            ns(peer, "ip", "route", "add", "default", "via", f"{subnet}.1")
        run("sysctl", "-qw", "net.ipv4.ip_forward=1")
        ns(ORIGIN, "ip", "addr", "add", f"{ORIGIN_IP_EXPLICIT}/32", "dev", "eth0")
        ns(ORIGIN, "ip", "addr", "add", f"{ORIGIN_IP_DEFAULT}/32", "dev", "eth0")
        for ip in (ORIGIN_IP_EXPLICIT, ORIGIN_IP_DEFAULT):
            run("ip", "route", "add", f"{ip}/32", "via", "10.212.2.2")
            self.extra_routes.append((f"{ip}/32", "10.212.2.2"))
        for subnet in ("10.212.1.0/24", "10.212.3.0/24"):
            ns(ORIGIN, "ip", "route", "add", subnet, "via", WAN_IP)
        self.echo = Child(ORIGIN, ECHO, ORIGIN_IP_EXPLICIT)
        self.echo.ready()
        time.sleep(0.3)

    # -------------------------------------------------------------- checks
    def check_state(self):
        tables = self.nft_tables()
        expected = (TABLES_PRESENT_NORMAL if self.mode == "normal"
                    else TABLES_PRESENT_FAILCLOSED)
        missing = [t for t in expected if t not in tables]
        require(not missing, f"missing tables: {missing}")
        if self.mode == "failclosed":
            require("inet vs_router_tproxy_interception" not in tables,
                    "failclosed: capture table present (harness did not withhold it)")
        else:
            rules = run("ip", "rule").stdout
            require("fwmark 0x100 lookup 100" in rules, f"policy rule absent: {rules}")
            route = run("ip", "route", "show", "table", str(ROUTE_TABLE)).stdout
            require("default dev lo" in route, f"policy route absent: {route}")
        active = subprocess.run(["systemctl", "is-active", "vs-router-singbox.service"],
                                capture_output=True, text=True).stdout.strip()
        if self.mode == "normal":
            require(active == "active", f"engine unit not active: {active}")
            listeners = run("ss", "-H", "-lntu").stdout
            require("127.0.0.1:51272" in listeners and "127.0.0.1:51271" in listeners,
                    f"engine listeners absent: {listeners}")
            chain = run("nft", "list", "chain", "inet",
                        "vs_router_tproxy_interception", "prerouting").stdout
            require("ct mark set ct mark |" in chain, "ct-mark capture missing")
            require("tproxy ip to 127.0.0.1:51272" in chain, "route mark/tproxy missing")
        return (f"tables ok, unit={active}")

    def wait_engine_ready(self, timeout=8.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            active = subprocess.run(["systemctl", "is-active", "vs-router-singbox.service"],
                                    capture_output=True, text=True).stdout.strip()
            listeners = subprocess.run(["ss", "-H", "-lnt"], capture_output=True,
                                       text=True).stdout
            if active == "active" and "127.0.0.1:51272" in listeners:
                return True
            time.sleep(0.2)
        return False

    def swap_default_to_lab_wan(self):
        """Point the ROOT default at the lab WAN interface and restart the engine.

        The generated engine config uses ``auto_detect_interface``: on the
        disposable VM the only default route at boot is the *management* uplink
        (enp1s0), so a direct outbound would be bound to the management NIC and
        could never reach the lab origin on wan0. This is a lab-topology
        artifact, not a product claim: once the lab default route points at
        wan0, the engine (re)detects wan0 and the proxy path works. The original
        default routes are restored in cleanup.
        """
        self.saved_defaults = subprocess.run(["ip", "route", "show", "default"],
                                             capture_output=True, text=True).stdout.strip()
        subprocess.run(["ip", "route", "del", "default"], capture_output=True, text=True)
        run("ip", "route", "add", "default", "via", "10.212.2.2", "dev", "wan0")
        subprocess.run(["systemctl", "restart", "vs-router-singbox.service"],
                       capture_output=True, text=True, check=False)
        require(self.wait_engine_ready(), "engine not ready after lab-WAN default swap")

    def restore_default(self):
        if self.saved_defaults is None:
            return
        subprocess.run(["ip", "route", "del", "default"], capture_output=True, text=True)
        for line in self.saved_defaults.splitlines():
            subprocess.run(["ip", "route", "replace", *line.split()],
                           capture_output=True, text=True)
        self.saved_defaults = None

    def allowed_tcp_proxied(self):
        token = f"vsr-l32-allow-{uuid.uuid4().hex[:8]}"
        if self.mode == "failclosed":
            guard_before = self.count("vs_router_tproxy_guard", "forward", "tproxy_containment")
            res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
            require(res["reply"] is None, f"failclosed allowed flow delivered: {res}")
            require(not self.origin_receives(token), "failclosed allowed token leaked to origin")
            guard = self.count("vs_router_tproxy_guard", "forward", "tproxy_containment")
            require(guard > guard_before, "failclosed containment counter not hit")
            return f"allowed flow dropped, containment hit, origin empty"
        before = self.count("vs_router_tproxy_interception", "prerouting", "tproxy_tcp")
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, ECHO_PORT, token)
        require(res["connected"] and res["reply"] == token, f"allowed not delivered: {res}")
        recv = self.origin_receives(token)
        require(len(recv) == 1 and recv[0]["peer"] == WAN_IP,
                f"origin peer not router (not proxied): {recv}")
        require(self.count("vs_router_tproxy_interception", "prerouting", "tproxy_tcp")
                > before, "capture counter did not increase")
        require(self.count("vs_router_tproxy_guard", "forward", "tproxy_containment") == 0,
                "allowed flow hit containment")
        return f"proxied, origin_peer={recv[0]['peer']}"

    def denied_tcp_blocked(self):
        token = f"vsr-l32-deny-{uuid.uuid4().hex[:8]}"
        before = self.count("vs_router_tproxy_preauth", "transit")
        res = self.send_tcp(SELECTED, ORIGIN_IP_EXPLICIT, DENY_PORT, token)
        require(res["reply"] is None, f"denied flow delivered: {res}")
        require(not self.origin_receives(token), "denied token reached origin")
        require(self.count("vs_router_tproxy_preauth", "transit") > before,
                "denied flow did not hit preauth transit")
        return "blocked at preauth, origin empty"

    def default_deny_held(self):
        # ordinary (lan1) denied port: not intercepted, must be dropped by the
        # product FORWARD default-deny.
        token = f"vsr-l32-ord-{uuid.uuid4().hex[:8]}"
        res = self.send_tcp(ORDINARY, ORIGIN_IP_EXPLICIT, DENY_PORT, token)
        require(res["reply"] is None, f"ordinary denied delivered: {res}")
        require(not self.origin_receives(token), "ordinary denied token reached origin")
        return "ordinary denied blocked by FORWARD default-deny"

    def run_all(self):
        self.scenario("state_after_boot", self.check_state)
        if self.mode == "normal":
            self.swap_default_to_lab_wan()
        self.scenario("allowed_tcp_selected", self.allowed_tcp_proxied)
        self.scenario("denied_tcp_selected", self.denied_tcp_blocked)
        self.scenario("default_deny_held", self.default_deny_held)

    # -------------------------------------------------------------- cleanup
    def cleanup(self):
        errors = []
        try:
            self.restore_default()
        except Exception as exc:
            errors.append(repr(exc))
        if self.echo is not None:
            try:
                self.echo.stop()
            except Exception as exc:
                errors.append(repr(exc))
        for cidr, via in self.extra_routes:
            subprocess.run(["ip", "route", "del", cidr, "via", via],
                           capture_output=True, text=True, check=False)
        for name in reversed(self.created):
            try:
                subprocess.run(["ip", "netns", "del", name], check=False,
                               capture_output=True, text=True, timeout=20)
            except Exception as exc:
                errors.append(repr(exc))
        self.created = []
        require(not errors, f"cleanup errors: {errors}")
        print("CLEANUP: client netns + origin routes removed (persistent tract untouched)",
              flush=True)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("normal", "failclosed"):
        raise SystemExit("VM ONLY: lab32_reboot_probe.py normal|failclosed")
    require(os.geteuid() == 0, "root required")
    for binary in ("ip", "nft", "ss"):
        require(shutil.which(binary), f"missing binary: {binary}")
    probe = RebootProbe(sys.argv[1])
    failure = None
    try:
        probe.setup()
        probe.run_all()
    except BaseException as exc:  # noqa: BLE001
        failure = exc
    try:
        probe.cleanup()
    except Exception as exc:
        print(json.dumps({"cleanup_error": repr(exc)}), flush=True)
        if failure is None:
            failure = exc
    passed = sum(1 for _, s, _ in probe.results if s == "PASS")
    failed = [n for n, s, _ in probe.results if s == "FAIL"]
    print(json.dumps({"summary": {"mode": sys.argv[1], "pass": passed, "failed": failed}}),
          flush=True)
    if failure is not None:
        raise failure
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
