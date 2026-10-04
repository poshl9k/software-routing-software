"""VM ONLY: root stdlib DNS baseline probe on an authorized disposable VM.

Usage: python3 tproxy_dns_baseline_probe.py generated.json
Requires existing ip, nft, unbound, unbound-checkconf. Creates only three
temporary network namespaces. Never changes the guest root network namespace.
This proves ordinary DNS with TProxy explicitly off, not enabled fail-closed.
"""
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def run(*args, input=None):
    return subprocess.run(args, input=input, text=True, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def name_wire(name):
    return b''.join(bytes([len(x)]) + x.encode('ascii') for x in name.rstrip('.').split('.')) + b'\0'


def read_name(data, offset, depth=0):
    require(depth < 8, 'DNS compression loop')
    labels = []
    while True:
        require(offset < len(data), 'short DNS name')
        n = data[offset]
        if n & 0xc0 == 0xc0:
            require(offset + 1 < len(data), 'short DNS pointer')
            tail, _ = read_name(data, ((n & 0x3f) << 8) | data[offset + 1], depth + 1)
            return '.'.join(filter(None, ['.'.join(labels), tail])), offset + 2
        require(n < 64 and offset + n + 1 <= len(data), 'invalid DNS label')
        offset += 1
        if not n:
            return '.'.join(labels) + '.', offset
        labels.append(data[offset:offset + n].decode('ascii').lower())
        offset += n


def question(data):
    require(len(data) >= 12, 'short DNS header')
    name, end = read_name(data, 12)
    require(end + 4 <= len(data), 'short DNS question')
    qtype, qclass = struct.unpack_from('!HH', data, end)
    require(qtype == 1 and qclass == 1, 'expected A IN question')
    return name, end + 4


def answer(query, ip):
    name, end = question(query)
    require(name in ('www.forward.test.', 'tcp.forward.test.', 'guard.forward.test.'),
            'origin received unexpected DNS question')
    header = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
    rr = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + query[12:end] + rr


def parse_response(data, ident, expected_name):
    require(len(data) >= 12, 'short DNS response')
    rid, flags, questions, answers, _, _ = struct.unpack_from('!HHHHHH', data)
    require(rid == ident and flags & 0x8000 and questions == 1, 'DNS response identity/header mismatch')
    name, offset = question(data)
    require(name == expected_name, 'DNS response question mismatch')
    result = []
    for _ in range(answers):
        _, offset = read_name(data, offset)
        require(offset + 10 <= len(data), 'short DNS RR')
        kind, cls, _, size = struct.unpack_from('!HHIH', data, offset)
        offset += 10
        require(offset + size <= len(data), 'short DNS rdata')
        if kind == 1 and cls == 1 and size == 4:
            result.append(socket.inet_ntoa(data[offset:offset + size]))
        offset += size
    return flags & 15, result


CAPTURE = r'''
import json, socket, struct, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((sys.argv[1], 0))
print(json.dumps({'kind':'ready'}), flush=True)
while True:
    p, link = s.recvfrom(65535)
    if len(p) < 54 or p[12:14] != b'\x08\x00': continue
    ihl = (p[14] & 15) * 4
    if ihl < 20 or len(p) < 14 + ihl + 8: continue
    if struct.unpack_from('!H', p, 20)[0] & 0x3fff: continue
    proto = p[23]
    if proto not in (6,17): continue
    pos = 14 + ihl
    sport, dport = struct.unpack_from('!HH', p, pos)
    if dport != 53: continue
    end = min(len(p), 14 + struct.unpack_from('!H', p, 16)[0])
    if proto == 17:
        if end < pos + 8: continue
        payload = p[pos+8:end]
    else:
        if end < pos + 20: continue
        if p[pos+13] & 2:
            print(json.dumps({'kind':'tcp_syn','transport':'tcp',
                'src':socket.inet_ntoa(p[26:30]), 'dst':socket.inet_ntoa(p[30:34]),
                'sport':sport, 'dport':dport}), flush=True)
        h = (p[pos+12] >> 4) * 4
        if h < 20 or end < pos+h+2: continue
        payload = p[pos+h:end]
        if len(payload) < 2: continue
        length = struct.unpack_from('!H', payload)[0]
        if len(payload) < 2+length: continue
        payload = payload[2:2+length]
    if len(payload) < 12: continue
    labels=[]; i=12
    while i < len(payload):
        n=payload[i]; i+=1
        if n == 0: break
        if n > 63 or i+n > len(payload): break
        labels.append(payload[i:i+n].decode('ascii','replace').lower()); i+=n
    else: continue
    if not labels or i+4 > len(payload): continue
    print(json.dumps({'kind':'dns', 'transport':'tcp' if proto==6 else 'udp',
        'name':'.'.join(labels)+'.', 'id':struct.unpack_from('!H',payload)[0],
        'src':socket.inet_ntoa(p[26:30]), 'dst':socket.inet_ntoa(p[30:34]),
        'sport':sport, 'packet_type':link[2]}), flush=True)
'''


ORIGIN = r'''
import json, socket, struct, threading
IP='198.18.0.2'; ANSWER='203.0.113.7'
def name(data):
    labels=[]; i=12
    while True:
        n=data[i]; i+=1
        if not n: return '.'.join(labels)+'.',i
        if n > 63: raise ValueError('compressed origin query')
        labels.append(data[i:i+n].decode('ascii').lower()); i+=n
def respond(data, peer, transport):
    q,end=name(data)
    print(json.dumps({'kind':'receive','name':q,'transport':transport,
        'peer':peer[0], 'id':struct.unpack_from('!H',data)[0]}),flush=True)
    if q not in ('www.forward.test.', 'tcp.forward.test.', 'guard.forward.test.') or data[end:end+4] != b'\x00\x01\x00\x01': return None
    return (data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+data[12:end+4]
        +b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(ANSWER))
def tcp_client(c,peer):
    try:
        c.settimeout(2)
        def exact(n):
            b=b''
            while len(b)<n:
                part=c.recv(n-len(b))
                if not part: raise EOFError()
                b+=part
            return b
        size=struct.unpack('!H',exact(2))[0]
        reply=respond(exact(size),peer,'tcp')
        if reply: c.sendall(struct.pack('!H',len(reply))+reply)
    except (OSError,EOFError,ValueError): pass
    finally: c.close()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.bind((IP,53)); u.settimeout(.2)
t=socket.socket(); t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
t.bind((IP,53)); t.listen(8); t.settimeout(.2)
print(json.dumps({'kind':'ready'}),flush=True)
while True:
    try:
        data,peer=u.recvfrom(4096); reply=respond(data,peer,'udp')
        if reply: u.sendto(reply,peer)
    except socket.timeout: pass
    try:
        c,peer=t.accept(); threading.Thread(target=tcp_client,args=(c,peer),daemon=True).start()
    except socket.timeout: pass
'''


CLIENT = r'''
import json, socket, struct, sys
transport,target,name,ident=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4])
q=b''.join(bytes([len(x)])+x.encode() for x in name.rstrip('.').split('.'))+b'\0\0\1\0\1'
data=struct.pack('!HHHHHH',ident,0x0100,1,0,0,0)+q
result={'timeout':False}
try:
    if transport=='udp':
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.8)
        s.sendto(data,(target,53)); result['response']=s.recv(4096).hex()
    else:
        s=socket.create_connection((target,53),.8); s.settimeout(.8)
        s.sendall(struct.pack('!H',len(data))+data)
        def exact(n):
            b=b''
            while len(b)<n:
                p=s.recv(n-len(b))
                if not p: raise EOFError()
                b+=p
            return b
        result['response']=exact(struct.unpack('!H',exact(2))[0]).hex()
except (socket.timeout,ConnectionError,OSError,EOFError): result['timeout']=True
finally:
    try: s.close()
    except NameError: pass
print(json.dumps(result))
'''


class Child:
    def __init__(self, namespace, code, *args):
        self.process = subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable,
                                         '-u', '-c', code, *args], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.events = queue.Queue()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        for line in self.process.stdout:
            try: self.events.put(json.loads(line))
            except json.JSONDecodeError: self.events.put({'kind':'invalid','line':line})

    def ready(self):
        event = self.events.get(timeout=5)
        require(event == {'kind':'ready'}, f'child startup: {event}')

    def drain(self):
        out = []
        while True:
            try: out.append(self.events.get_nowait())
            except queue.Empty: return out

    def stop(self):
        self.process.terminate()
        try: self.process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.communicate()


def cleanup(children, created, config):
    errors = []
    for child in reversed(children):
        try: child.stop()
        except Exception as exc: errors.append(exc)
    for ns in reversed(created):
        try: subprocess.run(['ip','netns','del',ns],check=True)
        except Exception as exc: errors.append(exc)
    try: config.unlink(missing_ok=True)
    except Exception as exc: errors.append(exc)
    return errors


def main():
    require(os.geteuid() == 0 and len(sys.argv) == 2,
            'VM ONLY root: tproxy_dns_baseline_probe.py generated.json')
    for binary in ('ip','nft','unbound','unbound-checkconf'):
        require(shutil.which(binary), f'missing installed binary: {binary}')
    fixture = json.loads(Path(sys.argv[1]).read_text())
    require(fixture['kind'] == 'ordinary_dns_tproxy_off', 'wrong fixture kind')
    firewall, unbound = fixture['firewall'], fixture['unbound']
    require('tproxy' not in firewall.lower() and 'mark' not in firewall.lower(), 'interception in firewall')
    require('forward-addr: 198.18.0.2' in unbound, 'missing explicit forward')
    require('local-zone: "." refuse' in unbound, 'missing root refusal')
    suffix = uuid.uuid4().hex[:8]
    router, client, origin = [f'vsr-dns-{suffix}-{x}' for x in ('r','c','o')]
    created, children = [], []
    # Debian's AppArmor profile permits Unbound configs under /etc/unbound,
    # not the temporary directory. This unique guest-only file is removed below.
    config = Path('/etc/unbound') / f'vsr-dns-{suffix}.conf'
    require(not config.exists(), 'lab config path already exists')
    try:
        with tempfile.TemporaryDirectory(prefix='vsr-dns-') as temp:
            temp = Path(temp)
            for ns in (router,client,origin):
                run('ip','netns','add',ns); created.append(ns)
            for left,right,other in (('dcl'+suffix,'drl'+suffix,client),
                                     ('dor'+suffix,'dro'+suffix,origin)):
                run('ip','link','add',left,'type','veth','peer','name',right)
                run('ip','link','set',left,'netns',other)
                run('ip','link','set',right,'netns',router)
            for ns in created: run('ip','-n',ns,'link','set','lo','up')
            for ns,dev,address in ((client,'dcl'+suffix,'10.212.1.2/24'),
                                   (router,'drl'+suffix,'10.212.1.1/24'),
                                   (router,'dro'+suffix,'10.212.2.1/24'),
                                   (origin,'dor'+suffix,'10.212.2.2/24'),
                                   (origin,'dor'+suffix,'198.18.0.2/32')):
                run('ip','-n',ns,'addr','add',address,'dev',dev)
                run('ip','-n',ns,'link','set',dev,'up')
            run('ip','-n',router,'route','add','198.18.0.2/32','via','10.212.2.2')
            run('ip','-n',client,'route','add','198.18.0.0/24','via','10.212.1.1')
            run('ip','-n',origin,'route','add','10.212.1.0/24','via','10.212.2.1')
            run('ip','netns','exec',router,'sysctl','-qw','net.ipv4.ip_forward=1')
            # Generated names lan0/wan0 are namespace-local interface names.
            run('ip','-n',router,'link','set','drl'+suffix,'name','lan0')
            run('ip','-n',router,'link','set','dro'+suffix,'name','wan0')
            config.write_text(unbound.replace('    username: "unbound"', '    username: ""')
                              .replace('server:', 'server:\n    directory: "/etc/unbound"\n'
                                       '    pidfile: ""\n'
                                       '    auto-trust-anchor-file: ""\n'
                                       '    root-hints: ""\n', 1))
            run('ip','netns','exec',router,'unbound-checkconf',str(config))
            nft_file = temp/'firewall.nft'
            nft_file.write_text(firewall + '\nadd rule inet vs_router forward counter drop comment "dns_baseline_drop"\n')
            run('ip','netns','exec',router,'nft','-c','-f',str(nft_file))
            run('ip','netns','exec',router,'nft','-f',str(nft_file))
            ingress = Child(router,CAPTURE,'lan0'); children.append(ingress); ingress.ready()
            outside = Child(origin,CAPTURE,'dor'+suffix); children.append(outside); outside.ready()
            server = Child(origin,ORIGIN); children.append(server); server.ready()
            service = subprocess.Popen(['ip','netns','exec',router,'unbound','-d','-c',str(config)],
                                       stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
            try:
                for _ in range(40):
                    if service.poll() is not None:
                        raise RuntimeError('Unbound exited: '+service.stderr.read())
                    if '10.212.1.1:53' in run('ip','netns','exec',router,'ss','-lntu'):
                        break
                    time.sleep(.1)
                else: raise RuntimeError('Unbound listener not ready')
                for transport in ('udp','tcp'):
                    for case, target, name, rcode, ip in (
                        ('local','10.212.1.1','router.test.',0,'192.0.2.77'),
                        ('forward','10.212.1.1',
                         fixture['expected']['forward_name_tcp'] if transport == 'tcp' else
                         fixture['expected']['forward_name'],0,'203.0.113.7'),
                        ('unknown','10.212.1.1','unknown.test.',3,None),
                        ('direct','198.18.0.2','www.forward.test.',None,None)):
                        ingress.drain(); outside.drain(); server.drain()
                        before = drop_count(router)
                        ident = int.from_bytes(os.urandom(2),'big')
                        result = json.loads(run('ip','netns','exec',client,sys.executable,
                                                '-c',CLIENT,transport,target,name,str(ident)))
                        if case == 'direct': require(result['timeout'], 'direct DNS unexpectedly answered')
                        else:
                            require(not result['timeout'], f'{transport} {case} timeout')
                            actual, addresses = parse_response(bytes.fromhex(result['response']),ident,name)
                            require(actual == rcode and (ip is None or ip in addresses),
                                    f'{transport} {case} DNS mismatch: {actual}, {addresses}')
                        time.sleep(.25)
                        wire_in, wire_out, received = ingress.drain(), outside.drain(), server.drain()
                        matching = lambda events: [e for e in events if e.get('kind') == 'dns'
                            and e.get('name') == name and e.get('id') == ident
                            and e.get('transport') == transport]
                        ingress_events = matching(wire_in)
                        if case == 'direct' and transport == 'tcp':
                            ingress_events = [e for e in wire_in if e.get('kind') == 'tcp_syn'
                                              and e.get('src') == '10.212.1.2'
                                              and e.get('dst') == target]
                        require(any(e['src']=='10.212.1.2' and e['dst']==target
                                    for e in ingress_events), f'{transport} {case} client ingress missing')
                        if case == 'forward':
                            # Unbound uses its own upstream DNS transaction ID;
                            # it need not equal the client's original ID.
                            upstream = [e for e in wire_out if e.get('kind') == 'dns'
                                        and e.get('name') == name
                                        and e.get('src') == '10.212.2.1'
                                        and e.get('dst') == '198.18.0.2']
                            accepted = [e for e in received if e.get('kind') == 'receive'
                                        and e.get('name') == name
                                        and e.get('peer') == '10.212.2.1']
                            require(upstream and accepted and
                                    any(a['id'] == b['id'] and a['transport'] == b['transport']
                                        for a in upstream for b in accepted),
                                    'forward origin wire/receiver missing')
                        else:
                            require(not any(e.get('kind') == 'dns' and e.get('name') == name
                                            for e in wire_out), f'{transport} {case} reached origin wire')
                            require(not any(e.get('kind') == 'receive' and e.get('name') == name
                                            for e in received), f'{transport} {case} reached origin server')
                        if case == 'direct': require(drop_count(router)>before,'FORWARD drop did not increase')
                        print(f'{transport} {case}: PASS',flush=True)
                # A selected-source FORWARD guard cannot contain resolver OUTPUT:
                # the local listener accepts INPUT, then Unbound sends a new packet.
                # A following allow supplies a positive control for the guard:
                # without it, the ordinary firewall already denies direct DNS.
                run('ip','netns','exec',router,'nft','insert','rule','inet','vs_router',
                    'forward','iifname','lan0','ip','daddr','198.18.0.2',
                    'udp','dport','53','accept')
                run('ip','netns','exec',router,'nft','insert','rule','inet','vs_router',
                    'forward','iifname','lan0','counter','drop','comment','"dns_selected_guard"')
                before_guard = guard_count(router)
                ingress.drain(); outside.drain(); server.drain()
                ident = int.from_bytes(os.urandom(2),'big')
                result = json.loads(run('ip','netns','exec',client,sys.executable,
                                        '-c',CLIENT,'udp','10.212.1.1',
                                        'guard.forward.test.',str(ident)))
                require(not result['timeout'], 'guarded client DNS request timed out')
                rcode, addresses = parse_response(bytes.fromhex(result['response']),
                                                  ident,'guard.forward.test.')
                require(rcode == 0 and '203.0.113.7' in addresses, 'guarded DNS response mismatch')
                time.sleep(.25)
                wire_in, wire_out, received = ingress.drain(), outside.drain(), server.drain()
                require(any(e.get('kind') == 'dns' and e.get('name') == 'guard.forward.test.'
                            and e.get('id') == ident and e.get('src') == '10.212.1.2'
                            for e in wire_in), 'guarded client ingress missing')
                upstream = [e for e in wire_out if e.get('kind') == 'dns'
                            and e.get('name') == 'guard.forward.test.'
                            and e.get('src') == '10.212.2.1' and e.get('dst') == '198.18.0.2']
                accepted = [e for e in received if e.get('kind') == 'receive'
                            and e.get('name') == 'guard.forward.test.'
                            and e.get('peer') == '10.212.2.1']
                require(upstream and accepted and any(a['id'] == b['id']
                    and a['transport'] == b['transport'] for a in upstream for b in accepted),
                    'guarded DNS upstream wire/receiver missing')
                require(guard_count(router) == before_guard,
                        'guarded flow unexpectedly hit selected FORWARD guard')
                print('selected FORWARD guard does not contain Unbound OUTPUT: PASS',flush=True)
                ingress.drain(); outside.drain(); server.drain()
                direct_ident = int.from_bytes(os.urandom(2),'big')
                direct = json.loads(run('ip','netns','exec',client,sys.executable,
                                        '-c',CLIENT,'udp','198.18.0.2',
                                        'www.forward.test.',str(direct_ident)))
                require(direct['timeout'] and guard_count(router) > before_guard,
                        'selected FORWARD guard failed to block allowed direct DNS')
                time.sleep(.25)
                require(any(e.get('kind') == 'dns' and e.get('id') == direct_ident
                            and e.get('dst') == '198.18.0.2' for e in ingress.drain()),
                        'direct control ingress missing')
                require(not any(e.get('kind') == 'dns' and e.get('id') == direct_ident
                                for e in outside.drain()), 'direct control reached origin wire')
                require(not any(e.get('kind') == 'receive' and e.get('name') == 'www.forward.test.'
                                for e in server.drain()), 'direct control reached origin server')
                print('selected FORWARD guard direct DNS control: PASS',flush=True)
            finally:
                service.terminate()
                try: service.communicate(timeout=3)
                except subprocess.TimeoutExpired: service.kill(); service.communicate()
    finally:
        errors = cleanup(children, created, config)
        if errors:
            if sys.exc_info()[0] is None:
                raise ExceptionGroup('DNS probe cleanup failed', errors)
            for error in errors:
                sys.exc_info()[1].add_note(f'cleanup failed: {error!r}')


def drop_count(ns):
    data=json.loads(run('ip','netns','exec',ns,'nft','-j','list','chain','inet','vs_router','forward'))
    return sum(expr['counter']['packets'] for entry in data['nftables']
               if entry.get('rule',{}).get('comment') == 'dns_baseline_drop'
               for expr in entry['rule']['expr'] if 'counter' in expr)

def guard_count(ns):
    data=json.loads(run('ip','netns','exec',ns,'nft','-j','list','chain','inet','vs_router','forward'))
    return sum(expr['counter']['packets'] for entry in data['nftables']
               if entry.get('rule',{}).get('comment') == 'dns_selected_guard'
               for expr in entry['rule']['expr'] if 'counter' in expr)


if __name__ == '__main__':
    main()
