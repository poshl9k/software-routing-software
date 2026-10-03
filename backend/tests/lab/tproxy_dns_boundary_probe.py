"""VM ONLY: disposable root probe; four network namespaces, no root-net changes.

Run on an authorized disposable VM: python3 tproxy_dns_boundary_probe.py fixture.json
Needs installed ip/nft/Python. Uses test UDP receivers, never Unbound or sing-box.
A bounded absence check is evidence for this namespace experiment only.
"""
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid


ROUTER = '10.212.1.1'
OTHER_ROUTER = '10.212.3.1'
ORIGIN = '198.18.0.2'
WINDOW = 0.7


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=8).stdout


# Each payload is a unique ASCII token; port 53 is a fake DNS receiver, not a
# resolver. AF_PACKET records source, destination, port and token at each edge.
CAPTURE = r'''
import json,socket,struct,sys
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.bind((sys.argv[1],0))
print(json.dumps({'kind':'ready'}),flush=True)
while True:
 p,_=s.recvfrom(65535)
 if len(p)<42 or p[12:14]!=b'\x08\x00' or p[23]!=17: continue
 h=(p[14]&15)*4; end=14+struct.unpack_from('!H',p,16)[0]; u=14+h
 if h<20 or end>len(p) or u+8>end or struct.unpack_from('!H',p,20)[0]&0x3fff: continue
 sport,dport=struct.unpack_from('!HH',p,u)
 if dport not in (53,19090): continue
 token=p[u+8:end].decode('ascii','replace')
 print(json.dumps({'kind':'wire','src':socket.inet_ntoa(p[26:30]),'dst':socket.inet_ntoa(p[30:34]),'port':dport,'sport':sport,'token':token}),flush=True)
'''
RECEIVER = r'''
import json,socket,select,sys
address=sys.argv[1]; sockets=[]
for port in (53,19090):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((address,port)); sockets.append(s)
print(json.dumps({'kind':'ready'}),flush=True)
while True:
 for s in select.select(sockets,[],[],1)[0]:
  data,peer=s.recvfrom(4096); token=data.decode('ascii','replace')
  print(json.dumps({'kind':'receive','port':s.getsockname()[1],'token':token,'peer':peer[0]}),flush=True)
  s.sendto(data,peer)
'''
CLIENT = r'''
import json,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.6)
print(json.dumps({'kind':'ready','sport':s.getsockname()[1]}),flush=True)
for line in sys.stdin:
 request=json.loads(line); target=request['target']; port=request['port']; token=request['token']
 s.sendto(token.encode(),(target,port))
 try: response=s.recv(4096).decode('ascii','replace')
 except socket.timeout: response=None
 print(json.dumps({'kind':'result','token':token,'response':response,'sport':s.getsockname()[1]}),flush=True)
'''


class Child:
    def __init__(self, namespace, code, *args):
        self.process = subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable,
                                         '-u', '-c', code, *args], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, bufsize=1)
        self.events = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            try: self.events.put(json.loads(line))
            except json.JSONDecodeError: self.events.put({'kind': 'invalid', 'line': line})

    def take(self, kind, timeout=5):
        try: event = self.events.get(timeout=timeout)
        except queue.Empty as exc:
            raise AssertionError(f'{kind} timed out; child exit={self.process.poll()}') from exc
        require(event.get('kind') == kind, f'expected {kind}: {event}')
        return event

    def drain(self):
        result = []
        while True:
            try: result.append(self.events.get_nowait())
            except queue.Empty: return result

    def send(self, target, port, token):
        self.process.stdin.write(json.dumps({'target': target, 'port': port, 'token': token})+'\n')
        self.process.stdin.flush()
        return self.take('result')

    def stop(self):
        if self.process.poll() is None: self.process.terminate()
        try: self.process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.communicate(timeout=3)


def counters(ns, table, chain):
    data = json.loads(run('ip','netns','exec',ns,'nft','-j','list','chain','inet',table,chain))
    return {r['rule']['comment']: sum(e['counter']['packets'] for e in r['rule']['expr']
                                      if 'counter' in e)
            for r in data['nftables'] if 'rule' in r and 'comment' in r['rule']}


def check_fixture(f):
    require(type(f) is dict and f.get('kind') == 'tproxy_dns_boundary_vm_v1', 'fixture kind')
    require(all(isinstance(f.get(k), str) for k in
                ('firewall','preauth','guard_on','guard_off','preauth_off')), 'fixture fields')
    fw, pre, guard = f['firewall'], f['preauth'], f['guard_on']
    require('iifname { "lan0", "lan1" }' in fw and 'oifname { "wan0" }' in fw,
            'ordinary interface selection')
    require(all(f'comment "{name}"' in fw for name in
                ('dns_local','dns_external','external_port')), 'ordinary pass rules')
    require('tproxy' not in fw.lower() and 'mark' not in fw.lower(), 'ordinary firewall must be off')
    require('iifname != { "lan0" } return' in pre and 'fib daddr type local return' in pre,
            'preauth source/local boundary')
    require('iifname { "lan0" } counter drop comment "tproxy_containment"' in guard,
            'guard source boundary')
    require(f['guard_off'].strip() == 'destroy table inet vs_router_tproxy_guard' and
            f['preauth_off'].strip() == 'destroy table inet vs_router_tproxy_preauth',
            'off must remove lab tables')


def apply(ns, path, content):
    path.write_text(content)
    run('ip','netns','exec',ns,'nft','-c','-f',str(path))
    run('ip','netns','exec',ns,'nft','-f',str(path))


def cleanup(children, namespaces):
    errors = []
    for child in reversed(children):
        try: child.stop()
        except Exception as exc: errors.append(exc)
    for ns in reversed(namespaces):
        try: run('ip','netns','del',ns)
        except Exception as exc: errors.append(exc)
    return errors


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'VM-only root required')
    for binary in ('ip','nft'):
        require(shutil.which(binary), f'missing installed binary: {binary}')
    fixture = json.loads(args.fixture.read_text())
    check_fixture(fixture)
    suffix = uuid.uuid4().hex[:8]
    ns = {key: f'vsr-db-{suffix}-{key}' for key in ('router','selected','other','origin')}
    made, children = [], []
    try:
        with tempfile.TemporaryDirectory(prefix='vsr-dns-boundary-') as temp:
            path = Path(temp)/'rules.nft'
            for value in ns.values():
                run('ip','netns','add',value); made.append(value)
                run('ip','-n',value,'link','set','lo','up')
            links = [('lan0','selected','10.212.1.1/24','10.212.1.2/24'),
                     ('lan1','other','10.212.3.1/24','10.212.3.2/24'),
                     ('wan0','origin','10.212.2.1/24','10.212.2.2/24')]
            for index,(iface,peer,router_ip,peer_ip) in enumerate(links):
                remote = f'vdb{suffix[:6]}{index}'
                run('ip','-n',ns['router'],'link','add',iface,'type','veth','peer','name',remote)
                run('ip','-n',ns['router'],'link','set',remote,'netns',ns[peer])
                for namespace,dev,address in ((ns['router'],iface,router_ip),
                                              (ns[peer],remote,peer_ip)):
                    run('ip','-n',namespace,'addr','add',address,'dev',dev)
                    run('ip','-n',namespace,'link','set',dev,'up')
                if peer == 'origin':
                    run('ip','-n',ns[peer],'addr','add',ORIGIN+'/32','dev',remote)
                else:
                    run('ip','-n',ns[peer],'route','add',ORIGIN+'/32','via',router_ip.split('/')[0])
            run('ip','-n',ns['router'],'route','add',ORIGIN+'/32','via','10.212.2.2')
            for subnet in ('10.212.1.0/24','10.212.3.0/24'):
                run('ip','-n',ns['origin'],'route','add',subnet,'via','10.212.2.1')
            run('ip','netns','exec',ns['router'],'sysctl','-qw','net.ipv4.ip_forward=1')
            apply(ns['router'],path,fixture['firewall']+'\n'+fixture['preauth'])
            apply(ns['router'],path,'''destroy table inet vs_router_dns_observer
table inet vs_router_dns_observer {
 chain forward { type filter hook forward priority -20; policy accept;
  iifname "lan0" ip daddr 198.18.0.2 udp dport 53 ct state established counter comment "selected_established"
 }
}
''')
            selected = Child(ns['selected'],CLIENT); children.append(selected); selected.take('ready')
            other = Child(ns['other'],CLIENT); children.append(other); other.take('ready')
            ingress = Child(ns['router'],CAPTURE,'lan0'); children.append(ingress); ingress.take('ready')
            other_ingress = Child(ns['router'],CAPTURE,'lan1'); children.append(other_ingress); other_ingress.take('ready')
            outside = Child(ns['origin'],CAPTURE,f'vdb{suffix[:6]}2'); children.append(outside); outside.take('ready')
            local = Child(ns['router'],RECEIVER,'0.0.0.0'); children.append(local); local.take('ready')
            origin = Child(ns['origin'],RECEIVER,ORIGIN); children.append(origin); origin.take('ready')

            def trial(label, client, capture, target, port, reaches, guard=False):
                for child in (ingress,other_ingress,outside,local,origin): child.drain()
                before = counters(ns['router'],'vs_router_tproxy_guard','forward').get('tproxy_containment',0) if guard else 0
                token = f'{suffix}-{label}'
                result = client.send(target,port,token)
                time.sleep(WINDOW)
                incoming = capture.drain(); wire = outside.drain(); local_events = local.drain(); received = origin.drain()
                require(any(e.get('token') == token and e.get('dst') == target and
                            e.get('port') == port for e in incoming), f'{label}: ingress missing')
                if target in (ROUTER,OTHER_ROUTER):
                    require(any(e.get('token') == token and e.get('kind') == 'receive'
                                for e in local_events), f'{label}: local receiver missing')
                    require(not any(e.get('token') == token for e in wire+received),
                            f'{label}: local escaped to origin')
                else:
                    seen = any(e.get('token') == token and e.get('dst') == target for e in wire)
                    accepted = any(e.get('token') == token and e.get('kind') == 'receive'
                                   for e in received)
                    require(seen == reaches and accepted == reaches,
                            f'{label}: origin wire/receiver={seen}/{accepted}, expected={reaches}')
                require((result['response'] == token) == reaches, f'{label}: response mismatch')
                if guard:
                    require(counters(ns['router'],'vs_router_tproxy_guard','forward')
                            .get('tproxy_containment',0) > before, f'{label}: guard counter unchanged')
                print(f'{label}: PASS',flush=True)
                return result['sport']

            # Same selected socket and source port persists across guard toggle.
            trial('selected-local-before',selected,ingress,ROUTER,53,True)
            trial('other-local-before',other,other_ingress,OTHER_ROUTER,53,True)
            source_port = trial('selected-direct-unsafe-control',selected,ingress,ORIGIN,53,True)
            apply(ns['router'],path,fixture['guard_on'])
            established_before = counters(ns['router'],'vs_router_dns_observer','forward').get('selected_established',0)
            require(trial('selected-local-guard',selected,ingress,ROUTER,53,True) == source_port,
                    'selected socket changed')
            require(trial('selected-direct-repeat-guard',selected,ingress,ORIGIN,53,False,True)
                    == source_port, 'established UDP tuple changed')
            require(counters(ns['router'],'vs_router_dns_observer','forward')
                    .get('selected_established',0) > established_before,
                    'repeat was not observed as ct established before guard')
            trial('other-local-guard',other,other_ingress,OTHER_ROUTER,53,True)
            trial('other-external-dns-guard',other,other_ingress,ORIGIN,53,True)
            trial('other-external-port-guard',other,other_ingress,ORIGIN,19090,True)
            apply(ns['router'],path,fixture['guard_off']+'\n'+fixture['preauth_off']+
                  '\ndestroy table inet vs_router_dns_observer\n')
            trial('selected-off-ordinary',selected,ingress,ORIGIN,53,True)
            trial('other-off-ordinary',other,other_ingress,ORIGIN,19090,True)
    finally:
        errors = cleanup(children,made)
        if errors:
            if sys.exc_info()[1] is None: raise ExceptionGroup('namespace cleanup failed',errors)
            for error in errors: sys.exc_info()[1].add_note(f'cleanup failed: {error!r}')


if __name__ == '__main__':
    main()
