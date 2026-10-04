"""VM ONLY: run two disposable Unbound instances in isolated namespaces.

Run as root on an authorized disposable Debian guest with ip, nft, unbound,
unbound-checkconf and ss already installed. No host/root-network changes.
A fake loopback DNS stub is NOT sing-box; this proves only DNS source/cache
separation in the namespace experiment, never TProxy fail-closed.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any
import uuid

from tproxy_dns_baseline_probe import Child, CLIENT, parse_response

SERVER = r'''
import json, socket, struct, sys, threading
ip, port, answer = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def respond(data, transport, peer):
 if len(data) < 17: return None
 labels=[]; i=12
 try:
  while True:
   n=data[i]; i+=1
   if n==0: break
   if n>63: return None
   labels.append(data[i:i+n].decode('ascii').lower()); i+=n
  if data[i:i+4]!=b'\x00\x01\x00\x01': return None
 except (IndexError,UnicodeDecodeError): return None
 name='.'.join(labels)+'.'
 print(json.dumps({'kind':'receive','name':name,'peer':peer[0],
                   'id':struct.unpack_from('!H',data)[0],'transport':transport}),flush=True)
 return data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+data[12:i+4]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(answer)
def tcp_client(client,peer):
 try:
  client.settimeout(2)
  def exact(n):
   data=b''
   while len(data)<n:
    part=client.recv(n-len(data))
    if not part: raise EOFError()
    data+=part
   return data
  length=struct.unpack('!H',exact(2))[0]
  reply=respond(exact(length),'tcp',peer)
  if reply: client.sendall(struct.pack('!H',len(reply))+reply)
 except (OSError,EOFError): pass
 finally: client.close()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind((ip,port)); udp.settimeout(.2)
tcp=socket.socket(); tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
tcp.bind((ip,port)); tcp.listen(8); tcp.settimeout(.2)
print(json.dumps({'kind':'ready'}),flush=True)
while True:
 try:
  data,peer=udp.recvfrom(4096); reply=respond(data,'udp',peer)
  if reply: udp.sendto(reply,peer)
 except socket.timeout: pass
 try:
  client,peer=tcp.accept(); threading.Thread(target=tcp_client,args=(client,peer),daemon=True).start()
 except socket.timeout: pass
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=12).stdout


def counter(namespace, table, chain, comment):
    data=json.loads(run('ip','netns','exec',namespace,'nft','-j','list','chain',
                        'inet',table,chain))
    return sum(expr['counter']['packets'] for entry in data['nftables']
               if entry.get('rule',{}).get('comment') == comment
               for expr in entry['rule']['expr'] if 'counter' in expr)


def check_fixture(fixture: dict[str, Any]):
    require(type(fixture) is dict and fixture.get('kind') == 'tproxy_dns_split_vm_v1',
            'wrong fixture kind')
    require(all(type(fixture.get(k)) is str for k in
                ('firewall','listener_guard','direct_guard','output_guard')), 'missing nft rules')
    require(type(fixture.get('unbound')) is dict and
            all(type(fixture['unbound'].get(k)) is str for k in ('selected','ordinary')),
            'missing Unbound configs')
    selected, ordinary = fixture['unbound']['selected'], fixture['unbound']['ordinary']
    require('interface: 10.212.1.1' in selected and 'interface: 10.212.3.1' not in selected and
            'do-not-query-localhost: no' in selected and
            'forward-addr: 127.0.0.1@15353' in selected, 'selected split invalid')
    require('interface: 10.212.3.1' in ordinary and 'interface: 10.212.1.1' not in ordinary and
            'forward-addr: 198.18.0.3' in ordinary and
            '127.0.0.1@15353' not in ordinary, 'ordinary split invalid')
    require('tproxy_dns_selected_wrong_listener' in fixture['listener_guard'] and
            'tproxy_dns_unselected_wrong_listener' in fixture['listener_guard'] and
            'tproxy_dns_direct' in fixture['direct_guard'] and
            'meta skuid 29092' in fixture['output_guard'] and
            'ip daddr { 198.18.0.2 }' in fixture['output_guard'] and
            '198.18.0.3' not in fixture['output_guard'], 'missing DNS protection')
    require('tproxy' not in fixture['firewall'].lower(), 'live TProxy in ordinary firewall')


def main():
    require(os.geteuid() == 0 and len(sys.argv) == 2,
            'VM ONLY root: tproxy_dns_split_probe.py generated.json')
    for binary in ('ip','nft','unbound','unbound-checkconf','ss','setpriv'):
        require(shutil.which(binary), f'missing installed binary: {binary}')
    fixture = json.loads(Path(sys.argv[1]).read_text())
    check_fixture(fixture)
    suffix = uuid.uuid4().hex[:8]
    ns = {key: f'vsr-split-{suffix}-{key}' for key in ('router','selected','ordinary','origin')}
    config = {key: Path('/etc/unbound') / f'vsr-split-{suffix}-{key}.conf'
              for key in ('selected','ordinary')}
    made, children, processes = [], [], []
    try:
        with tempfile.TemporaryDirectory(prefix='vsr-split-') as temp:
            rules = Path(temp)/'rules.nft'
            for name in ns.values():
                run('ip','netns','add',name); made.append(name)
                run('ip','-n',name,'link','set','lo','up')
            links = [('lan0','selected','10.212.1.1/24','10.212.1.2/24'),
                     ('lan1','ordinary','10.212.3.1/24','10.212.3.2/24'),
                     ('wan0','origin','10.212.2.1/24','10.212.2.2/24')]
            for index,(iface,peer,router_ip,peer_ip) in enumerate(links):
                remote=f'vsp{suffix[:6]}{index}'
                run('ip','-n',ns['router'],'link','add',iface,'type','veth','peer','name',remote)
                run('ip','-n',ns['router'],'link','set',remote,'netns',ns[peer])
                for name,dev,address in ((ns['router'],iface,router_ip),(ns[peer],remote,peer_ip)):
                    run('ip','-n',name,'addr','add',address,'dev',dev)
                    run('ip','-n',name,'link','set',dev,'up')
                if peer == 'origin':
                    run('ip','-n',ns[peer],'addr','add','198.18.0.2/32','dev',remote)
                    run('ip','-n',ns[peer],'addr','add','198.18.0.3/32','dev',remote)
                else:
                    run('ip','-n',ns[peer],'route','add','198.18.0.2/32','via',router_ip.split('/')[0])
                    other = '10.212.3.1' if peer == 'selected' else '10.212.1.1'
                    run('ip','-n',ns[peer],'route','add',other+'/32','via',router_ip.split('/')[0])
            for target in ('198.18.0.2/32','198.18.0.3/32'):
                run('ip','-n',ns['router'],'route','add',target,'via','10.212.2.2')
            for subnet in ('10.212.1.0/24','10.212.3.0/24'):
                run('ip','-n',ns['origin'],'route','add',subnet,'via','10.212.2.1')
            run('ip','netns','exec',ns['router'],'sysctl','-qw','net.ipv4.ip_forward=1')
            run('ip','netns','exec',ns['router'],'sysctl','-qw',
                'net.ipv4.ip_unprivileged_port_start=0')
            rules.write_text('\n'.join(fixture[k] for k in
                                       ('firewall','listener_guard','direct_guard','output_guard')))
            run('ip','netns','exec',ns['router'],'nft','-c','-f',str(rules))
            run('ip','netns','exec',ns['router'],'nft','-f',str(rules))
            for key in ('selected','ordinary'):
                text=fixture['unbound'][key]
                text=text.replace('    username: "unbound"','    username: ""')
                text=text.replace('server:', 'server:\n    directory: "/etc/unbound"\n'
                                  '    pidfile: ""\n    auto-trust-anchor-file: ""\n'
                                  '    root-hints: ""\n',1)
                require(not config[key].exists(), 'lab config already exists')
                config[key].write_text(text)
                run('ip','netns','exec',ns['router'],'unbound-checkconf',str(config[key]))
            stub = Child(ns['router'],SERVER,'127.0.0.1','15353','203.0.113.8')
            children.append(stub); stub.ready()
            origin_explicit = Child(ns['origin'],SERVER,'198.18.0.2','53','203.0.113.7')
            children.append(origin_explicit); origin_explicit.ready()
            origin_default = Child(ns['origin'],SERVER,'198.18.0.3','53','203.0.113.7')
            children.append(origin_default); origin_default.ready()
            for key, address, uid in (('selected','10.212.1.1',29092),
                                      ('ordinary','10.212.3.1',29093)):
                process = subprocess.Popen(['ip','netns','exec',ns['router'],
                                            'setpriv',f'--reuid={uid}',f'--regid={uid}',
                                            '--clear-groups','unbound','-d','-c',str(config[key])],
                                           stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
                processes.append(process)
                for _ in range(50):
                    if process.poll() is not None:
                        assert process.stderr is not None
                        raise RuntimeError(f'{key} Unbound exited: '+process.stderr.read())
                    if address+':53' in run('ip','netns','exec',ns['router'],'ss','-lntu'):
                        break
                    time.sleep(.1)
                else: raise RuntimeError(f'{key} Unbound listener not ready')
                status = Path(f'/proc/{process.pid}/status').read_text()
                require(f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}' in status,
                        f'{key} Unbound socket process UID mismatch')
                require('CapEff:\t0000000000000000' in status and
                        'CapAmb:\t0000000000000000' in status,
                        f'{key} Unbound retained capabilities')
                print(f'{key} Unbound UID {uid}: PASS',flush=True)
            def query(source, destination, name, expected, transport='udp'):
                ident = int.from_bytes(os.urandom(2),'big')
                result = json.loads(run('ip','netns','exec',ns[source],sys.executable,
                                        '-c',CLIENT,transport,destination,name,str(ident)))
                require(not result['timeout'], f'{source} {name} timed out')
                rcode, ips = parse_response(bytes.fromhex(result['response']),ident,name)
                require(rcode == 0 and expected in ips,
                        f'{source} {name} reply: rcode={rcode}, IPs={ips}')
                print(f'{source} {transport} {name} -> {expected}: PASS',flush=True)
            for transport in ('udp','tcp'):
                name = f'shared-{transport}.vsrprobe.org.'
                stub.drain(); origin_explicit.drain(); origin_default.drain()
                before_reply=counter(ns['router'],'vs_router_tproxy_dns_output','output',
                                     'tproxy_dns_client_reply')
                query('selected','10.212.1.1','router.test.','192.0.2.77',transport)
                query('ordinary','10.212.3.1','router.test.','192.0.2.77',transport)
                require(counter(ns['router'],'vs_router_tproxy_dns_output','output',
                                'tproxy_dns_client_reply')>before_reply,
                        'selected UID client reply OUTPUT missing')
                require(not stub.drain() and not origin_explicit.drain() and
                        not origin_default.drain(), 'local record escaped')
                before_stub=counter(ns['router'],'vs_router_tproxy_dns_output','output','tproxy_dns_stub')
                query('selected','10.212.1.1',name,'203.0.113.8',transport)
                selected_upstream = stub.drain(); require(any(e.get('name')==name for e in selected_upstream),
                                                           'selected stub did not receive query')
                require(counter(ns['router'],'vs_router_tproxy_dns_output','output',
                                'tproxy_dns_stub') > before_stub, 'selected stub UID OUTPUT missing')
                require(not any(e.get('name')==name for e in
                                origin_explicit.drain()+origin_default.drain()),
                        'selected unmatched query reached WAN origin')
                query('ordinary','10.212.3.1',name,'203.0.113.7',transport)
                require(any(e.get('name')==name for e in origin_default.drain()),
                        'ordinary upstream did not receive query')
                require(not any(e.get('name')==name for e in stub.drain()),
                        'ordinary query reached selected stub')
                query('selected','10.212.1.1',name,'203.0.113.8',transport)
                require(any(e.get('name')==name for e in stub.drain()),
                        'selected repeat was served from cache instead of stub')
                query('ordinary','10.212.3.1',name,'203.0.113.7',transport)
                require(not any(e.get('name')==name for e in
                                origin_explicit.drain()+origin_default.drain()),
                        'ordinary repeat bypassed instance cache')
                forward = ('www.forward.vsrprobe.org.' if transport == 'udp'
                           else 'tcp.forward.vsrprobe.org.')
                before_forward=counter(ns['router'],'vs_router_tproxy_dns_output','output',
                                       'tproxy_dns_explicit_forward')
                query('selected','10.212.1.1',forward,'203.0.113.7',transport)
                require(any(e.get('name')==forward for e in origin_explicit.drain()) and
                        counter(ns['router'],'vs_router_tproxy_dns_output','output',
                                'tproxy_dns_explicit_forward')>before_forward,
                        'selected explicit forward did not reach origin')
                query('ordinary','10.212.3.1',forward,'203.0.113.7',transport)
                require(any(e.get('name')==forward for e in origin_explicit.drain()),
                        'ordinary explicit forward did not reach origin')
                require(not stub.drain(), 'explicit forward reached selected stub')
                for source, destination, table, chain, comment in (
                    ('selected','10.212.3.1','vs_router_tproxy_dns_listener','input',
                     'tproxy_dns_selected_wrong_listener'),
                    ('ordinary','10.212.1.1','vs_router_tproxy_dns_listener','input',
                     'tproxy_dns_unselected_wrong_listener'),
                    ('selected','198.18.0.2','vs_router_tproxy_dns_ingress','prerouting',
                     'tproxy_dns_direct')):
                    name=f'blocked-{source}-{transport}.vsrprobe.org.'
                    before=counter(ns['router'],table,chain,comment)
                    result=json.loads(run('ip','netns','exec',ns[source],sys.executable,
                                          '-c',CLIENT,transport,destination,name,
                                          str(int.from_bytes(os.urandom(2),'big'))))
                    require(result['timeout'] and counter(ns['router'],table,chain,comment)>before,
                            f'{source} {transport} {destination}: missing drop or timeout')
                    require(not any(e.get('name') == name for e in
                                    stub.drain()+origin_explicit.drain()+origin_default.drain()),
                            f'{source} {transport} {destination}: reached upstream')
                    print(f'{source} {transport} {destination} blocked: PASS',flush=True)
                # Same external tuple: selected UID is denied; ordinary UID works.
                name=f'uid-{transport}.vsrprobe.org.'
                before=counter(ns['router'],'vs_router_tproxy_dns_output','output',
                               'tproxy_dns_output_denied')
                def from_uid(uid):
                    ident=int.from_bytes(os.urandom(2),'big')
                    result=json.loads(run('ip','netns','exec',ns['router'],'setpriv',
                                          f'--reuid={uid}',f'--regid={uid}','--clear-groups',
                                          sys.executable,'-c',CLIENT,transport,'198.18.0.3',
                                          name,str(ident)))
                    return result,ident
                denied,_=from_uid(29092)
                after_denied=counter(ns['router'],'vs_router_tproxy_dns_output',
                                     'output','tproxy_dns_output_denied')
                require(denied['timeout'] and after_denied>before,
                    'selected UID external OUTPUT was not revoked')
                require(not any(e.get('name')==name for e in origin_default.drain()),
                        'selected UID reached ordinary origin')
                allowed,allowed_id=from_uid(29093)
                require(not allowed['timeout'] and
                        any(e.get('name')==name for e in origin_default.drain()),
                        'ordinary UID failed same-destination control')
                rcode,ips=parse_response(bytes.fromhex(allowed['response']),allowed_id,name)
                require(rcode==0 and '203.0.113.7' in ips,
                        'ordinary UID received invalid DNS response')
                require(counter(ns['router'],'vs_router_tproxy_dns_output','output',
                                'tproxy_dns_output_denied')==after_denied,
                        'ordinary UID unexpectedly matched selected drop')
                print(f'{transport} socket UID OUTPUT boundary: PASS',flush=True)
            # Repeating a previously resolved name must also fail after loss;
            # fresh QNAMEs separately rule out masking by cache or negative cache.
            stub.stop()
            require(stub.process.poll() is not None, 'fake DNS stub still running')
            stub.drain(); origin_explicit.drain(); origin_default.drain()
            prior='shared-tcp.vsrprobe.org.'
            prior_id=int.from_bytes(os.urandom(2),'big')
            cached=json.loads(run('ip','netns','exec',ns['selected'],sys.executable,
                                  '-c',CLIENT,'tcp','10.212.1.1',prior,str(prior_id)))
            if not cached['timeout']:
                cached_rcode,cached_ips=parse_response(bytes.fromhex(cached['response']),prior_id,prior)
                require(cached_rcode!=0 or not cached_ips,
                        f'selected cache answered after stub loss: {cached_ips}')
            print('previously resolved selected name blocked after stub loss: PASS',flush=True)
            for transport in ('udp','tcp'):
                lost=f'loss-{transport}.vsrprobe.org.'
                ident=int.from_bytes(os.urandom(2),'big')
                result=json.loads(run('ip','netns','exec',ns['selected'],sys.executable,
                                      '-c',CLIENT,transport,'10.212.1.1',lost,str(ident)))
                failure_result = 'timeout'
                if not result['timeout']:
                    rcode,ips=parse_response(bytes.fromhex(result['response']),ident,lost)
                    require(rcode!=0 or not ips,
                            f'{transport} selected fresh name succeeded without stub: {ips}')
                    failure_result = f'rcode={rcode}, answers={ips}'
                time.sleep(1)
                require(not any(e.get('name')==lost for e in
                                origin_explicit.drain()+origin_default.drain()),
                        f'{transport} selected fresh name reached WAN after stub loss')
                ordinary_name=f'ordinary-loss-{transport}.vsrprobe.org.'
                query('ordinary','10.212.3.1',ordinary_name,'203.0.113.7',transport)
                require(any(e.get('name')==ordinary_name for e in origin_default.drain()),
                        'ordinary DNS loss control did not reach origin')
                query('selected','10.212.1.1','router.test.','192.0.2.77',transport)
                forward=f'alive-{transport}.forward.vsrprobe.org.'
                query('selected','10.212.1.1',forward,'203.0.113.7',transport)
                require(any(e.get('name')==forward for e in origin_explicit.drain()),
                        'selected explicit forward failed with stub down')
                print(f'{transport} fresh DNS loss: {failure_result}; ordinary WAN absent: PASS',flush=True)
            stub = Child(ns['router'],SERVER,'127.0.0.1','15353','203.0.113.8')
            children.append(stub); stub.ready()
            recovered=False
            for attempt in range(4):
                name=f'recovery-{attempt}.vsrprobe.org.'
                ident=int.from_bytes(os.urandom(2),'big')
                result=json.loads(run('ip','netns','exec',ns['selected'],sys.executable,
                                      '-c',CLIENT,'udp','10.212.1.1',name,str(ident)))
                if not result['timeout']:
                    rcode,ips=parse_response(bytes.fromhex(result['response']),ident,name)
                    if rcode==0 and '203.0.113.8' in ips:
                        require(any(e.get('name')==name for e in stub.drain()),
                                'recovery answer not attributed to stub')
                        recovered=True
                        break
                time.sleep(1)
            require(recovered, 'selected DNS did not recover after fake stub restart')
            tcp_recovery='recovery-tcp.vsrprobe.org.'
            query('selected','10.212.1.1',tcp_recovery,'203.0.113.8','tcp')
            require(any(e.get('name')==tcp_recovery for e in stub.drain()),
                    'TCP recovery did not reach restarted stub')
            require(not any(e.get('name','').startswith(('recovery-','loss-')) for e in
                            origin_explicit.drain()+origin_default.drain()),
                    'selected fault/recovery DNS query reached WAN origin late')
            print('selected fresh UDP/TCP DNS after stub restart: PASS',flush=True)
            print('two Unbound processes/cache paths: PASS',flush=True)
    finally:
        errors=[]
        for process in reversed(processes):
            try:
                process.terminate()
                try: process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.communicate()
            except Exception as exc: errors.append(exc)
        for child in reversed(children):
            try: child.stop()
            except Exception as exc: errors.append(exc)
        for name in reversed(made):
            try: run('ip','netns','del',name)
            except Exception as exc: errors.append(exc)
        for path in config.values():
            try: path.unlink(missing_ok=True)
            except Exception as exc: errors.append(exc)
        if errors:
            if sys.exc_info()[1] is None:
                raise ExceptionGroup('DNS split probe cleanup failed',errors)
            failure = sys.exc_info()[1]
            assert failure is not None
            for error in errors: failure.add_note(f'cleanup failed: {error!r}')


if __name__ == '__main__':
    main()
