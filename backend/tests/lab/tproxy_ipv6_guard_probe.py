"""Generated TProxy IPv6-WAN-escape guard proof. DISPOSABLE DEBIAN VM ONLY, root.

Runs the product generator ``generate_tproxy_ipv6_guard`` together with a small
IPv6 network built entirely inside four temporary network namespaces:

    vsr6-router  -- lan0  -->  vsr6-client   (selected source,  2001:db8:1::/64)
                 -- lan1  -->  vsr6-other     (unselected source, 2001:db8:2::/64)
                 -- wan0  -->  vsr6-origin    (WAN peer, 2001:db8:3::/64)

The far WAN destination ``2001:db8:99::1`` lives on the origin loopback and is
reached only by routed transit through ``wan0``. The guest root namespace, its
routes and its firewall are untouched. Only ``ip``/``nft``/``ping`` are used.

This is not a product enablement path: the public gate ``tproxy.not_available``
stays closed and nothing is wired to bundle/apply/boot. The guard text is the
exact generator output. Negative evidence is bounded (ping timeout).

Proven here (see docs/lab-36-tproxy-ipv6-guard.md): a selected source's routed
IPv6 to a non-local (WAN) destination is dropped while the guard is active; the
router's own local/management and link-local IPv6 stay reachable; an unselected
source is unaffected; IPv4 transit is unaffected; explicit off restores routing.

NOT proven here (known boundary, do not treat as covered): bridge/flow-offload
fast paths and iif/L4-dependent policy-routing/ECMP lookups that can bypass the
ordinary FORWARD decision.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

NAMES = ('vsr6-router', 'vsr6-client', 'vsr6-other', 'vsr6-origin')
ROUTER, CLIENT, OTHER, ORIGIN = NAMES

GUARD_TABLE = 'vs_router_tproxy_ipv6_guard'
GUARD_CHAIN = 'forward'

# Network layout (all addresses router-owned are ".1", peers are ".2").
LAN0 = '2001:db8:1::/64'
LAN1 = '2001:db8:2::/64'
WAN0 = '2001:db8:3::/64'
V4LAN0 = '10.212.1'
V4WAN0 = '10.212.3'

ROUTER_LOCAL = '2001:db8:1::1'      # router address on lan0 (local / INPUT)
ROUTER_MGMT = '2001:db8:6::1'       # router-owned management/panel address
FAR_V6 = '2001:db8:99::1'           # far WAN destination (origin loopback)
FAR_V4 = '198.18.0.1'               # far IPv4 WAN destination (origin loopback)


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def run(*args, **kwargs):
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('text', True)
    kwargs.setdefault('timeout', 20)
    return subprocess.run(args, **kwargs)


def ns(name, *args, **kwargs):
    return run('ip', 'netns', 'exec', name, *args, **kwargs)


def ping(name, target, *, v6=True, count=2, timeout=2):
    binary = 'ping6' if v6 else 'ping'
    result = subprocess.run(['ip', 'netns', 'exec', name, binary, '-c', str(count),
                             '-W', str(timeout), target],
                            capture_output=True, text=True, timeout=count * timeout + 5)
    return result.returncode == 0, (result.stdout + result.stderr).strip().splitlines()[-1:]


def validate_fixture(policies):
    require(policies.get('__tproxy_ipv6_guard__') is True,
            'requires opt-in --tproxy-ipv6-guard fixture')
    require(policies.get('ingress') == ['lan0'], 'expected fixture ingress ["lan0"]')
    guard = policies.get('guard')
    require(isinstance(guard, str), 'missing generated guard text')
    require('table inet vs_router_tproxy_ipv6_guard {' in guard,
            'missing generated IPv6 guard table')
    require('type filter hook forward priority -11; policy accept;' in guard,
            'expected generated IPv6 guard priority -11')
    require('meta nfproto != ipv6 return' in guard,
            'expected IPv6-only guard (IPv4 preserved)')
    require('fib daddr type local return' in guard,
            'expected local-destination preservation')
    require('ip6 daddr { fe80::/10, ff00::/8 } return' in guard,
            'expected link-local/multicast preservation')
    require('iifname != { "lan0" } return' in guard,
            'expected unselected-ingress preservation')
    require('counter drop comment "tproxy_ipv6_guard"' in guard,
            'expected single fail-closed drop rule')
    require(guard.count('drop') == 1 and 'accept' not in guard.replace('policy accept', ''),
            'guard must be drop-only')
    require(policies['off'] == f'destroy table inet {GUARD_TABLE}\n',
            'unexpected off text')


def router_link_local():
    state = json.loads(ns(ROUTER, 'ip', '-j', '-6', 'addr', 'show', 'dev', 'lan0').stdout)
    for link in state:
        for info in link.get('addr_info', []):
            if info.get('family') == 'inet6' and info.get('scope') == 'link':
                return info['local']
    raise AssertionError('router lan0 has no link-local IPv6 address')


def guard_drop_count():
    state = json.loads(ns(ROUTER, 'nft', '-j', 'list', 'chain', 'inet',
                          GUARD_TABLE, GUARD_CHAIN).stdout)
    return sum(entry['counter']['packets'] for item in state['nftables']
               for rule in [item.get('rule', {})]
               if rule.get('comment') == 'tproxy_ipv6_guard'
               for entry in rule.get('expr', []) if 'counter' in entry)


def apply_nft(text):
    ns(ROUTER, 'nft', '-c', '-f', '-', input=text)
    ns(ROUTER, 'nft', '-f', '-', input=text)


def build_topology():
    for name in NAMES:
        run('ip', 'netns', 'add', name)
        ns(name, 'ip', 'link', 'set', 'lo', 'up')
    links = (('lan0', CLIENT, LAN0, f'{V4LAN0}.1/24', f'{V4LAN0}.2/24'),
             ('lan1', OTHER, LAN1, None, None),
             ('wan0', ORIGIN, WAN0, f'{V4WAN0}.1/24', f'{V4WAN0}.2/24'))
    for iface, peer, subnet, rv4, pv4 in links:
        ns(ROUTER, 'ip', 'link', 'add', iface, 'type', 'veth', 'peer', 'name',
           'eth0', 'netns', peer)
        ns(ROUTER, 'ip', 'addr', 'add', subnet.replace('::/64', '::1/64'),
           'dev', iface, 'nodad')
        ns(peer, 'ip', 'addr', 'add', subnet.replace('::/64', '::2/64'),
           'dev', 'eth0', 'nodad')
        if rv4:
            ns(ROUTER, 'ip', 'addr', 'add', rv4, 'dev', iface)
            ns(peer, 'ip', 'addr', 'add', pv4, 'dev', 'eth0')
        ns(ROUTER, 'ip', 'link', 'set', iface, 'up')
        ns(peer, 'ip', 'link', 'set', 'eth0', 'up')
    # Router-owned extra local/management address on the selected ingress link.
    ns(ROUTER, 'ip', 'addr', 'add', f'{ROUTER_MGMT}/128', 'dev', 'lan0', 'nodad')
    # Selected client default route; unselected client default route.
    ns(CLIENT, 'ip', '-6', 'route', 'add', 'default', 'via', ROUTER_LOCAL)
    ns(OTHER, 'ip', '-6', 'route', 'add', 'default', 'via', LAN1.replace('::/64', '::1'))
    ns(CLIENT, 'ip', 'route', 'add', 'default', 'via', f'{V4LAN0}.1')
    # Router route to the far WAN destinations (routed transit only).
    ns(ROUTER, 'ip', '-6', 'route', 'add', '2001:db8:99::/64', 'via',
       WAN0.replace('::/64', '::2'))
    ns(ROUTER, 'ip', 'route', 'add', '198.18.0.0/24', 'via', f'{V4WAN0}.2')
    # Origin holds the far destinations and knows the client subnets.
    ns(ORIGIN, 'ip', '-6', 'addr', 'add', f'{FAR_V6}/64', 'dev', 'lo', 'nodad')
    ns(ORIGIN, 'ip', 'addr', 'add', f'{FAR_V4}/32', 'dev', 'lo')
    ns(ORIGIN, 'ip', '-6', 'route', 'add', LAN0, 'via', WAN0.replace('::/64', '::1'))
    ns(ORIGIN, 'ip', '-6', 'route', 'add', LAN1, 'via', WAN0.replace('::/64', '::1'))
    ns(ORIGIN, 'ip', 'route', 'add', f'{V4LAN0}.0/24', 'via', f'{V4WAN0}.1')
    ns(ROUTER, 'sysctl', '-qw', 'net.ipv4.ip_forward=1',
       'net.ipv6.conf.all.forwarding=1')


def cleanup():
    errors = []
    for name in reversed(NAMES):
        result = run('ip', 'netns', 'delete', name)
        if result.returncode not in (0, 1):  # 1 => already gone
            errors.append(f'{name}: {result.stderr.strip()}')
    require(not errors, f'cleanup failed: {errors}')


def main():
    if len(sys.argv) != 2:
        raise SystemExit('VM ONLY: tproxy_ipv6_guard_probe.py generated-ipv6.json')
    policies = json.loads(Path(sys.argv[1]).read_text())
    validate_fixture(policies)
    require(os.geteuid() == 0, 'root required in authorized disposable VM')
    require(sys.flags.optimize == 0, 'run without Python optimization')
    for binary in ('ip', 'nft', 'ping', 'ping6'):
        require(subprocess.run(['which', binary], capture_output=True).returncode == 0,
                f'missing installed binary: {binary}')
    lab = {}
    try:
        build_topology()
        ll = router_link_local()
        print(json.dumps({'topology': NAMES, 'router_link_local': ll}), flush=True)

        # --- baseline: guard absent, every path reachable --------------------
        lab['baseline_selected_wan'] = ping(CLIENT, FAR_V6)[0]
        lab['baseline_selected_local'] = ping(CLIENT, ROUTER_LOCAL)[0]
        lab['baseline_selected_mgmt'] = ping(CLIENT, ROUTER_MGMT)[0]
        lab['baseline_selected_ll'] = ping(CLIENT, f'{ll}%eth0')[0]
        lab['baseline_unselected_wan'] = ping(OTHER, FAR_V6)[0]
        lab['baseline_selected_v4'] = ping(CLIENT, FAR_V4, v6=False)[0]
        require(all(lab.values()), f'baseline unreachable: {lab}')

        # --- guard active ----------------------------------------------------
        apply_nft(policies['guard'])
        before = guard_drop_count()
        lab['guard_selected_wan_blocked'] = not ping(CLIENT, FAR_V6, count=2)[0]
        after = guard_drop_count()
        lab['guard_drop_delta'] = after - before
        require(lab['guard_drop_delta'] > 0, 'guard rule was not reached')
        lab['guard_selected_local_ok'] = ping(CLIENT, ROUTER_LOCAL)[0]
        lab['guard_selected_mgmt_ok'] = ping(CLIENT, ROUTER_MGMT)[0]
        lab['guard_selected_ll_ok'] = ping(CLIENT, f'{ll}%eth0')[0]
        lab['guard_unselected_wan_ok'] = ping(OTHER, FAR_V6)[0]
        lab['guard_selected_v4_ok'] = ping(CLIENT, FAR_V4, v6=False)[0]
        print(json.dumps({'case': 'guard', **lab}), flush=True)
        require(lab['guard_selected_wan_blocked'], 'selected IPv6 escaped to WAN')
        require(lab['guard_selected_local_ok'], 'local IPv6 was blocked')
        require(lab['guard_selected_mgmt_ok'], 'management IPv6 was blocked')
        require(lab['guard_selected_ll_ok'], 'link-local IPv6 was blocked')
        require(lab['guard_unselected_wan_ok'], 'unselected source was affected')
        require(lab['guard_selected_v4_ok'], 'IPv4 tract was broken')

        # --- explicit off ----------------------------------------------------
        apply_nft(policies['off'])
        listed = ns(ROUTER, 'nft', 'list', 'tables').stdout
        lab['off_table_gone'] = GUARD_TABLE not in listed
        lab['off_selected_wan_ok'] = ping(CLIENT, FAR_V6)[0]
        print(json.dumps({'case': 'off', **lab}), flush=True)
        require(lab['off_table_gone'], 'off did not remove the guard table')
        require(lab['off_selected_wan_ok'], 'off did not restore selected IPv6 routing')

        print('PASS: selected IPv6 to WAN is dropped while the guard is active; '
              'local/management/link-local IPv6 and unselected sources and the '
              'IPv4 tract are preserved; explicit off restores routing.', flush=True)
    finally:
        cleanup()


if __name__ == '__main__':
    main()
