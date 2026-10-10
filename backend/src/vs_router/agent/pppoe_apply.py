"""Typed PPPoE artifact bundle and fixed host-side validation."""
import json
import re
import time
from ..generators import generate_pppoe

FILES = {'pppoe': 'pppoe.json'}
_PEER = re.compile(r'/etc/ppp/peers/vs-router-([A-Za-z][A-Za-z0-9_.-]{0,14})\Z')
_SECRETS = {'/etc/ppp/pap-secrets', '/etc/ppp/chap-secrets'}


def interfaces(bundle):
    files = json.loads(bundle)
    if not isinstance(files, dict):
        raise ValueError('pppoe.invalid_bundle')
    names = []
    for path, content in files.items():
        match = _PEER.fullmatch(path)
        if match:
            names.append(match.group(1))
        elif path not in _SECRETS:
            raise ValueError('pppoe.invalid_bundle')
        if not isinstance(content, str):
            raise ValueError('pppoe.invalid_bundle')
    if (len(set(names)) != len(names) or
            (set(files) & _SECRETS not in (set(), _SECRETS)) or
            (bool(names) != bool(set(files) & _SECRETS))):
        raise ValueError('pppoe.invalid_bundle')
    return files, sorted(names)


def generate(version, key):
    return json.dumps(generate_pppoe(version, key), sort_keys=True)


def ready(executor, names):
    """Require running peers and an IPCP address for each expected PPP link."""
    for name in names:
        if executor.run(['systemctl', 'is-active', '--quiet',
                         f'vs-router-pppoe@{name}.service'], 5).returncode:
            return False
    result = executor.run(['ip', '-j', '-4', 'addr', 'show'], 5)
    routes = executor.run(['ip', '-j', '-4', 'route', 'show'], 5)
    if result.returncode or routes.returncode:
        return False
    try:
        links = json.loads(result.stdout)
        route_table = json.loads(routes.stdout)
        routed = {route.get('dev') for route in route_table
                  if route.get('dev', '').startswith('ppp')}
        return sum(
            link.get('ifname', '').startswith('ppp') and
            link.get('ifname') in routed and
            'LOWER_UP' in link.get('flags', []) and
            any(addr.get('family') == 'inet' and addr.get('local') and
                (addr.get('peer') or addr.get('address')) for addr in link.get('addr_info', []))
            for link in links
        ) >= len(names)
    except (TypeError, ValueError, AttributeError):
        return False


def wait_ready(executor, names, *, timeout=30, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + timeout
    while True:
        if ready(executor, names):
            return True
        remaining = deadline - clock()
        if remaining <= 0:
            return False
        sleep(min(1, remaining))
