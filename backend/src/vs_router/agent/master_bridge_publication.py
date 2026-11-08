"""Host-owned, allowlisted publication of the master-only node bridge.

The marker is root-owned. The adapter overlays its routes on every Caddy
installation (including boot restore and rollback), never on versioned data.
"""
from copy import deepcopy
from ipaddress import ip_address
from pathlib import Path

MARKER = Path('/etc/vs-router/master-bridge-publication.json')
SOCKET = 'unix//run/vs-router/web/master.sock'
PATH = '/internal/master/*'


def publish_bridge(config: dict, setting: dict) -> dict:
    """Fail closed if the root marker cannot target an existing TLS panel name."""
    try:
        hostname = setting['hostname']
        source = ip_address(setting['source_ip'])
        if not isinstance(hostname, str) or not hostname:
            raise ValueError('hostname required')
        if hostname not in config['apps']['tls']['certificates']['automate']:
            raise ValueError('hostname has no panel certificate')
        routes = config['apps']['http']['servers']['management']['routes']
        if not isinstance(routes, list):
            raise ValueError('management routes missing')
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('master bridge publication: invalid marker or hostname') from exc

    result = deepcopy(config)
    routes = result['apps']['http']['servers']['management']['routes']
    # A re-install may consume the already published JSON. Replace rather than
    # duplicate our exact routes if the source IP is changed by the operator.
    routes[:] = [route for route in routes if not (
        route.get('handle') == [{'handler': 'reverse_proxy',
                                 'upstreams': [{'dial': SOCKET}]}]
        or (route.get('match') == [{'host': [hostname], 'path': [PATH]}]
            and route.get('handle') == [{'handler': 'static_response', 'status_code': 403}])
    )]
    matcher = {'host': [hostname], 'path': [PATH]}
    mask = 32 if source.version == 4 else 128
    routes[:0] = [
        {'match': [{**matcher, 'remote_ip': {'ranges': [f'{source}/{mask}']}}],
         'handle': [{'handler': 'reverse_proxy', 'upstreams': [{'dial': SOCKET}]}]},
        {'match': [matcher], 'handle': [{'handler': 'static_response', 'status_code': 403}]},
    ]
    return result
