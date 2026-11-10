"""Host-owned, allowlisted publication of the master-only node bridge.

The marker is root-owned. The adapter overlays its routes on every Caddy
installation (including boot restore and rollback), never on versioned data.
"""
from copy import deepcopy
import json
from ipaddress import ip_address
from pathlib import Path

MARKER = Path('/etc/vs-router/master-bridge-publication.json')
SOCKET = 'unix//run/vs-router/web/master.sock'
PATH = '/internal/master/*'
LIVE_CONFIG = Path('/etc/caddy/caddy.json')


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


def publication_status(filesystem, snapshot):
    """Report host publication state without claiming bearer authentication."""
    from ..generators.caddy import deserialize_caddy

    try:
        bundle = deserialize_caddy(filesystem.read(snapshot))
        base = json.loads(bundle['caddy.json'])
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return {'publication_state': 'unavailable'}

    state = 'absent'
    expected = base
    try:
        marker = filesystem.read(MARKER)
    except FileNotFoundError:
        marker = None
    except (OSError, UnicodeError):
        return {'publication_state': 'unavailable'}
    if marker is not None:
        try:
            setting = json.loads(marker)
        except (TypeError, ValueError):
            state = 'invalid_marker'
        else:
            try:
                expected = publish_bridge(base, setting)
                state = 'configured_on_disk'
            except (ValueError, TypeError, KeyError):
                state = 'incompatible'

    try:
        live = json.loads(filesystem.read(LIVE_CONFIG))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {'publication_state': 'unavailable'}
    if live != expected:
        return {'publication_state': 'drift'}
    return {'publication_state': state}


def configure_publication(filesystem, snapshot, setting, reload):
    """Install a marker and reload Caddy without overwriting runtime drift.

    The current live JSON must match the applied bundle plus its existing valid
    marker. A failed reload restores the previous marker and panel config.
    """
    from ..generators.caddy import deserialize_caddy

    try:
        bundle = deserialize_caddy(filesystem.read(snapshot))
        base = json.loads(bundle['caddy.json'])
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        raise ValueError('master_bridge.configuration_unavailable') from None
    try:
        normalized = {'hostname': setting['hostname'],
                      'source_ip': str(ip_address(setting['source_ip']))}
        candidate = publish_bridge(base, normalized)
    except (OSError, TypeError, ValueError, KeyError):
        raise ValueError('master_bridge.publication_invalid') from None

    try:
        previous_marker = filesystem.read(MARKER)
    except FileNotFoundError:
        previous_marker = None
    except (OSError, UnicodeError):
        raise ValueError('master_bridge.marker_unavailable') from None
    try:
        old_setting = json.loads(previous_marker) if previous_marker is not None else None
    except (TypeError, ValueError):
        # The reloader treats malformed host metadata as absent; allow an
        # authenticated administrator to repair it through the same flow.
        old_setting = None

    expected = base
    if old_setting is not None:
        try:
            expected = publish_bridge(base, old_setting)
        except (ValueError, TypeError, KeyError):
            # Old snapshots can no longer contain the marker's TLS hostname;
            # CaddyReloader deliberately drops that optional route.
            expected = base
    try:
        live = json.loads(filesystem.read(LIVE_CONFIG))
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError('master_bridge.caddy_unavailable') from None
    # Accept the exact requested candidate as a recoverable partial state. A
    # prior attempt may have written it before marker restoration or reload
    # failed; unrelated runtime edits still fail closed.
    candidate_is_live = live == candidate
    if live != expected and not candidate_is_live:
        raise ValueError('master_bridge.caddy_drift')

    try:
        filesystem.write(MARKER, json.dumps(normalized, sort_keys=True))
        reload(snapshot)
        if json.loads(filesystem.read(LIVE_CONFIG)) != candidate:
            raise ValueError('master_bridge.caddy_verify_failed')
    except Exception as exc:
        try:
            if previous_marker is None:
                filesystem.remove(MARKER)
            else:
                filesystem.write(MARKER, previous_marker)
            reload(snapshot)
            if json.loads(filesystem.read(LIVE_CONFIG)) != expected:
                raise ValueError('master_bridge.restore_failed')
        except Exception:
            raise ValueError('master_bridge.restore_failed') from None
        if isinstance(exc, ValueError) and str(exc).startswith('master_bridge.'):
            raise
        raise ValueError('master_bridge.publication_failed') from None
    return {'published': True, **normalized}
