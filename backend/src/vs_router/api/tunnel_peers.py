"""Program a saved tunnel's peers on the running device, without a full apply.

Adding or removing one client is additive and reversible, so the peer reaches
the live interface as soon as the draft is saved, while the stored configuration
still carries it and the next apply renders exactly the same set.

Best-effort by design: a draft saved before the tunnel is applied, or with the
agent unreachable, takes effect at the next apply. A peer edit must never fail
the save, so this never raises — the panel learns the outcome from the response.
"""
import logging
import os
import re

from ..secrets import decrypt_secret

log = logging.getLogger(__name__)

# A WireGuard/AmneziaWG key: 32 base64-encoded bytes. The panel only checks that
# the field is non-empty, so a hand-typed key can reach here — and it cannot be
# programmed on the device.
WG_KEY = re.compile(r'^[A-Za-z0-9+/]{43}=$')


def _server_peers(configuration):
    return {tunnel.name: tunnel.peers for tunnel in configuration.tunnels
            if tunnel.role == 'server'}


def _specs(peer, key):
    """The peer as the agent programs it, or None when it cannot be programmed."""
    if not peer.allowed_ips or not WG_KEY.fullmatch(peer.public_key or ''):
        return None
    preshared = None
    if peer.preshared_key is not None:
        try:
            preshared = decrypt_secret(peer.preshared_key, key)
        except Exception:
            return None
    return {'public_key': peer.public_key, 'allowed_ips': list(peer.allowed_ips),
            'preshared_key': preshared}


def live_peers(configuration, previous=None):
    """Sync every server tunnel whose peers changed since ``previous``.

    Returns ``{tunnel: {added: [...], removed: [...], unchanged: [...]}}`` for
    the tunnels that were reached; a tunnel that is not applied is reported as
    ``{tunnel: {'skipped': code}}`` rather than silently ignored.
    """
    from .errors import APIError
    from .versions import agent_call

    before = _server_peers(previous) if previous is not None else {}
    key = os.environ.get('VS_ROUTER_SECRET_KEY', '').encode()
    result = {}
    for tunnel in configuration.tunnels:
        if tunnel.role != 'server':
            continue
        if previous is not None and before.get(tunnel.name) == tunnel.peers:
            continue
        specs, skipped = [], []
        for peer in tunnel.peers:
            spec = _specs(peer, key)
            if spec is None:
                skipped.append(peer.name)
            else:
                specs.append(spec)
        if skipped:
            # Never program a PARTIAL set: the sync removes every peer it is not
            # given, so one unusable peer would silently deprogram the others.
            log.warning('tunnel.peer_not_programmable tunnel=%s peers=%s', tunnel.name, skipped)
            result[tunnel.name] = {'skipped': 'tunnel.peer_not_programmable'}
            continue
        try:
            result[tunnel.name] = agent_call(
                'tunnel_peers_sync', {'interface': tunnel.interface, 'peers': specs})
        except APIError as exc:
            # Not applied yet (or no agent): the next apply installs the peers.
            log.info('tunnel.peers_not_synced tunnel=%s code=%s', tunnel.name, exc.code)
            result[tunnel.name] = {'skipped': exc.code}
        except Exception:
            # The draft is already committed: a peer that cannot be programmed,
            # or an agent whose RPC contract moved on, must not fail the save.
            log.exception('tunnel.peers_sync_failed tunnel=%s', tunnel.name)
            result[tunnel.name] = {'skipped': 'tunnel.peers_not_synced'}
    return result
