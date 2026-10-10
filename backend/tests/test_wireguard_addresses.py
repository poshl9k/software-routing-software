"""Stable, set-independent WG/AWG address allocation."""
import pytest

from vs_router.generators.wireguard import (
    _hash_slot, SUBNET_SLOTS, materialize_addresses, peer_address,
    tunnel_addresses, tunnel_index,
)
from vs_router.schema import Configuration, EncryptedSecret

KEY = EncryptedSecret(ciphertext='gAAAAplaceholder')


def config(names=('middle',), peers=('zoe', 'mary')):
    return Configuration.model_validate({
        'interfaces': [{'name': f'wg{n}', 'zone': 'lan'} for n in names],
        'tunnels': [{'name': n, 'interface': f'wg{n}', 'role': 'server',
                     'protocol': 'wg', 'private_key': KEY, 'listen_port': 51820,
                     'peers': [{'name': p, 'public_key': 'test'} for p in peers]}
                    for n in names],
    })


def allocated(configuration):
    tunnel = next(t for t in configuration.tunnels if t.name == 'middle')
    return (tunnel_addresses(tunnel, configuration),
            {p.name: peer_address(tunnel, p, configuration) for p in tunnel.peers})


def test_add_remove_unrelated_tunnel_preserves_interface_and_peers():
    base = config()
    expected = allocated(base)
    assert allocated(config(('aaa', 'middle'))) == expected
    assert allocated(config(('middle', 'zzz'))) == expected
    assert allocated(config(('zzz', 'middle', 'aaa'))) == expected
    assert allocated(config(('middle',), ('mary', 'zoe'))) == expected


def test_fresh_config_deterministic_and_materialized_idempotent():
    one = config()
    two = config()
    assert allocated(one) == allocated(two)
    filled = materialize_addresses(one)
    assert materialize_addresses(filled) == filled
    assert next(i for i in filled.interfaces if i.name == 'wgmiddle').addresses
    assert all(p.allowed_ips for p in filled.tunnels[0].peers)


def test_explicit_addresses_win():
    original = config()
    interface = original.interfaces[0].model_copy(update={'addresses': ('192.0.2.1/24',)})
    tunnel = original.tunnels[0]
    peer = tunnel.peers[0].model_copy(update={'allowed_ips': ('192.0.2.77/32',)})
    tunnel = tunnel.model_copy(update={'peers': (peer, *tunnel.peers[1:])})
    explicit = original.model_copy(update={'interfaces': (interface,), 'tunnels': (tunnel,)})
    filled = materialize_addresses(explicit)
    assert filled.interfaces[0].addresses == ('192.0.2.1/24',)
    assert filled.tunnels[0].peers[0].allowed_ips == ('192.0.2.77/32',)


def test_tunnel_hash_collision_raises_not_shared_address():
    first = 'middle'
    second = next(f'other{n}' for n in range(1000)
                  if _hash_slot(f'other{n}', SUBNET_SLOTS) == _hash_slot(first, SUBNET_SLOTS))
    c = config((first, second), ())
    with pytest.raises(ValueError, match='^wireguard.address_collision$'):
        tunnel_index(c.tunnels[0], c)
    with pytest.raises(ValueError, match='^wireguard.address_collision$'):
        materialize_addresses(c)


def test_peer_hash_collision_raises():
    first = 'mary'
    second = next(f'peer{n}' for n in range(2000)
                  if _hash_slot(f'peer{n}', 253) == _hash_slot(first, 253))
    c = config(peers=(first, second))
    with pytest.raises(ValueError, match='^wireguard.address_collision$'):
        materialize_addresses(c)


def test_small_subnet_stays_usable_and_explicit_tunnel_does_not_collide():
    c = config(peers=('mary',))
    interface = c.interfaces[0].model_copy(update={'addresses': ('192.0.2.1/30',)})
    c = c.model_copy(update={'interfaces': (interface,)})
    assert peer_address(c.tunnels[0], c.tunnels[0].peers[0], c) == ['192.0.2.2/32']
    other = next(f'other{n}' for n in range(1000)
                 if _hash_slot(f'other{n}', SUBNET_SLOTS) == _hash_slot('middle', SUBNET_SLOTS))
    with_other = config(('middle', other), ())
    explicit = with_other.interfaces[0].model_copy(update={'addresses': ('192.0.2.1/24',)})
    with_other = with_other.model_copy(update={'interfaces': (explicit, with_other.interfaces[1])})
    assert tunnel_addresses(with_other.tunnels[1], with_other)
