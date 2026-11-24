"""A client tunnel picks the WAN gateway its own outer UDP leaves through.

The userspace daemon opens one connected UDP socket per endpoint and keeps the
route resolved at connect time, so the choice is expressed as an endpoint /32
host route placed in the main table before `setconf`. Outer UDP packets carry
no source address at fib-rule time, so segment policy rules never claim them
and a transport gateway may differ from any RF exit gateway on the same link.
Live evidence (2026-11-16, panel stand): with the /32 via the secondary
gateway, tcpdump showed the tunnel's dst MAC pointing at that gateway and the
handshake completed through it; the observed source stayed the interface
primary because the automatic masquerade rewrites it (hence transport_snat).
"""
import pytest
from pathlib import Path
from cryptography.fernet import Fernet

from test_agent_apply import FakeExecutor, FakeFS
from vs_router.agent.apply import ApplyEngine, ApplyError
from vs_router.agent.services import WireGuardReloader
from vs_router.api.configuration import parse_configuration
from vs_router.api.errors import APIError
from vs_router.generators.nftables import generate_nftables
from vs_router.generators.wireguard import generate_wg_bundle
from vs_router.schema import Configuration, ConfigurationVersion, Tunnel
from vs_router.secrets import encrypt_secret

SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}


@pytest.fixture(autouse=True)
def secret_key(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    return key


def document(tunnel_extra):
    tunnel = {'name': 'client_vpn', 'interface': 'wg1', 'role': 'client',
              'protocol': 'wg', 'private_key': {'plaintext': 'PRIVATEKEY='},
              'endpoint': '203.0.113.7:51820', 'server_public_key': 'S' * 44}
    tunnel.update(tunnel_extra)
    return {
        'schema_version': 1,
        'interfaces': [
            {'name': 'lan0', 'zone': 'lan', 'addresses': ['10.10.10.1/24']},
            {'name': 'wan0', 'zone': 'wan',
             'addresses': ['192.168.170.10/16', '192.168.180.10/16']},
            {'name': 'wg1', 'addresses': ['10.66.66.5/32']},
        ],
        'tunnels': [tunnel],
    }


def version(tunnel_extra):
    parsed = parse_configuration(document(tunnel_extra))
    return ConfigurationVersion(configuration=Configuration.model_validate(parsed))


UPLINK = {'interface': 'wan0', 'gateway': '192.168.116.254'}


def test_manifest_carries_the_uplink():
    import json
    manifest = json.loads(generate_wg_bundle(version({'uplink': UPLINK}), {})['manifest.json'])
    assert manifest['wg1']['uplink'] == {'gateway': '192.168.116.254', 'interface': 'wan0'}


def test_manifest_without_uplink_stays_unchanged():
    manifest = generate_wg_bundle(version({}), {})['manifest.json']
    assert 'uplink' not in manifest


def test_uplink_is_client_only():
    with pytest.raises(ValueError):
        Tunnel.model_validate({'name': 'srv', 'interface': 'wg1', 'role': 'server',
                               'protocol': 'wg', 'private_key': SECRET,
                               'listen_port': 51820, 'uplink': UPLINK})


def test_uplink_gateway_must_be_an_address():
    with pytest.raises(ValueError):
        Tunnel.model_validate({'name': 'c', 'interface': 'wg1', 'role': 'client',
                               'protocol': 'wg', 'private_key': SECRET,
                               'endpoint': '203.0.113.7:51820',
                               'server_public_key': 'S' * 44,
                               'uplink': {'interface': 'wan0',
                                          'gateway': 'not-an-address'}})


def test_gateway_outside_the_link_subnets_is_rejected():
    with pytest.raises(APIError) as failure:
        version({'uplink': {'interface': 'wan0', 'gateway': '10.9.9.1'}})
    assert any(detail['message'] == 'tunnel.uplink_gateway_unreachable'
               for detail in failure.value.details), failure.value.details


def test_source_must_belong_to_the_uplink_interface():
    with pytest.raises(APIError) as failure:
        version({'uplink': {'interface': 'wan0', 'gateway': '192.168.116.254',
                            'source': '192.168.170.99'}})
    assert any(detail['message'] == 'tunnel.uplink_source_not_on_interface'
               for detail in failure.value.details), failure.value.details


def test_unknown_uplink_interface_is_rejected():
    with pytest.raises(APIError) as failure:
        version({'uplink': {'interface': 'wan9', 'gateway': '192.168.116.254'}})
    assert any(detail['message'] == 'tunnel.uplink_interface'
               for detail in failure.value.details), failure.value.details


def test_ipv6_endpoint_cannot_use_an_ipv4_gateway():
    with pytest.raises(APIError) as failure:
        version({'uplink': UPLINK, 'endpoint': '[2001:db8::1]:51820'})
    assert any(detail['message'] == 'tunnel.uplink_gateway_family'
               for detail in failure.value.details), failure.value.details


def test_same_endpoint_with_two_transports_is_refused():
    raw = document({'uplink': UPLINK})
    raw['tunnels'].append(dict(document({})['tunnels'][0],
                              name='client_vpn2', interface='wg2',
                              uplink={'interface': 'wan0',
                                      'gateway': '192.168.107.1'}))
    raw['interfaces'].append({'name': 'wg2', 'addresses': ['10.66.66.6/32']})
    with pytest.raises(APIError) as failure:
        Configuration.model_validate(parse_configuration(raw))
    assert any(detail['message'] == 'tunnel.uplink_endpoint_conflict'
               for detail in failure.value.details), failure.value.details


def test_transport_source_is_pinned_before_masquerade():
    text = generate_nftables(version({'uplink': {'interface': 'wan0',
                                                 'gateway': '192.168.116.254',
                                                 'source': '192.168.180.10'}}))
    snat = [line for line in text.splitlines() if 'transport_snat' in line]
    masquerade = [line for line in text.splitlines() if 'counter masquerade' in line]
    assert snat and masquerade
    assert 'ip saddr 192.168.180.10' in snat[0]
    assert text.index(snat[0]) < text.index(masquerade[0])


def test_transport_without_source_emits_no_snat():
    text = generate_nftables(version({'uplink': UPLINK}))
    assert 'transport_snat' not in text


class Harness:
    def __init__(self):
        self.fs, self.executor = FakeFS(), FakeExecutor()
        self.reloader = WireGuardReloader(
            executor=self.executor, filesystem=self.fs,
            config_dir=Path('/etc/vs-router/wireguard'))
        self.fs.write(Path('/etc/vs-router/wireguard/t.conf'),
                      '[Interface]\nPrivateKey = x\n\n[Peer]\n'
                      'Endpoint = 203.0.113.7:51820\n')


ENTRY = {'file': 't.conf', 'protocol': 'wg', 'addresses': ['10.66.66.5/32'],
         'routes': [], 'endpoint': '203.0.113.7:51820'}


def test_the_transport_route_is_installed_before_setconf():
    harness = Harness()
    entry = {**ENTRY, 'uplink': {'interface': 'wan0',
                                 'gateway': '192.168.116.254',
                                 'source': '192.168.180.10'}}
    harness.reloader.configure('wg1', entry, 'wg')
    calls = [call[0] for call in harness.executor.calls]
    route = calls.index(['ip', '-4', 'route', 'replace', '203.0.113.7/32',
                         'via', '192.168.116.254', 'dev', 'wan0',
                         'src', '192.168.180.10'])
    setconf = next(i for i, argv in enumerate(calls)
                   if argv[:2] == ['wg', 'setconf'])
    assert route < setconf


def test_an_unresolvable_endpoint_fails_the_transport():
    from vs_router.agent.services import SubprocessExecutor  # noqa: F401 (smoke)

    harness = Harness()
    with pytest.raises(ApplyError) as caught:
        harness.reloader.transport_route(None, {'gateway': '192.168.116.254'})
    assert caught.value.code == 'wireguard.endpoint_unresolved'


def test_a_dropped_uplink_retires_the_route():
    harness = Harness()
    previous = {**ENTRY, 'uplink': {'interface': 'wan0',
                                    'gateway': '192.168.116.254'},
                'endpoint_ip': '203.0.113.7'}
    harness.reloader.reconcile_transport({'wg1': previous}, {'wg1': dict(ENTRY)}, {})
    calls = [call[0] for call in harness.executor.calls]
    assert ['ip', '-4', 'route', 'del', '203.0.113.7/32'] in calls


def test_an_unchanged_uplink_keeps_its_route():
    harness = Harness()
    uplink = {'interface': 'wan0', 'gateway': '192.168.116.254'}
    previous = {**ENTRY, 'uplink': uplink, 'endpoint_ip': '203.0.113.7'}
    harness.reloader.reconcile_transport(
        {'wg1': previous}, {'wg1': {**ENTRY, 'uplink': uplink}}, {})
    assert not [call for call in harness.executor.calls
                if call[0][:3] == ['ip', '-4', 'route', 'del']]


def test_one_endpoint_behind_two_transports_fails():
    harness = Harness()
    manifest = {
        'wg1': {**ENTRY, 'uplink': {'interface': 'wan0',
                                    'gateway': '192.168.116.254'}},
        'wg2': {**ENTRY, 'file': 't2.conf',
                'uplink': {'interface': 'wan0', 'gateway': '192.168.107.1'}},
    }
    with pytest.raises(ApplyError) as caught:
        harness.reloader.reconcile_transport({}, manifest,
                                             {'wg1': '203.0.113.7',
                                              'wg2': '203.0.113.7'})
    assert caught.value.code == 'wireguard.endpoint_route_conflict'


def test_an_unchanged_bundle_with_uplink_still_reasserts_the_transport_route():
    """A byte-identical wireguard bundle cannot prove the /32 survived.

    The transport route lives in the main table, outside every applied artifact.
    A rollback (or an earlier version without an uplink) can remove it while the
    generated bytes stay equal to an older confirmed version; skipping the
    wireguard phase then leaves both tunnels with `network is unreachable`.
    """
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    reloads = []
    reloader = WireGuardReloader(executor=executor, filesystem=fs,
                                 config_dir=Path('/etc/vs-router/wireguard'),
                                 kernel_probe=lambda *_: False)
    engine.reload_commands = {'wireguard': lambda path: (reloads.append(path), reloader(path))[1]}
    snapshot = dict(version({'uplink': UPLINK}).model_dump(mode='json'), id=1, status='draft')

    assert engine.apply_version(snapshot).status == 'confirmed'
    assert len(reloads) == 1
    assert engine.apply_version(dict(snapshot, id=2)).status == 'confirmed'
    assert len(reloads) == 2
    assert any(call[0] == ['ip', '-4', 'route', 'replace', '203.0.113.7/32',
                           'via', '192.168.116.254', 'dev', 'wan0']
               for call in executor.calls)
