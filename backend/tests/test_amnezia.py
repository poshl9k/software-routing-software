"""Amnezia `vpn://` export.

The document shape is taken from a real export of the Amnezia app (an
AmneziaWG 3.1 container). That blob is deliberately not stored here — it
carries live private keys — so these tests pin the envelope and the structure
instead, and prove the reader accepts an app-shaped document.
"""
import base64
import json
import zlib

import pytest
from cryptography.fernet import Fernet

from vs_router.generators.amnezia import (CONTAINER, DNS_PLACEHOLDER, amnezia_uri,
                                          decode_document, encode_document, tunnel_dns,
                                          DEFAULT_PRIMARY_DNS, DEFAULT_SECONDARY_DNS)
from vs_router.generators.wireguard import generate_wg_bundle
from vs_router.schema import ConfigurationVersion, Peer
from vs_router.secrets import encrypt_secret


@pytest.fixture
def config(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())

    def secret(value):
        return encrypt_secret(value, key).model_dump()

    tunnel = dict(
        name='vpn', interface='wg0', role='server', protocol='awg',
        private_key=secret(base64.b64encode(bytes(range(32))).decode()),
        listen_port=44517, endpoint='rg1.example.net', keepalive='25-35',
        allowed_ips=['0.0.0.0/0', '::/0'],
        obfuscation={'Jc': 5, 'Jmin': 10, 'Jmax': 50, 'S1': 28, 'S2': 132,
                     'S3': 43, 'S4': 12, 'H1': 1, 'H2': 2, 'H3': 3, 'H4': 4,
                     'ContentPaddingAddition': '10-100', 'RekeyAfterTime': '100-120',
                     'RekeyTimeout': '3-7', 'RejectAfterTime': '150-180',
                     'KeepaliveTimeout': '5-15', 'MaxHandshakeAttempts': '15-20'},
        header_protection_key=secret('HEADERPROTECTIONKEY='),
        random_trailers=True, disable_cookies=True,
        peers=[dict(name='phone', public_key='CLIENTPUBLICKEY=',
                    private_key=secret(base64.b64encode(bytes(range(32, 64))).decode()),
                    preshared_key=secret('PRESHAREDKEY='),
                    allowed_ips=['10.66.66.2/32'])],
    )
    return ConfigurationVersion.model_validate(dict(id=1, configuration=dict(
        interfaces=[dict(name='wan0', zone='wan', addresses=['203.0.113.1/24']),
                    dict(name='wg0', zone='lan', addresses=['10.66.66.1/24'])],
        tunnels=[tunnel])))


def uri_for(config, **kwargs):
    tunnel = config.configuration.tunnels[0]
    return amnezia_uri(tunnel, tunnel.peers[0], config.configuration, **kwargs)


def test_reader_accepts_an_app_shaped_export(monkeypatch):
    """The envelope the app emits (uint32 length + zlib, base64url, no padding)
    is exactly what the reader resolves — built here from an app-shaped document
    rather than a real one, which would carry live keys."""
    body = json.dumps({'format_version': '1', 'hostName': 'rg1.example.net',
                       'containers': [{'container': 'amnezia-awg2',
                                       'awg': {'port': '44517', 'protocol_version': '3.1'}}]},
                      separators=(',', ':')).encode()
    envelope = base64.urlsafe_b64encode(len(body).to_bytes(4, 'big') + zlib.compress(body)).decode().rstrip('=')
    document = decode_document('vpn://' + envelope)
    assert document['containers'][0]['container'] == 'amnezia-awg2'
    assert document['containers'][0]['awg']['protocol_version'] == '3.1'


def test_uri_matches_the_app_container_shape(config):
    document = decode_document(uri_for(config))
    assert document['format_version'] == '1'
    assert document['hostName'] == 'rg1.example.net'
    assert document['dns1'] == '10.66.66.1' and document['dns2'] == DEFAULT_SECONDARY_DNS
    assert document['defaultContainer'] == CONTAINER
    container = document['containers'][0]
    assert container['container'] == CONTAINER
    awg = container['awg']
    # Interface parameters travel as strings, I1-I5 always present, plus the
    # app's own container metadata.
    assert awg['Jc'] == '5' and awg['S4'] == '12'
    assert awg['RekeyAfterTime'] == '100-120' and awg['RandomTrailers'] == 'on'
    assert awg['HeaderProtectionKey'] == 'HEADERPROTECTIONKEY='
    assert all(awg[key] == '' for key in ('I1', 'I2', 'I3', 'I4', 'I5'))
    assert awg['port'] == '44517' and awg['transport_proto'] == 'udp'
    assert awg['protocol_version'] == '3.1'
    assert awg['subnet_address'] == '10.66.66.0' and awg['subnet_cidr'] == '24'
    inner = json.loads(awg['last_config'])
    # An unset signature key stays out of last_config, as in the app's own export.
    assert not any(key in inner for key in ('I1', 'I2', 'I3', 'I4', 'I5'))
    assert inner['client_ip'] == '10.66.66.2'
    assert inner['client_pub_key'] == 'CLIENTPUBLICKEY='
    assert inner['clientId'] == 'CLIENTPUBLICKEY='
    assert inner['server_pub_key'] == inner['server_pub_key'].strip()
    assert inner['psk_key'] == 'PRESHAREDKEY='
    assert inner['allowed_ips'] == ['0.0.0.0/0', '::/0']
    assert inner['hostName'] == 'rg1.example.net'
    assert inner['port'] == 44517 and inner['persistent_keep_alive'] == '25-35'


def test_inner_conf_is_a_full_tunnel_with_dns_placeholders(config):
    awg = decode_document(uri_for(config))['containers'][0]['awg']
    conf = json.loads(awg['last_config'])['config']
    assert conf.startswith('[Interface]\n')
    assert f'DNS = {DNS_PLACEHOLDER}' in conf
    assert 'Address = 10.66.66.2/32' in conf
    assert '[Peer]' in conf
    # The app orders [Peer] as key, psk, allowed IPs, endpoint, keepalive.
    order = [conf.index(f'{k} =') for k in
             ('PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive')]
    assert order == sorted(order), conf
    assert 'Endpoint = rg1.example.net:44517' in conf
    assert 'PersistentKeepalive = 25-35' in conf


def test_export_is_deterministic_and_shares_the_client_private_key(config):
    first, second = uri_for(config), uri_for(config)
    assert first == second
    awg = decode_document(first)['containers'][0]['awg']
    inner = json.loads(awg['last_config'])
    # The same private key the .conf bundle ships for this peer, so a client can
    # use either export without a key mismatch.
    bundle = generate_wg_bundle(config, {})
    assert inner['client_priv_key'] in bundle['vpn.peer-phone.conf']
    assert 'DNS = 10.66.66.1, 1.1.1.1\n' in bundle['vpn.peer-phone.conf']


def test_tunnel_dns_overrides_and_validation(config):
    data = json.loads(config.model_dump_json())
    tunnel = data['configuration']['tunnels'][0]
    tunnel['dns_servers'] = ['2001:db8::53', '10.66.66.53']
    version = ConfigurationVersion.model_validate(data)
    selected = version.configuration.tunnels[0]
    assert tunnel_dns(selected, version.configuration) == ('2001:db8::53', '10.66.66.53')
    assert (decode_document(uri_for(version))['dns1'], decode_document(uri_for(version))['dns2']) == ('2001:db8::53', '10.66.66.53')
    assert 'DNS = 2001:db8::53, 10.66.66.53\n' in generate_wg_bundle(version, {})['vpn.peer-phone.conf']
    tunnel['dns_servers'] = ['10.66.66.53']
    version = ConfigurationVersion.model_validate(data)
    assert tunnel_dns(version.configuration.tunnels[0], version.configuration) == ('10.66.66.53', DEFAULT_SECONDARY_DNS)
    assert tunnel_dns(version.configuration.tunnels[0], version.configuration, dns1='9.9.9.9', dns2='8.8.8.8') == ('9.9.9.9', '8.8.8.8')
    for servers, error in [(['bad'], 'tunnel.dns_server_invalid'),
                           (['1.1.1.1', '2.2.2.2', '3.3.3.3'], 'tunnel.dns_server_limit')]:
        tunnel['dns_servers'] = servers
        with pytest.raises(ValueError, match=error):
            ConfigurationVersion.model_validate(data)


def test_client_dns_defaults_and_server_only(config):
    data = json.loads(config.model_dump_json())
    tunnel = data['configuration']['tunnels'][0]
    tunnel.update(role='client', peers=[], endpoint='rg1.example.net:44517',
                  server_public_key='SERVER', dns_servers=['1.1.1.1'])
    with pytest.raises(ValueError, match='tunnel.dns_servers_server_only'):
        ConfigurationVersion.model_validate(data)
    tunnel['dns_servers'] = []
    version = ConfigurationVersion.model_validate(data)
    assert tunnel_dns(version.configuration.tunnels[0], version.configuration) == (DEFAULT_PRIMARY_DNS, DEFAULT_SECONDARY_DNS)


def test_dns_and_description_can_be_overridden(config):
    document = decode_document(uri_for(config, dns1='172.29.172.254', dns2='1.0.0.1',
                                       description='Сервер 1', mtu=1420))
    assert (document['dns1'], document['dns2']) == ('172.29.172.254', '1.0.0.1')
    assert document['description'] == 'Сервер 1'
    assert json.loads(document['containers'][0]['awg']['last_config'])['mtu'] == '1420'


def test_client_and_wireguard_tunnels_are_out_of_scope(config):
    data = json.loads(config.model_dump_json())
    tunnel = data['configuration']['tunnels'][0]
    tunnel.update(role='client', peers=[], endpoint='rg1.example.net:44517',
                  server_public_key='SERVER', allowed_ips=['0.0.0.0/0'], open_port=False)
    version = ConfigurationVersion.model_validate(data)
    client = version.configuration.tunnels[0]
    with pytest.raises(ValueError, match='amnezia.role_unsupported'):
        amnezia_uri(client, Peer(name='phone', public_key='K'), version.configuration,
                    dns1='10.66.66.1', dns2='1.0.0.1')

    wireguard = json.loads(config.model_dump_json())
    wireguard['configuration']['tunnels'][0]['protocol'] = 'wg'
    version = ConfigurationVersion.model_validate(wireguard)
    server = version.configuration.tunnels[0]
    with pytest.raises(ValueError, match='amnezia.role_unsupported'):
        amnezia_uri(server, server.peers[0], version.configuration,
                    dns1='10.66.66.1', dns2='1.0.0.1')


def test_unresolved_endpoint_is_rejected(config):
    data = json.loads(config.model_dump_json())
    data['configuration']['tunnels'][0]['endpoint'] = None
    data['configuration']['interfaces'][0]['addresses'] = []
    version = ConfigurationVersion.model_validate(data)
    tunnel = version.configuration.tunnels[0]
    with pytest.raises(ValueError, match='amnezia.endpoint_unresolved'):
        amnezia_uri(tunnel, tunnel.peers[0], version.configuration,
                    dns1='10.66.66.1', dns2='1.0.0.1')


def test_peer_without_its_own_private_key_is_rejected(config):
    data = json.loads(config.model_dump_json())
    data['configuration']['tunnels'][0]['peers'][0]['private_key'] = None
    version = ConfigurationVersion.model_validate(data)
    tunnel = version.configuration.tunnels[0]
    with pytest.raises(ValueError, match='amnezia.peer_private_key_required'):
        amnezia_uri(tunnel, tunnel.peers[0], version.configuration,
                    dns1='10.66.66.1', dns2='1.0.0.1')


def test_encode_decode_roundtrip_preserves_unicode():
    document = {'description': 'Сервер 1', 'containers': []}
    assert decode_document(encode_document(document)) == document
