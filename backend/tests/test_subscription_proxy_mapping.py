import json

from cryptography.fernet import Fernet

from vs_router.agent.subscription_parse import materialize, parse_body
from vs_router.schema import ProxySubscription
from vs_router.secrets import decrypt_secret


def test_vless_share_options_and_skips():
    key = Fernet.generate_key()
    body = ('vless://uuid@edge.example:443?security=reality&sni=front.example&pbk=public&sid=01'
            '&type=grpc&serviceName=relay&flow=xtls-rprx-vision&fp=chrome#Relay')
    member = parse_body(body, key=key).members[0]
    outbound = materialize(ProxySubscription(name='sub', url='', inline=True, inline_content=body), [member])[0][0]
    assert outbound.transport == {'type': 'grpc', 'service_name': 'relay'}
    assert outbound.reality_public_key == 'public'
    assert outbound.tls_server_name == 'front.example'
    assert outbound.flow == 'xtls-rprx-vision'
    assert outbound.tls_utls_fingerprint == 'chrome'
    assert decrypt_secret(outbound.secret, key) == 'uuid'
    assert 'uuid' not in repr(member)

    parsed = parse_body(json.dumps({'outbounds': [
        {'type': 'vless', 'server': 'edge.example', 'server_port': 443, 'uuid': 'id',
         'transport': {'type': 'xhttp'}},
        {'type': 'mieru', 'server': 'edge.example', 'server_port': 443,
         'username': 'user', 'password': 'password'},
    ]}), key=key)
    assert parsed.members == ()
    assert [row['reason'] for row in parsed.skipped] == [
        'subscription.unsupported_xhttp', 'subscription.unsupported_mieru']


def test_hysteria_obfs_is_encrypted():
    key = Fernet.generate_key()
    body = json.dumps({'outbounds': [{'type': 'hysteria2', 'server': 'edge.example',
        'server_port': 443, 'password': 'main-secret',
        'obfs': {'type': 'salamander', 'password': 'obfs-secret'}}]})
    member = parse_body(body, key=key).members[0]
    assert decrypt_secret(member.secret, key) == 'main-secret'
    assert decrypt_secret(member.obfs_password, key) == 'obfs-secret'
    assert 'obfs-secret' not in repr(member)
