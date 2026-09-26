import pytest
from cryptography.fernet import Fernet
from vs_router.api.configuration import parse_configuration, redact
from vs_router.api.errors import APIError
from vs_router.secrets import decrypt_secret


def payload():
    return {'interfaces': [{'name': 'enp1s0', 'type': 'physical', 'zone': 'wan'},
                           {'name': 'wg0', 'type': 'physical', 'zone': 'vpn'}],
            'tunnels': [{'name': 'client', 'interface': 'wg0', 'role': 'client',
                         'protocol': 'wg', 'endpoint': 'example.org:51820',
                         'server_public_key': 'public', 'private_key': {'plaintext': 'new-key'}}],
            'sites': [{'name': 'web', 'hostname': 'example.org', 'upstream': 'localhost:443',
                       'certificate_mode': 'manual', 'certificate': {'plaintext': 'cert'},
                       'private_key': {'plaintext': 'cert-key'}}],
            'ddns': [{'name': 'home', 'provider': 'cloudflare', 'hostname': 'example.org',
                      'zone': 'example.org', 'api_token': {'plaintext': 'token'}}]}


def test_encrypt_and_restore(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    config = parse_configuration(payload())
    assert decrypt_secret(config.tunnels[0].private_key, key) == 'new-key'
    assert decrypt_secret(config.sites[0].certificate, key) == 'cert'
    assert decrypt_secret(config.ddns[0].api_token, key) == 'token'
    saved = config.model_dump(mode='json')
    assert 'plaintext' not in str(saved)
    assert parse_configuration(redact(saved), saved) == config


def test_missing_encryption_key_does_not_accept_plaintext(monkeypatch):
    monkeypatch.delenv('VS_ROUTER_SECRET_KEY', raising=False)
    with pytest.raises(APIError) as error:
        parse_configuration(payload())
    assert error.value.code == 'secret.encryption_unavailable'
    assert error.value.details == []
