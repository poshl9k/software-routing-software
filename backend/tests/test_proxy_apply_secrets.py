"""The preview is redacted while the gated agent artifact has live credentials."""
import json
import os
import stat

import pytest
from cryptography.fernet import Fernet

from vs_router.agent import tproxy_apply
from vs_router.agent.apply import LocalFileSystem
from vs_router.agent.subscription_parse import materialize, parse_body
from vs_router.generators.singbox import PLACEHOLDER_UUID, generate_singbox
from vs_router.schema import ConfigurationVersion, ProxySubscription


def test_owner_shape_preview_and_agent_secret_injection():
    key = Fernet.generate_key()
    uuid = 'b35057c4-c68d-40d9-9c15-5b51e53b5fd1'
    body = json.dumps({'outbounds': [{'type': 'vless', 'tag': 'Owner',
        'server': 'edge.example', 'server_port': 443, 'uuid': uuid,
        'transport': {'type': 'httpupgrade', 'host': 'front.example', 'path': '/up'},
        'tls': {'enabled': True, 'server_name': 'front.example', 'insecure': False,
                'utls': {'enabled': True, 'fingerprint': 'chrome'},
                'reality': {'enabled': True, 'public_key': 'synthetic-key', 'short_id': '01'}}}]})
    parsed = parse_body(body, key=key)
    assert len(parsed.members) == 1 and not parsed.skipped
    sub = ProxySubscription(name='sub', url='', inline=True, inline_content=body)
    outbounds, groups = materialize(sub, parsed.members)
    base = ConfigurationVersion()
    proxies = base.configuration.proxies.model_copy(update={
        'enabled': True, 'outbounds': tuple(outbounds), 'groups': tuple(groups)})
    version = base.model_copy(update={'configuration': base.configuration.model_copy(
        update={'proxies': proxies})})
    preview = generate_singbox(version)
    redacted = next(o for o in preview['outbounds'] if o['type'] == 'vless')
    assert redacted['uuid'] == PLACEHOLDER_UUID
    assert uuid not in json.dumps(preview)
    assert redacted['transport'] == {'type': 'httpupgrade', 'host': 'front.example', 'path': '/up'}
    assert redacted['tls']['server_name'] == 'front.example'
    assert redacted['tls']['utls']['fingerprint'] == 'chrome'
    assert redacted['tls']['reality']['short_id'] == '01'
    actual = next(o for o in generate_singbox(version, tproxy_apply._secret_provider(key))['outbounds']
                  if o['type'] == 'vless')
    assert actual['uuid'] == uuid
    with pytest.raises(ValueError, match='secret.decryption_failed'):
        generate_singbox(version, tproxy_apply._secret_provider(Fernet.generate_key()))
    assert generate_singbox(version) == preview
    from test_tproxy_dns_integration import enabled_version
    offline = enabled_version()
    offline = offline.model_copy(update={'configuration': offline.configuration.model_copy(
        update={'proxies': proxies})})
    staged = tproxy_apply.build_artifacts(offline, key=key)['singbox']
    assert uuid in staged and PLACEHOLDER_UUID not in staged
    assert uuid not in tproxy_apply.build_artifacts(offline)['singbox']


def test_apply_engine_writes_decrypted_singbox_artifact(monkeypatch):
    from test_tproxy_dns_integration import enabled_version, recording_validators
    from test_agent_apply import FakeFS, FakeExecutor
    from vs_router.agent.apply import APPLIED_DIR, ApplyEngine
    from vs_router.secrets import encrypt_secret
    from vs_router.schema import ProxyOutbound

    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    uuid = 'b35057c4-c68d-40d9-9c15-5b51e53b5fd1'
    version = enabled_version()
    proxy = ProxyOutbound(tag='edge', type='vless', server='edge.example', port=443,
                          secret=encrypt_secret(uuid, key), tls=True)
    proxies = version.configuration.proxies.model_copy(update={'enabled': True, 'outbounds': (proxy,)})
    version = version.model_copy(update={'configuration': version.configuration.model_copy(
        update={'proxies': proxies})})
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor())
    engine._verify_tproxy_tables = lambda expected=None: None  # native nft readiness tested separately
    seen = []

    def inspect(path):
        seen.append(json.loads(fs.read(path))['outbounds'])
        raise ValueError('synthetic.stop')

    engine.reload_commands['singbox'] = inspect
    result = engine.apply_version(version, validators=recording_validators([]))
    assert result.status == 'failed'
    assert len(seen) == 1, (result, fs.files.keys())
    assert next(o for o in seen[0] if o['tag'] == 'edge')['uuid'] == uuid
    assert APPLIED_DIR / 'singbox.json' not in fs.files


def test_password_outbounds_and_obfs_are_private_until_apply():
    from vs_router.secrets import encrypt_secret
    from vs_router.schema import ProxyOutbound

    key = Fernet.generate_key()
    naive = ProxyOutbound(tag='naive1', type='naive', server='edge.example', port=443,
                          username='alice', secret=encrypt_secret('synthetic-pass', key))
    hy = ProxyOutbound(tag='hy2', type='hysteria2', server='edge.example', port=443,
                       tls=True, secret=encrypt_secret('synthetic-hy', key),
                       obfs_type='salamander', obfs_password=encrypt_secret('synthetic-obfs', key))
    base = ConfigurationVersion()
    proxies = base.configuration.proxies.model_copy(update={
        'enabled': True, 'outbounds': (naive, hy)})
    version = base.model_copy(update={'configuration': base.configuration.model_copy(
        update={'proxies': proxies})})
    redacted = generate_singbox(version)['outbounds']
    assert next(o for o in redacted if o['tag'] == 'naive1')['password'] == 'redacted'
    assert next(o for o in redacted if o['tag'] == 'hy2')['obfs']['password'] == 'redacted'
    live = generate_singbox(version, tproxy_apply._secret_provider(key))['outbounds']
    assert next(o for o in live if o['tag'] == 'naive1')['password'] == 'synthetic-pass'
    hy2 = next(o for o in live if o['tag'] == 'hy2')
    assert hy2['password'] == 'synthetic-hy'
    assert hy2['obfs'] == {'type': 'salamander', 'password': 'synthetic-obfs'}


def test_local_singbox_file_is_root_owned_and_private(tmp_path, monkeypatch):
    fs = LocalFileSystem()
    path = tmp_path / 'singbox.json'
    calls = []
    original = os.fchown

    def fake_chown(fd, uid, gid):
        calls.append((uid, gid))
        # Non-root CI cannot chown; the production call is still mandatory.

    monkeypatch.setattr(os, 'fchown', fake_chown)
    fs.write(path, '{"password":"synthetic"}')
    assert calls == [(0, 0)]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == '{"password":"synthetic"}'
    monkeypatch.setattr(os, 'fchown', original)
