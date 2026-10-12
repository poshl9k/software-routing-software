import base64
import json
import os

import pytest
from cryptography.fernet import Fernet

from vs_router.schema import ProxySubscription
from vs_router.secrets import decrypt_secret
from vs_router.agent import downloader
from vs_router.agent.subscription_parse import parse_body, materialize, SubscriptionParseError
from vs_router.agent.subscriptions import fetch, refresh
from vs_router.generators.singbox import _render_outbound, _render_group

KEY = Fernet.generate_key()
LINK = 'vless://uuid@alpha.example:443?security=tls&sni=s.example#Alpha'


@pytest.mark.parametrize('body,protocol', [
    (LINK, 'vless'),
    ('trojan://pass@alpha.example:443#Trojan', 'trojan'),
    ('ss://YWVzLTI1Ni1nY206cGFzcw@alpha.example:8388#SS', 'shadowsocks'),
    ('hysteria2://pass@alpha.example:443#HY', 'hysteria2'),
    ('tuic://uuid:pass@alpha.example:443#TUIC', 'tuic'),
    (base64.b64encode(LINK.encode()).decode(), 'vless'),
    ('proxies:\n  - name: Alpha\n    type: vless\n    server: alpha.example\n    port: 443\n    uuid: uuid\n    tls: true\n', 'vless'),
    (json.dumps({'outbounds': [{'type': 'trojan', 'tag': 'X', 'server': 'alpha.example', 'server_port': 443, 'password': 'pass'}]}), 'trojan'),
    (json.dumps({'vnext': [{'address': 'alpha.example', 'port': 443, 'users': [{'id': 'uuid'}]}]}), 'vless'),
    (json.dumps({'outbounds': [{'protocol': 'vless', 'tag': 'X', 'settings': {'vnext': [{'address': 'alpha.example', 'port': 443, 'users': [{'id': 'uuid'}]}]}, 'streamSettings': {'security': 'tls', 'network': 'tcp'}}]}), 'vless'),
])
def test_formats(body, protocol):
    parsed = parse_body(body, key=KEY)
    assert parsed.members[0].protocol == protocol
    assert parsed.members[0].secret.ciphertext != 'pass'
    assert 'plaintext' not in str(parsed)


def test_stable_tags_secret_and_diff():
    first = parse_body(LINK + '\n# comment\nvmess://opaque', key=KEY)
    second = parse_body(LINK.replace('#Alpha', '#Renamed') + '\ntrojan://pass@two.example:443#Two', key=KEY)
    assert first.skipped == ({'line': 3, 'reason': 'vmess_unsupported'},)
    assert first.members[0].tag == second.members[0].tag
    assert first.members[0].secret != second.members[0].secret
    diff = refresh(first, second)
    assert (len(diff.added), len(diff.updated), len(diff.unchanged), len(diff.orphans)) == (1, 1, 0, 0)
    assert len(refresh(second, first).orphans) == 1
    assert len(refresh(first, parse_body(LINK, key=KEY)).unchanged) == 1
    assert decrypt_secret(first.members[0].secret, KEY) == 'uuid'


def test_filter_active_exclude_and_urltest():
    members = parse_body(LINK + '\ntrojan://pass@two.example:443#Two', key=KEY).members
    sub = ProxySubscription(name='demo', url='', inline=True, inline_content=LINK,
                            filter_include='Alpha|Two', filter_exclude='Two', active_member=members[0].tag)
    outs, groups = materialize(sub, members)
    assert [o.tag for o in outs] == [members[0].tag]
    assert groups[0].outbounds == (members[0].tag,)
    assert materialize(sub.model_copy(update={'excluded_members': (members[0].tag,)}), members) == ([], [])
    _, groups = materialize(sub.model_copy(update={'mode': 'urltest', 'filter_exclude': None,
        'url_test': 'https://example.com/204', 'test_interval_minutes': 2, 'test_tolerance_ms': 50}), members)
    assert groups[0].type == 'urltest' and groups[0].interval_minutes == 2


@pytest.mark.parametrize('pattern', ['(?=Alpha)', '(?<=A)lpha', '(a+)+', r'(a)\1'])
def test_re2_boundary(pattern):
    sub = ProxySubscription(name='demo', url='', inline=True, inline_content=LINK, filter_include=pattern)
    with pytest.raises(SubscriptionParseError, match='filter_not_re2'):
        materialize(sub, parse_body(LINK, key=KEY).members)


def test_line_error_and_limits():
    with pytest.raises(SubscriptionParseError) as err:
        parse_body('# skip\nwrong://password@example.com:443', key=KEY)
    assert err.value.line == 2
    with pytest.raises(SubscriptionParseError, match='too_large'):
        parse_body('x' * (downloader.DEFAULT_MAX_BYTES + 1), key=KEY)


def test_safe_fetch_boundary():
    sub = ProxySubscription(name='demo', url='https://example.org/token?secret=abc')
    with pytest.raises(downloader.DownloadError, match='download.user_authorization_required'):
        fetch(sub, key=KEY)
    seen = []
    def injected(spec, *, transport, resolver):
        seen.append(spec)
        return downloader.FetchResult(url=spec.url, content=LINK, sha256='x', size=len(LINK))
    result = fetch(sub, key=KEY, authorized=True, downloader_fetch=injected)
    assert result.members and seen[0].max_bytes == downloader.DEFAULT_MAX_BYTES
    assert seen[0].timeout == downloader.DEFAULT_TIMEOUT
    assert seen[0].allowed_hosts == frozenset({'example.org'})
    assert fetch(ProxySubscription(name='demo', url='', inline=True, inline_content=LINK), key=KEY).members
    with pytest.raises(SubscriptionParseError, match='headers_unsupported'):
        fetch(sub.model_copy(update={'headers': ('Authorization: Bearer secret',)}), key=KEY, authorized=True, downloader_fetch=injected)


def test_singbox_mixed_groups_transports_endpoints_and_skip():
    fixture = {'outbounds': [
        {'type': 'selector', 'tag': 'Select', 'outbounds': ['A']},
        {'type': 'urltest', 'tag': 'Auto', 'outbounds': ['A']},
        {'type': 'vless', 'tag': 'A', 'server': 'a.example', 'server_port': 443,
         'uuid': 'uuid-a', 'transport': {'type': 'httpupgrade', 'path': '/proxy'},
         'tls': {'enabled': True, 'server_name': 'a.example', 'reality': {'enabled': True, 'public_key': 'abc', 'short_id': '01'}}},
        {'type': 'vmess', 'tag': 'B', 'server': 'b.example', 'server_port': 443,
         'uuid': 'uuid-b', 'transport': {'type': 'ws', 'path': '/ws'}},
        {'type': 'trojan', 'tag': 'C', 'server': 'c.example', 'server_port': 443,
         'password': 'pass-c', 'transport': {'type': 'grpc', 'service_name': 'service'}},
        {'type': 'wireguard', 'tag': 'unsupported', 'server': 'd.example'},
    ], 'endpoints': [
        {'type': 'hysteria2', 'tag': 'E', 'server': 'e.example', 'server_port': 443, 'password': 'pass-e'},
        {'type': 'naive', 'tag': 'N', 'server': 'n.example', 'server_port': 443, 'username': 'user', 'password': 'pass-n'},
        {'type': 'mieru', 'tag': 'M', 'server': 'm.example', 'server_port': 443, 'username': 'user', 'password': 'pass-m'},
    ]}
    body = json.dumps(fixture)
    parsed = parse_body(body, key=KEY)
    assert len(parsed.members) == 6
    assert parsed.skipped == ({'line': 1, 'reason': 'non_server'},
                              {'line': 2, 'reason': 'non_server'},
                              {'line': 6, 'reason': 'subscription.unsupported_protocol'})
    assert parsed.members[0].tag == parse_body(body, key=KEY).members[0].tag
    assert decrypt_secret(parsed.members[0].secret, KEY) == 'uuid-a'
    sub = ProxySubscription(name='owner_sub', url='', inline=True, inline_content=body)
    outs, groups = materialize(sub, parsed.members)
    assert len(outs) == 6 and len(groups) == 1
    assert _render_group(groups[0])['tag'] == 'owner_sub'
    assert _render_group(groups[0])['outbounds'] == [o.tag for o in outs]
    assert [_render_outbound(o).get('transport', {}).get('type') for o in outs[:3]] == ['httpupgrade', 'ws', 'grpc']
    assert _render_outbound(outs[0])['tls']['reality']['public_key'] == 'abc'
    auto = sub.model_copy(update={'mode': 'urltest', 'url_test': 'https://example.com/204'})
    assert _render_group(materialize(auto, parsed.members)[1][0])['type'] == 'urltest'


@pytest.mark.skipif(not os.getenv('VS_ROUTER_TEST_SUBSCRIPTION_URL'), reason='live subscription URL unset')
def test_live_owner_subscription():
    sub = ProxySubscription(name='owner_live', url=os.environ['VS_ROUTER_TEST_SUBSCRIPTION_URL'])
    try:
        parsed = fetch(sub, key=KEY, authorized=True)
    except downloader.DownloadError as exc:
        if exc.code in {'download.resolve_failed', 'download.timeout', 'download.transport_failed'}:
            pytest.skip('network unavailable')
        raise
    outs, groups = materialize(sub, parsed.members)
    assert len(parsed.members) >= 1
    assert len(parsed.skipped) >= 1 or len(groups) >= 1
    assert len(outs) == len(parsed.members) and groups[0].tag == sub.name
    print(f'owner subscription: members={len(parsed.members)} skipped={len(parsed.skipped)} groups={len(groups)}')


def test_downloader_rejects_private_and_redirect():
    sub = ProxySubscription(name='demo', url='https://example.org/token')
    transport = type('T', (), {'fetch': lambda self, **kw: downloader.FetchResponse(302, {'location': 'https://elsewhere.example/'}, b'')})()
    with pytest.raises(downloader.DownloadError, match='forbidden_address'):
        fetch(sub, key=KEY, authorized=True, transport=transport, resolver=lambda _: ['127.0.0.1'])
    with pytest.raises(downloader.DownloadError, match='host_not_authorized'):
        fetch(sub, key=KEY, authorized=True, transport=transport, resolver=lambda _: ['8.8.8.8'])
