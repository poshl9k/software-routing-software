"""Routing policy contract and profile safety, without host networking."""
import json
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet

from test_agent_apply import FakeExecutor, FakeFS
from vs_router.agent import apply as apply_mod
from vs_router.agent.apply import ApplyEngine, ApplyError, host_files
from vs_router.api.configuration import parse_configuration, structural_diff, validate
from vs_router.api.errors import APIError
from vs_router.api.versions import diff_summary
from vs_router.schema import Configuration, ConfigurationVersion
from vs_router.secrets import encrypt_secret


SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}


def document():
    return {
        'schema_version': 1,
        'subscribers': [{'name': 'alice'}, {'name': 'bob'}],
        'interfaces': [{'name': 'wg0'}, {'name': 'wg1'}],
        'tunnels': [
            {'name': 'server_vpn', 'interface': 'wg0', 'role': 'server',
             'protocol': 'wg', 'listen_port': 51820, 'private_key': SECRET,
             'peers': [{'name': 'phone', 'public_key': 'P' * 44,
                        'subscriber': 'alice'},
                       {'name': 'laptop', 'public_key': 'Q' * 44,
                        'subscriber': 'bob'},
                       {'name': 'transport', 'public_key': 'R' * 44}]},
            {'name': 'client_vpn', 'interface': 'wg1', 'role': 'client',
             'protocol': 'wg', 'private_key': SECRET,
             'endpoint': 'vpn.example:51820', 'server_public_key': 'S' * 44},
        ],
        'proxies': {'enabled': False, 'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                    'groups': [{'tag': 'group1', 'type': 'selector',
                                'outbounds': ['proxy1']}]},
    }


def rule(name='site', **overrides):
    return {'name': name, 'ip_cidr': ['203.0.113.0/24'], **overrides}


def invalid(document_value, code):
    with pytest.raises(APIError) as failure:
        parse_configuration(document_value)
    assert failure.value.code == 'configuration.invalid'
    assert any(detail['message'] == code for detail in failure.value.details), failure.value.details


def test_criterion_1_roundtrip_diff_and_tproxy_isolation():
    data = document()
    data['routing_rules'] = [
        rule('straight'),
        rule('proxied', subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
             domain_suffix=['example.org'], exit={'kind': 'outbound', 'tag': 'proxy1'}),
        rule('tunneled', exit={'kind': 'tunnel', 'name': 'client_vpn'}),
    ]
    parsed = parse_configuration(data)
    assert parsed.schema_version == 1
    assert [r.exit.kind for r in parsed.routing_rules] == ['direct', 'outbound', 'tunnel']
    assert [r.subject.kind for r in parsed.routing_rules] == ['server', 'device', 'server']
    assert parsed.routing_rules[0].exit.tag is None
    assert parsed.routing_rules[0].subject.peer is None
    assert parse_configuration(json.loads(parsed.model_dump_json())) == parsed
    before = Configuration()
    changes = structural_diff(before.model_dump(mode='json'), parsed.model_dump(mode='json'))
    assert any(c['path'].startswith('/routing_rules/') for c in changes)
    assert next(row for row in diff_summary(changes) if row['area'] == 'routing_rules')['title'] == 'Правила маршрутизации'
    assert parsed.tproxy == before.tproxy
    assert not any(c['path'].startswith('/tproxy') for c in changes)


def test_criterion_2_destination_required():
    data = document()
    data['routing_rules'] = [{'name': 'empty'}]
    invalid(data, 'routing.destination_required')


@pytest.mark.parametrize('target,code', [
    ({'kind': 'outbound', 'tag': 'missing'}, 'routing.outbound_reference'),
    ({'kind': 'outbound', 'tag': 'group1'}, 'routing.outbound_reference'),
    ({'kind': 'outbound', 'tag': 'direct'}, 'routing.outbound_reference'),
    ({'kind': 'tunnel', 'name': 'missing'}, 'routing.tunnel_reference'),
])
def test_criterion_3_missing_or_non_outbound_reference(target, code):
    data = document()
    data['routing_rules'] = [rule(exit=target)]
    invalid(data, code)


def test_criterion_3_disabled_proxies_still_declare_outbound():
    data = document()
    data['routing_rules'] = [rule(exit={'kind': 'outbound', 'tag': 'proxy1'})]
    assert parse_configuration(data).proxies.enabled is False


def test_criterion_4_server_tunnel_cannot_be_exit():
    data = document()
    data['routing_rules'] = [rule(exit={'kind': 'tunnel', 'name': 'server_vpn'})]
    invalid(data, 'routing.tunnel_client_required')


@pytest.mark.parametrize('subject,code', [
    ({'kind': 'device', 'subscriber': 'missing', 'peer': 'phone'}, 'routing.subscriber_reference'),
    ({'kind': 'device', 'subscriber': 'alice', 'peer': 'missing'}, 'routing.device_reference'),
    ({'kind': 'device', 'subscriber': 'alice', 'peer': 'laptop'}, 'routing.device_reference'),
    ({'kind': 'device', 'subscriber': 'alice', 'peer': 'transport'}, 'routing.device_reference'),
])
def test_criterion_5_device_reference_requires_own_bound_peer(subject, code):
    data = document()
    data['routing_rules'] = [rule(subject=subject)]
    invalid(data, code)


def test_criterion_5_same_peer_name_other_subscriber_does_not_resolve():
    data = document()
    data['tunnels'][0]['peers'].append(
        {'name': 'shared', 'public_key': 'T' * 44, 'subscriber': 'bob'})
    data['routing_rules'] = [rule(subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'shared'})]
    invalid(data, 'routing.device_reference')
    data['tunnels'][0]['peers'].append(
        {'name': 'shared', 'public_key': 'U' * 44, 'subscriber': 'alice'})
    assert parse_configuration(data).routing_rules[0].subject.subscriber == 'alice'


def test_criterion_5_ambiguous_only_within_own_subscriber():
    data = document()
    data['tunnels'][1]['role'] = 'server'
    data['tunnels'][1].pop('endpoint')
    data['tunnels'][1].pop('server_public_key')
    data['tunnels'][1]['listen_port'] = 51821
    data['tunnels'][1]['peers'] = [
        {'name': 'phone', 'public_key': 'T' * 44, 'subscriber': 'alice'}]
    assert parse_configuration(data).tunnels[1].peers[0].name == 'phone'
    data['routing_rules'] = [rule(subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'})]
    invalid(data, 'routing.device_ambiguous')


@pytest.mark.parametrize('destinations', [
    {'domain_suffix': ['example.org']},
    {'domain_exact': ['example.org']},
    {'ip_cidr': ['2001:db8::/32'], 'domain_exact': ['example.org']},
])
def test_criterion_6_own_dns_device_rejects_domain_destinations(destinations):
    data = document()
    data['tunnels'][0]['peers'][0]['dns_mode'] = 'own'
    data['routing_rules'] = [{'name': 'domain', 'subject': {
        'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'}, **destinations}]
    invalid(data, 'routing.domain_rule_own_resolvers')


def test_criterion_6_ip_only_panel_dns_and_server_rules_valid():
    data = document()
    data['tunnels'][0]['peers'][0]['dns_mode'] = 'own'
    data['routing_rules'] = [
        rule('ipv6', subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
             ip_cidr=['2001:db8::/32']),
        rule('panel', subject={'kind': 'device', 'subscriber': 'bob', 'peer': 'laptop'},
             ip_cidr=[], domain_suffix=['example.org']),
        rule('server', ip_cidr=[], domain_exact=['example.org']),
    ]
    assert len(parse_configuration(data).routing_rules) == 3


def test_criterion_7_router_apply_refuses_device_policy_before_effects(monkeypatch):
    data = document()
    data['routing_rules'] = [rule(subject={
        'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'})]
    assert parse_configuration(data).routing_rules[0].subject.kind == 'device'
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: 'router')
    monkeypatch.setattr(apply_mod.shutil, 'which', lambda name: f'/usr/sbin/{name}')
    fs, executor = FakeFS(), FakeExecutor()
    management = Mock(side_effect=AssertionError('management probe must not run'))
    panel_probe = Mock(side_effect=AssertionError('panel probe must not run'))
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which),
                         management_provider=management, panel_probe=panel_probe)
    with pytest.raises(ApplyError) as failure:
        engine.apply_version({'id': 1, 'profile': 'router', 'configuration': data})
    assert failure.value.code == 'profile.subscribers_not_supported'
    assert fs.files == {}
    assert executor.calls == []
    management.assert_not_called()
    panel_probe.assert_not_called()

    data['subscribers'] = []
    for peer in data['tunnels'][0]['peers']:
        peer.pop('subscriber', None)
    with pytest.raises(ValueError, match='routing.subscriber_reference'):
        engine.apply_version({'id': 2, 'profile': 'router', 'configuration': data})
    assert fs.files == {}
    assert executor.calls == []
    management.assert_not_called()
    panel_probe.assert_not_called()


def test_criterion_8_legacy_document_parses_validates_and_applies(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    old = {'schema_version': 1, 'interfaces': [{'name': 'wg0'}],
           'tunnels': [{'name': 'vpn', 'interface': 'wg0', 'role': 'server',
                        'protocol': 'wg', 'listen_port': 51820,
                        'private_key': encrypt_secret('A' * 43 + '=', key).model_dump(),
                        'peers': [{'name': 'phone', 'public_key': 'P' * 44}]}]}
    parsed = parse_configuration(old)
    assert parsed.schema_version == 1
    assert parsed.routing_rules == ()
    assert parsed.tunnels[0].peers[0].dns_mode == 'panel'
    assert validate(old)['valid'] is True
    assert ConfigurationVersion.model_validate({'id': 1, 'configuration': old}).configuration == parsed
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: 'router')
    monkeypatch.setattr(apply_mod.shutil, 'which', lambda name: f'/usr/sbin/{name}')
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which))
    result = engine.apply_version({'id': 1, 'profile': 'router', 'configuration': old})
    assert result.status == 'confirmed', result.error
    assert executor.calls
    assert fs.files
    assert json.loads(fs.read(apply_mod.APPLIED_DIR / 'snapshot.json'))['configuration'] == old


@pytest.mark.parametrize('exit_value,code', [
    ({'kind': 'outbound'}, 'routing.outbound_tag_required'),
    ({'kind': 'tunnel'}, 'routing.tunnel_name_required'),
    ({'kind': 'direct', 'tag': 'proxy1'}, 'routing.exit_fields_unexpected'),
    ({'kind': 'direct', 'name': 'client_vpn'}, 'routing.exit_fields_unexpected'),
    ({'kind': 'outbound', 'tag': 'proxy1', 'name': 'client_vpn'}, 'routing.exit_fields_unexpected'),
    ({'kind': 'tunnel', 'name': 'client_vpn', 'tag': 'proxy1'}, 'routing.exit_fields_unexpected'),
])
def test_exit_shape(exit_value, code):
    data = document()
    data['routing_rules'] = [rule(exit=exit_value)]
    invalid(data, code)


@pytest.mark.parametrize('subject,code', [
    ({'kind': 'device'}, 'routing.device_required'),
    ({'kind': 'device', 'subscriber': 'alice'}, 'routing.device_required'),
    ({'kind': 'device', 'peer': 'phone'}, 'routing.device_required'),
    ({'kind': 'server', 'subscriber': 'alice'}, 'routing.subject_fields_unexpected'),
    ({'kind': 'server', 'peer': 'phone'}, 'routing.subject_fields_unexpected'),
])
def test_subject_shape(subject, code):
    data = document()
    data['routing_rules'] = [rule(subject=subject)]
    invalid(data, code)


@pytest.mark.parametrize('destination,code', [
    ({'ip_cidr': ['not-a-cidr']}, 'routing.ip_cidr_invalid'),
    ({'domain_suffix': ['bad domain']}, 'routing.domain_invalid'),
    ({'domain_exact': ['bad/domain']}, 'routing.domain_invalid'),
])
def test_destination_shape(destination, code):
    data = document()
    data['routing_rules'] = [{'name': 'invalid', **destination}]
    invalid(data, code)


def test_duplicate_rule_names():
    data = document()
    data['routing_rules'] = [rule(), rule()]
    invalid(data, 'routing.duplicate_name')
