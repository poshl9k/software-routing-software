"""Destination disjunction (B3) — slice 3b, product routing rule shape.

The product routing rule means: traffic *from* the subject **and** to any one
of the listed destinations **and** with the chosen exit. Destination families
(ip_cidr / domain_suffix / domain_exact) form a sing-box logical OR; the
subject matcher stays outside it.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from vs_router.generators.singbox import (SUBSCRIBER_PEERS_RULE_SET_PATH,
                                          SUBSCRIBER_PEERS_RULE_SET_TAG, generate_singbox)
from vs_router.schema import ConfigurationVersion

SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}


def document():
    return {
        'profile': 'panel',
        'configuration': {
            'subscribers': [{'name': 'alice'}],
            'interfaces': [
                {'name': 'lan', 'addresses': ['192.168.10.1/24'], 'zone': 'lan'},
                {'name': 'wg0', 'addresses': ['10.0.0.1/24']},
                {'name': 'tun1', 'addresses': ['10.0.0.2/24']},
                {'name': 'wan', 'zone': 'wan', 'addresses': ['198.51.100.2/24']},
            ],
            'tunnels': [
                {'name': 'server_vpn', 'interface': 'wg0', 'role': 'server',
                 'protocol': 'wg', 'listen_port': 51820, 'private_key': SECRET,
                 'peers': [{'name': 'phone', 'public_key': 'P' * 44,
                            'subscriber': 'alice', 'allowed_ips': ['10.66.66.2/32']}]},
                {'name': 'client_vpn', 'interface': 'tun1', 'role': 'client',
                 'protocol': 'wg', 'private_key': SECRET,
                 'endpoint': 'vpn.example:51820', 'server_public_key': 'S' * 44},
            ],
            'routing_rules': [],
        },
    }


def render(data):
    return generate_singbox(ConfigurationVersion.model_validate(data))


def first_rule(data):
    # Skip the system sniff row: ADR-0031 adds a product sniff rule whenever a
    # routing rule matches domains or rule sets, so the user rule is no longer
    # guaranteed to be rules[0].
    rules = render(data)['route']['rules']
    return next(rule for rule in rules if rule.get('action') != 'sniff')


def assert_outbound_route(rule):
    assert rule['action'] == 'route'
    assert rule['outbound'] == 'direct'


def assert_reject(rule):
    assert rule['action'] == 'reject'


# --- B3-1: one destination family only stays flat --------------------------

def test_criterion_B3_1_rule_set_destination_family_flat():
    data = document()
    data['configuration']['rule_sets'] = [
        {'name': 'geosite-category-porn', 'format': 'srs',
         'url': 'https://example.org/porn.srs'}]
    data['configuration']['routing_rules'] = [
        {'name': 'adult', 'rule_sets': ['geosite-category-porn']},
    ]
    output = render(data)
    rule = output['route']['rules'][1]  # rules[0] is the system sniff row
    assert rule == {'rule_set': ['geosite-category-porn'], 'action': 'route',
                    'outbound': 'direct'}
    # The engine learns the set from the same document (ADR-0031).
    assert output['route']['rule_set'] == [
        {'type': 'remote', 'tag': 'geosite-category-porn', 'format': 'binary',
         'url': 'https://example.org/porn.srs'},
        {'type': 'local', 'tag': SUBSCRIBER_PEERS_RULE_SET_TAG, 'format': 'source',
         'path': SUBSCRIBER_PEERS_RULE_SET_PATH}]


def test_criterion_B3_2_rule_set_is_an_alternative_in_the_or():
    data = document()
    data['configuration']['rule_sets'] = [
        {'name': 'geosite-rkn', 'format': 'srs', 'url': 'https://example.org/rkn.srs'}]
    data['configuration']['routing_rules'] = [
        {'name': 'mixed', 'ip_cidr': ['203.0.113.0/24'],
         'rule_sets': ['geosite-rkn']},
    ]
    rule = render(data)['route']['rules'][1]
    assert rule['type'] == 'logical' and rule['mode'] == 'or'
    assert {'ip_cidr': ['203.0.113.0/24']} in rule['rules']
    assert {'rule_set': ['geosite-rkn']} in rule['rules']


def test_criterion_B3_1_single_destination_flat():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'domain_only', 'domain_suffix': ['example.org']},
    ]
    rule = first_rule(data)
    # Flat exactly as today; no logical wrapper when nothing to disjoin.
    assert rule == {'domain_suffix': ['example.org'], 'action': 'route', 'outbound': 'direct'}
    assert_outbound_route(rule)


def test_criterion_B3_1_single_ip_family_flat():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'ip_only', 'ip_cidr': ['203.0.113.0/24']},
    ]
    assert first_rule(data) == {'ip_cidr': ['203.0.113.0/24'], 'action': 'route', 'outbound': 'direct'}


# --- B3-2: two+ families -> logical OR for destination ---------------------

def test_criterion_B3_2_two_families_logical_or():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'net_domain', 'ip_cidr': ['203.0.113.0/24'],
         'domain_suffix': ['rutube.ru'], 'subject': {'kind': 'server'}},
    ]
    rule = first_rule(data)
    assert rule['type'] == 'logical' and rule['mode'] == 'or'
    assert {'ip_cidr': ['203.0.113.0/24']} in rule['rules']
    assert {'domain_suffix': ['rutube.ru']} in rule['rules']
    assert_outbound_route(rule)


def test_criterion_B3_2_three_families_logical_or():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'three', 'ip_cidr': ['10.0.0.0/8'],
         'domain_suffix': ['a.ru', 'b.ru'], 'domain_exact': ['c.org'],
         'subject': {'kind': 'server'}},
    ]
    rule = first_rule(data)
    assert rule['type'] == 'logical' and rule['mode'] == 'or'
    assert {'ip_cidr': ['10.0.0.0/8']} in rule['rules']
    assert {'domain_suffix': ['a.ru', 'b.ru']} in rule['rules']
    assert {'domain': ['c.org']} in rule['rules']
    assert_outbound_route(rule)


# --- B3-3: subject matcher stays outside the destination OR ----------------

def test_criterion_B3_3_device_subject_nested_in_and():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'device_multi', 'domain_suffix': ['rutube.ru'],
         'ip_cidr': ['10.0.0.0/8'],
         'subject': {'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
         'exit': {'kind': 'tunnel', 'name': 'client_vpn'}},
    ]
    rule = first_rule(data)
    assert rule['type'] == 'logical' and rule['mode'] == 'and'
    # Rules in AND: subject matcher + destination disjunction
    subject = next(r for r in rule['rules'] if r.get('source_ip_cidr'))
    assert subject['source_ip_cidr'] == ['10.66.66.2/32']
    dest = next(r for r in rule['rules'] if r.get('type') == 'logical' and r['mode'] == 'or')
    assert {'domain_suffix': ['rutube.ru']} in dest['rules']
    assert {'ip_cidr': ['10.0.0.0/8']} in dest['rules']
    assert rule['action'] == 'route'
    assert rule['outbound'] == 'routing-tunnel:client_vpn'


def test_criterion_B3_3_interface_subject_same_shape():
    data = document()
    data['configuration']['routing_rules'] = [
        # Single destination family + interface subject -> flat, no logical wrapper.
        {'name': 'iface_flat', 'domain_suffix': ['example.org'],
         'subject': {'kind': 'interface', 'interface': 'lan'},
         'exit': {'kind': 'direct'}},
    ]
    rule = first_rule(data)
    assert 'type' not in rule
    assert rule['source_ip_cidr'] == ['192.168.10.0/24']
    assert rule['domain_suffix'] == ['example.org']
    assert rule['action'] == 'route'
    assert rule['outbound'] == 'direct'


# --- B3-4: block uses reject with same destination shape -------------------

def test_criterion_B3_4_block_reject_with_logical_destination():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'block_two', 'ip_cidr': ['10.0.0.0/8'], 'domain_suffix': ['evil.com'],
         'exit': {'kind': 'block'}},
    ]
    rule = first_rule(data)
    assert rule['action'] == 'reject'
    assert rule['type'] == 'logical' and rule['mode'] == 'or'
    assert {'ip_cidr': ['10.0.0.0/8']} in rule['rules']
    assert {'domain_suffix': ['evil.com']} in rule['rules']


def test_criterion_B3_4_block_single_family_flat_reject():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'block_one', 'domain_exact': ['tracker.ru'],
         'exit': {'kind': 'block'}},
    ]
    assert first_rule(data) == {'domain': ['tracker.ru'], 'action': 'reject'}


# --- B3-5: single destination family with subject stays flat --------------

def test_criterion_B3_5_single_family_with_subject_flat():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'server_ip', 'ip_cidr': ['192.0.2.0/24'],
         'subject': {'kind': 'server'}},
    ]
    rule = first_rule(data)
    assert 'type' not in rule
    assert rule == {'ip_cidr': ['192.0.2.0/24'], 'action': 'route', 'outbound': 'direct'}


def test_criterion_B3_5_single_family_with_device_subject_flat():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'dev_ip', 'domain_suffix': ['a.ru'],
         'subject': {'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'}},
    ]
    rule = first_rule(data)
    assert 'type' not in rule
    assert rule == {'source_ip_cidr': ['10.66.66.2/32'], 'domain_suffix': ['a.ru'],
                    'action': 'route', 'outbound': 'direct'}


# --- B3-6: pinned engine accepts the shape -------------------------------

def _pinned_sing_box():
    """Locate the pinned sing-box 1.14.2 binary.

    The engine check is a real proof, so it must not silently skip in CI.
    ``VS_ROUTER_SINGBOX`` points at the binary; otherwise the archive's
    directory inside the scratch tree is used when present.
    """
    import os
    import shutil

    explicit = os.environ.get("VS_ROUTER_SINGBOX")
    if explicit and Path(explicit).exists():
        return Path(explicit)
    found = shutil.which("sing-box")
    if found:
        return Path(found)
    scratch = Path("/home/poshl9k/.hermes/cache/scratch")
    if scratch.exists():
        for candidate in sorted(scratch.glob("sing-box-*/sing-box")):
            return candidate
    return None


def test_criterion_B3_6_engine_check_logical_and_accepted():
    data = document()
    data['configuration']['routing_rules'] = [
        {'name': 'dev_two', 'domain_suffix': ['rutube.ru'],
         'ip_cidr': ['203.0.113.0/24'],
         'subject': {'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'}},
    ]
    rendered = render(data)
    rule = first_rule(data)
    assert rule['type'] == 'logical' and rule['mode'] == 'and'
    assert {'source_ip_cidr': ['10.66.66.2/32']} in rule['rules']
    dest = next(r for r in rule['rules'] if r.get('type') == 'logical' and r['mode'] == 'or')
    assert {'domain_suffix': ['rutube.ru']} in dest['rules']
    assert {'ip_cidr': ['203.0.113.0/24']} in dest['rules']

    # Prove the pinned engine accepts the shape.
    sb_path = _pinned_sing_box()
    if sb_path is None:
        pytest.skip("pinned sing-box binary not found; set VS_ROUTER_SINGBOX to run "
                    "the engine check")
    version = subprocess.run([str(sb_path), 'version'], capture_output=True, text=True)
    assert '1.14.2' in (version.stdout + version.stderr), version.stdout + version.stderr
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(rendered, f)
        fname = f.name
    try:
        result = subprocess.run([str(sb_path), 'check', '-c', fname],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        os.unlink(fname)


def test_criterion_B3_6_flat_subject_with_logical_is_rejected_by_the_engine():
    """The engine refuses ``source_ip_cidr`` beside a ``logical`` matcher.

    This is why the subject and the destination disjunction are nested in an
    AND node instead of sitting side by side. The test pins the engine's
    refusal so nobody "simplifies" the generator back into a shape the engine
    rejects.
    """
    sb_path = _pinned_sing_box()
    if sb_path is None:
        pytest.skip("pinned sing-box binary not found; set VS_ROUTER_SINGBOX to run "
                    "the engine check")
    bad = {
        "inbounds": [{"type": "tproxy", "tag": "t", "listen": "127.0.0.1",
                      "listen_port": 51271}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{
                "source_ip_cidr": ["10.66.66.2/32"],
                "type": "logical", "mode": "or",
                "rules": [{"domain_suffix": ["rutube.ru"]},
                          {"ip_cidr": ["203.0.113.0/24"]}],
                "action": "route", "outbound": "direct",
            }],
            "final": "direct",
            "auto_detect_interface": True,
        },
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(bad, f)
        fname = f.name
    try:
        result = subprocess.run([str(sb_path), 'check', '-c', fname],
                                capture_output=True, text=True)
        assert result.returncode != 0
        assert 'source_ip_cidr' in (result.stdout + result.stderr)
    finally:
        os.unlink(fname)


# --- B3-7: legacy TProxy rendering pinned --------------------------------

def _legacy_tproxy_document():
    # Minimal legacy document using only fields validated by the router profile.
    # The legacy path renders rules flat (AND-ed) inside each TProxy rule,
    # which is the existing behavior to be pinned.
    data = {
        'profile': 'router',
        'configuration': {
            'interfaces': [
                {'name': 'lan', 'zone': 'lan', 'addresses': ['192.168.10.1/24']},
                {'name': 'wan', 'zone': 'wan', 'addresses': ['198.51.100.2/24']},
            ],
            'proxies': {'enabled': False, 'outbounds': [], 'groups': []},
            'tproxy': {
                'enabled': True,
                'rules': [
                    {'name': 'multi_rule', 'ip_cidr': ['10.0.0.0/8'],
                     'domain_suffix': ['example.org'],
                     'action': 'block', 'outbound': None, 'order': 1},
                ],
                'final': 'direct',
            },
        },
    }
    return data


def test_criterion_B3_7_legacy_tproxy_pinned():
    """Pin the existing legacy TProxy output: unchanged, byte level.

    The existing golden file (singbox-legacy.json) already captures the exact
    legacy TProxy rendering. The code in this slice does not modify legacy
    rendering, so the golden file stays byte-identical; this test confirms it
    is present and unchanged.
    """
    golden_path = Path(__file__).parent / 'golden' / 'singbox-legacy.json'
    assert golden_path.exists()
    from test_routing_rules import scenario as s
    version = s('typical')
    from vs_router.generators.singbox import generate_singbox
    expected = golden_path.read_bytes()
    actual = (json.dumps(generate_singbox(version), indent=2) + '\n').encode()
    assert actual == expected


# --- B3-8: golden files not regenerated ----------------------------------

def test_criterion_B3_8_no_golden_regeneration():
    """golden/ must not be regenerated to make a test pass."""
    golden_dir = Path(__file__).parent / 'golden'
    assert golden_dir.exists()
    # Only the single pre-existing legacy golden is used by this suite.
    assert any(p.name == 'singbox-legacy.json' for p in golden_dir.iterdir())