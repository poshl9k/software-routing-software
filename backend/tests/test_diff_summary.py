import pytest

from vs_router.api.versions import diff_summary


@pytest.mark.parametrize('area,title,consequence', [
    ('interfaces', 'Сетевые интерфейсы', 'Изменяется сеть или доступ к панели — проверьте доступ к веб-панели после применения.'),
    ('aliases', 'Псевдонимы', None),
    ('dhcp_subnets', 'DHCP', None),
    ('firewall_rules', 'Правила firewall', 'Изменяются правила firewall/NAT — проверьте порядок (первое совпадение решает) и доступ.'),
    ('port_forwards', 'Проброс портов', 'Изменяются правила firewall/NAT — проверьте порядок (первое совпадение решает) и доступ.'),
    ('outbound_nat_mode', 'NAT', 'Изменяются правила firewall/NAT — проверьте порядок (первое совпадение решает) и доступ.'),
    ('outbound_nat', 'NAT', 'Изменяются правила firewall/NAT — проверьте порядок (первое совпадение решает) и доступ.'),
    ('dns', 'DNS', 'Изменяется DNS — проверьте разрешение имён.'),
    ('tunnels', 'Туннели', 'Изменяются туннели/DDNS — проверьте подключения.'),
    ('sites', 'Входящие сайты', 'Изменяются входящие сайты — проверьте сертификаты и порты.'),
    ('ddns', 'DDNS', 'Изменяются туннели/DDNS — проверьте подключения.'),
    ('ssh', 'Доступ по SSH', 'Изменяется доступ по SSH.'),
    ('tproxy', 'Выборочная маршрутизация (TProxy)', None),
    ('proxies', 'Прокси-выходы', None),
    ('rule_sets', 'Источники списков', None),
    ('anti_lockout', 'Доступ к панели', 'Изменяется сеть или доступ к панели — проверьте доступ к веб-панели после применения.'),
    ('panel_port', 'Доступ к панели', 'Изменяется сеть или доступ к панели — проверьте доступ к веб-панели после применения.'),
    ('future_key', 'future_key', None),
])
def test_area_titles_and_consequences(area, title, consequence):
    assert diff_summary([{'op': 'add', 'path': f'/{area}/0', 'after': 'secret'}]) == [{
        'area': area, 'title': title, 'added': 1, 'removed': 0, 'changed': 0,
        'consequences': [consequence] if consequence else [],
    }]


def test_counts_order_skips_schema_and_values():
    changes = [
        {'op': 'replace', 'path': '/dns/servers/0', 'before': 'private-before', 'after': 'private-after'},
        {'op': 'remove', 'path': '/aliases/1', 'before': 'private-before'},
        {'op': 'add', 'path': '/dns/servers/1', 'after': 'private-after'},
        {'op': 'add', 'path': '/aliases/2', 'after': 'private-after'},
        {'op': 'replace', 'path': '/aliases/0', 'before': 'private-before', 'after': 'private-after'},
        {'op': 'replace', 'path': '/schema_version', 'before': 1, 'after': 2},
        {'op': 'replace', 'path': '', 'before': 'private-before', 'after': 'private-after'},
    ]
    expected = [
        {'area': 'aliases', 'title': 'Псевдонимы', 'added': 1, 'removed': 1, 'changed': 1, 'consequences': []},
        {'area': 'dns', 'title': 'DNS', 'added': 1, 'removed': 0, 'changed': 1,
         'consequences': ['Изменяется DNS — проверьте разрешение имён.']},
    ]
    assert diff_summary(changes) == expected
    assert diff_summary(list(reversed(changes))) == expected
    assert diff_summary([]) == []
    assert 'private-' not in str(diff_summary(changes))


def test_unknown_escaped_pointer_is_not_discarded():
    assert diff_summary([{'op': 'remove', 'path': '/a~1b~0c/0', 'before': 123}]) == [{
        'area': 'a/b~c', 'title': 'a/b~c', 'added': 0, 'removed': 1,
        'changed': 0, 'consequences': [],
    }]
