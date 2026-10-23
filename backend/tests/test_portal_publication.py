from vs_router.management import portal_names, publication_names, Management


def _management(**overrides):
    base = dict(interface='eth0', mac='02:00:00:00:00:01', address='92.51.36.131/24',
                mode='single-uplink', hostname='92.51.36.131.nip.io')
    base.update(overrides)
    return Management(**base)


def test_portal_names_reserve_first():
    m = _management(custom_hostname='panel.example.com')
    # The portal's own domain is DERIVED from the panel's custom hostname by
    # the ``portal.`` prefix — one field serves both publications (ADR-0032).
    assert portal_names(m) == ('portal.92.51.36.131.nip.io', 'portal.panel.example.com')


def test_portal_names_empty_custom():
    m = _management()
    assert portal_names(m) == ('portal.92.51.36.131.nip.io',)


def test_portal_names_dedup():
    # A custom domain that already IS the reserve name collapses to one entry.
    m = _management(custom_hostname='92.51.36.131.nip.io')
    assert portal_names(m) == ('portal.92.51.36.131.nip.io',)


def test_panel_names_unchanged_by_portal():
    m = _management(custom_hostname='panel.example.com')
    assert publication_names(m) == ('92.51.36.131.nip.io', 'panel.example.com')


def test_caddy_portal_route_and_acme_subjects():
    from vs_router.schema import ConfigurationVersion, Configuration
    from vs_router.generators.caddy import generate_caddy_json
    version = ConfigurationVersion(id=1, status='confirmed', configuration=Configuration())
    management = _management(custom_hostname='panel.example.com')
    json = generate_caddy_json(version, management)
    servers = json['apps']['http']['servers']
    routes = servers['management']['routes']
    # First route: host-matched portal names to the portal socket.
    assert routes[0]['match'] == [{'host': ['portal.92.51.36.131.nip.io', 'portal.panel.example.com']}]
    assert routes[0]['handle'][0]['upstreams'] == [{'dial': 'unix//run/vs-router/portal/portal.sock'}]
    # Panel routes are host-bound to the panel's names, never a catch-all.
    for entry in routes[1:]:
        matchers = entry.get('match') or []
        assert matchers and all('host' in matcher for matcher in matchers)
    automate = json['apps']['tls']['certificates']['automate']
    assert 'portal.92.51.36.131.nip.io' in automate and '92.51.36.131.nip.io' in automate
    policies = json['apps']['tls']['automation']['policies']
    subjects = policies[0]['subjects']
    assert {'portal.92.51.36.131.nip.io', 'portal.panel.example.com'} <= set(subjects)


def test_caddy_without_custom_still_publishes_portal_reserve():
    from vs_router.schema import ConfigurationVersion, Configuration
    from vs_router.generators.caddy import generate_caddy_json
    version = ConfigurationVersion(id=1, status='confirmed', configuration=Configuration())
    management = _management()
    json = generate_caddy_json(version, management)
    routes = json['apps']['http']['servers']['management']['routes']
    assert routes[0]['match'] == [{'host': ['portal.92.51.36.131.nip.io']}]
