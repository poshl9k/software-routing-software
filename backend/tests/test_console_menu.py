"""Local menu tests never invoke real root, systemd, networking or getpass."""
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vs_router.agent.console_menu import (Addressing, Menu, Selection, build_configuration,
                                          local_guard, parse_role, render_status, static_address)
from vs_router.db import Base, ConfigurationRow, UserRow
from vs_router.management import Management


@pytest.fixture
def database(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path / "menu.db"}')
    Base.metadata.create_all(engine)
    return engine


def test_roles_and_guard():
    assert parse_role(' WAN ') == 'wan'
    assert parse_role('-') is None
    with pytest.raises(ValueError, match='console.invalid_role'):
        parse_role('OPT')
    for args in ((1, True, ''), (0, False, ''), (0, True, 'remote')):
        with pytest.raises(ValueError, match='console.local_root_required'):
            local_guard(*args)
    local_guard(0, True, '')


def test_loop_rejects_remote_before_input(database, monkeypatch):
    monkeypatch.setattr('vs_router.agent.console_menu.os.geteuid', lambda: 1)
    menu = Menu(database=database, input_fn=lambda _: pytest.fail('prompted off-console'))
    with pytest.raises(ValueError, match='console.local_root_required'):
        menu.loop()


def test_addressing_and_validation():
    selection = Selection({'enp1s0': 'wan', 'enp2s0': 'lan'},
                          {'enp1s0': Addressing('dhcp'),
                           'enp2s0': static_address('10.42.0.1/24', dns='1.1.1.1')})
    config = build_configuration(selection)
    assert [(i.name, i.zone, i.addressing) for i in config.interfaces] == [
        ('enp1s0', 'wan', 'dhcp'), ('enp2s0', 'lan', 'static')]
    assert config.interfaces[1].addresses == ('10.42.0.1/24',)
    assert config.dns.upstreams[0].address == '1.1.1.1'
    with pytest.raises(ValueError, match='console.invalid_address'):
        static_address('999.2.1.1/24')
    with pytest.raises(ValueError, match='management.dhcp_forbidden'):
        build_configuration(Selection(selection.roles, {'enp2s0': Addressing('dhcp')}))


def test_address_prompt_rejects_bad_ip_without_persisting(database):
    answers = iter(['enp2s0', 'static', '999.2.1.1/24', '', ''])
    menu = Menu(database=database, input_fn=lambda _: next(answers), print_fn=lambda _: None)
    menu.selection.roles = {'enp2s0': 'lan'}
    with pytest.raises(ValueError, match='console.invalid_address'):
        menu.set_address()
    assert menu.selection.addresses == {}


def test_assign_confirmation_and_status(tmp_path, database):
    sysnet = tmp_path / 'sys'
    for name, mac, carrier in [('enp1s0', '00:11:22:33:44:55', '1'),
                               ('enp2s0', '00:11:22:33:44:66', '0')]:
        (sysnet / name / 'device').mkdir(parents=True)
        (sysnet / name / 'type').write_text('1')
        (sysnet / name / 'address').write_text(mac)
        (sysnet / name / 'carrier').write_text(carrier)
    prompts = iter(['wan', 'lan', 'no', 'wan', 'lan', 'yes'])
    output = []
    seen_prompts = []
    def answer(prompt):
        seen_prompts.append(prompt)
        return next(prompts)
    menu = Menu(input_fn=answer, print_fn=output.append,
                sysnet=sysnet, database=database, runner=lambda argv: SimpleNamespace(returncode=0))
    menu.assign()
    assert menu.selection.roles == {}
    menu.assign()
    assert menu.selection.roles == {'enp1s0': 'wan', 'enp2s0': 'lan'}
    assert 'link=0' in ''.join(seen_prompts)
    menu.selection.addresses['enp2s0'] = static_address('10.42.0.1/24')
    state = Management(interface='enp2s0', mac='00:11:22:33:44:66', address='10.42.0.1/24')
    text = render_status(menu.ports(), menu.selection, 2, {'caddy': 'active'}, state, 'ab:cd')
    assert 'https://10.42.0.1/' in text and 'CA SHA-256: ab:cd' in text
    assert 'enp1s0' in text and 'Version: 2' in text


def test_password_no_echo(database):
    output = []
    secrets = iter(['correct horse battery', 'correct horse battery'])
    menu = Menu(database=database, print_fn=output.append, password_fn=lambda _: next(secrets))
    menu.set_password()
    with Session(database) as db:
        user = db.scalar(select(UserRow).where(UserRow.username == 'admin'))
        assert user.role == 'admin'
        assert user.password_hash.startswith('$argon2id$')
    assert 'correct horse' not in ''.join(output)


def test_save_apply_uses_draft_and_management_guard(tmp_path, database):
    sysnet = tmp_path / 'sys'
    for name, mac in [('enp1s0', '00:11:22:33:44:55'), ('enp2s0', '00:11:22:33:44:66')]:
        (sysnet / name / 'device').mkdir(parents=True)
        (sysnet / name / 'type').write_text('1')
        (sysnet / name / 'address').write_text(mac)
    calls = []
    class FakeConsole:
        def path(self, path):
            return tmp_path / str(path).lstrip('/')

        def provision(self, mac, address):
            calls.append(('provision', mac, address))

    menu = Menu(database=database, sysnet=sysnet, console=FakeConsole(),
                apply_fn=lambda version_id: calls.append(('apply', version_id)) or {'status': 'confirmed'},
                print_fn=lambda _: None)
    menu.selection = Selection({'enp1s0': 'wan', 'enp2s0': 'lan'},
                               {'enp1s0': Addressing('dhcp'),
                                'enp2s0': static_address('10.42.0.1/24')})
    menu.save_apply()
    assert calls == [('provision', '00:11:22:33:44:66', '10.42.0.1/24'), ('apply', 1)]
    with Session(database) as db:
        row = db.get(ConfigurationRow, 1)
        assert row.status == 'draft'  # Agent, not the menu, confirms the version.
        assert row.configuration.interfaces[1].addresses == ('10.42.0.1/24',)
    menu.save_apply()  # Identical draft can be retried after provisioning failure.
    assert calls[-2:] == [('provision', '00:11:22:33:44:66', '10.42.0.1/24'), ('apply', 1)]
    with Session(database) as db:
        assert db.scalar(select(ConfigurationRow.id).where(ConfigurationRow.id == 2)) is None
