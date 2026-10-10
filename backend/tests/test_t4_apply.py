"""Product TProxy activation proof, with no host nft mutations."""
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from test_tproxy_apply_integration import enabled_version
from vs_router.agent import tproxy_apply
from vs_router.agent.apply import ApplyEngine, ApplyError, APPLIED_DIR


def test_pinned_validator():
    assert tproxy_apply.TPROXY_VALIDATORS['singbox'] == [
        '/usr/local/lib/vs-router/sing-box', 'check', '-c']


def test_nft_activators_load_fixed_paths_in_order():
    executor = FakeExecutor()
    engine = ApplyEngine(filesystem=FakeFS(), executor=executor)
    for name in ('tproxy_guards', 'tproxy_interception', 'tproxy_cleanup'):
        engine.reload_service(name)
    assert [argv for argv, _ in executor.calls] == [
        ['/usr/sbin/nft', '-f', str(APPLIED_DIR / path)] for path in (
            'tproxy-guards.nft', 'tproxy-intercept.nft', 'tproxy-cleanup.nft')]


def test_missing_table_prevents_confirmation_and_rolls_back():
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor)
    assert engine.apply_version(snapshot()).status == 'confirmed'
    original = executor.run
    def run(argv, timeout):
        if argv == ['/usr/sbin/nft', 'list', 'tables']:
            return SimpleNamespace(returncode=0, stdout='table inet vs_router_tproxy_guard\n')
        return original(argv, timeout)
    executor.run = run
    validators = {name: lambda name, path: SimpleNamespace(returncode=0)
                  for name in ('nftables', 'unbound', 'kea', 'networkd', 'wireguard',
                               'caddy', 'ddns', 'ssh', *tproxy_apply.TPROXY_FILES)}
    result = engine.apply_version(enabled_version(), validators=validators)
    assert result.status == 'rolled_back'
    assert result.reason == 'agent.tproxy_tables_missing'
    assert engine.status()['status'] == 'rolled_back'
    calls = [argv for argv, _ in executor.calls]
    assert ['/usr/sbin/nft', '-f', str(APPLIED_DIR / 'tproxy-guards.nft')] in calls
    assert ['/usr/sbin/nft', '-f', str(APPLIED_DIR / 'tproxy-cleanup.nft')] in calls
    assert ['/usr/sbin/nft', '-f', str(APPLIED_DIR / 'tproxy-intercept.nft')] not in calls


def test_pending_confirmation_rechecks_live_tables():
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor)
    assert engine.apply_version(snapshot()).status == 'confirmed'
    original = executor.run
    tables = [''.join(f'table {name}\n' for name in tproxy_apply.owned_tables())]
    def run(argv, timeout):
        if argv == ['/usr/sbin/nft', 'list', 'tables']:
            return SimpleNamespace(returncode=0, stdout=tables[0])
        return original(argv, timeout)
    executor.run = run
    engine.reload_commands.update({tproxy_apply.POLICY_ROUTE_STEP: lambda: None,
                                   tproxy_apply.UNBOUND_PROCESS_STEP: lambda: None,
                                   tproxy_apply.SINGBOX_PROCESS_STEP: lambda: None})
    validators = {name: lambda name, path: SimpleNamespace(returncode=0)
                  for name in ('nftables', 'unbound', 'kea', 'networkd', 'wireguard',
                               'caddy', 'ddns', 'ssh', *tproxy_apply.TPROXY_FILES)}
    assert engine.apply_version(enabled_version(), safe_mode=True, validators=validators).status == 'pending'
    tables[0] = ''
    with pytest.raises(ApplyError, match='agent.tproxy_tables_missing'):
        engine.confirm_version(1)
    assert engine.status()['status'] == 'rolled_back'
