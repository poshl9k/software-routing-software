"""The router profile keeps the kernel wireguard module unloaded.

AWG runs as a userspace daemon there, and that daemon refuses to start while the
plain wireguard module is loaded — which happens on demand, from unrelated tools.
Nodes and VPS panels that serve subscribers with kernel WireGuard must keep it.
"""
from vs_router.agent import kernel_module
from test_agent_apply import FakeExecutor, FakeFS


class Config:
    def __init__(self, protocols):
        self.tunnels = [type("T", (), {"protocol": item})() for item in protocols]


def test_router_profile_writes_the_blacklist_and_unloads_the_module():
    fs, executor = FakeFS(), FakeExecutor()
    state = kernel_module.sync("router", Config(["awg"]), fs, executor)
    assert state == kernel_module.BLACKLISTED
    assert fs.read(kernel_module.BLACKLIST_PATH) == kernel_module.BLACKLIST_CONTENT
    assert ["modprobe", "-r", "wireguard"] in [argv for argv, _ in executor.calls]


def test_second_apply_is_idempotent():
    fs, executor = FakeFS(), FakeExecutor()
    kernel_module.sync("router", Config(["awg"]), fs, executor)
    executor.calls.clear()
    assert kernel_module.sync("router", Config(["awg"]), fs, executor) == kernel_module.UNCHANGED
    assert executor.calls == []


def test_a_wg_tunnel_keeps_the_kernel_module():
    fs, executor = FakeFS(), FakeExecutor()
    kernel_module.sync("router", Config(["awg"]), fs, executor)
    executor.calls.clear()
    state = kernel_module.sync("router", Config(["awg", "wg"]), fs, executor)
    assert state == kernel_module.REMOVED
    assert kernel_module.BLACKLIST_PATH not in fs.files
    assert executor.calls == []


def test_panel_profile_never_blacklists_and_removes_a_stale_file():
    fs, executor = FakeFS(), FakeExecutor()
    kernel_module.sync("router", Config(["awg"]), fs, executor)
    executor.calls.clear()
    assert kernel_module.sync("panel", Config(["awg"]), fs, executor) == kernel_module.REMOVED
    assert kernel_module.BLACKLIST_PATH not in fs.files
    assert executor.calls == []


def test_an_unmarked_host_is_left_alone():
    fs, executor = FakeFS(), FakeExecutor()
    assert kernel_module.sync(None, Config(["awg"]), fs, executor) == kernel_module.UNCHANGED
    assert kernel_module.BLACKLIST_PATH not in fs.files
    assert executor.calls == []


def test_the_agent_may_write_the_module_policy_file():
    """The agent runs under ProtectSystem=strict.

    `/etc/modprobe.d` is not in its ReadWritePaths, so writing the blacklist
    (the whole point of the router profile) fails with EROFS and the apply dies
    with `agent.internal_error` — a green unit test would never notice.
    """
    from pathlib import Path
    unit = (Path(__file__).resolve().parents[1] / 'packaging' /
            'vs-router-agent.service').read_text(encoding='utf-8')
    paths = next(line for line in unit.splitlines()
                 if line.startswith('ReadWritePaths='))
    assert '/etc/modprobe.d' in paths.split('=', 1)[1].split()
    assert kernel_module.BLACKLIST_PATH.parent == Path('/etc/modprobe.d')
