import json
from pathlib import Path
import sys
from pathlib import Path

sys.path.insert(0, "tests")
import pytest

from test_agent_apply import FakeExecutor, FakeFS, snapshot
from vs_router.agent.apply import ApplyEngine
from vs_router.agent.ddns_update import cloudflare_update, rfc2136_update, update_all


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self._payload if isinstance(self._payload, bytes) else json.dumps(self._payload).encode()

    def json(self):
        return self._payload


@pytest.fixture
def engine(monkeypatch):
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    engine.reveal_secret = lambda secret: "token-123"
    return engine, fs, executor


def ddns_snapshot():
    base = snapshot()
    base["configuration"] = {
        "interfaces": [{"name": "enp1s0", "type": "physical", "zone": "wan"}],
        "ddns": [{
            "name": "home_cf", "provider": "cloudflare", "hostname": "home.example.ru",
            "zone": "example.ru", "wan_interface": "enp1s0",
            "api_token": {"encrypted": True, "ciphertext": "gAAAAA-test"},
        }],
    }
    return base


def test_ddns_config_generated_in_apply(engine, monkeypatch):
    engine, fs, executor = engine
    monkeypatch.setenv("VS_ROUTER_SECRET_KEY", "k" * 43 + "=")
    result = engine.apply_version(ddns_snapshot())
    print("DBG status:", result.status, result.error, result.phases)
    assert result.status in ("confirmed", "pending")
    from pathlib import Path
    raw = fs.read(Path("/etc/vs-router/applied/ddns.conf"))
    jobs = json.loads(raw)["ddns"]
    assert jobs[0]["api_token"] == "token-123"
    assert jobs[0]["provider"] == "cloudflare"


def test_ddns_empty_without_secret_key(engine, monkeypatch):
    engine, fs, executor = engine
    monkeypatch.delenv("VS_ROUTER_SECRET_KEY", raising=False)
    # Реальная расшифровка: без ключа ValueError -> пустой ddns.conf
    engine.reveal_secret = ApplyEngine.reveal_secret.__get__(engine)
    result = engine.apply_version(ddns_snapshot())
    assert result.status in ("confirmed", "pending")
    jobs = json.loads(fs.read(Path("/etc/vs-router/applied/ddns.conf")))["ddns"]
    assert jobs == []


def test_cloudflare_update_create_then_put(monkeypatch):
    calls = []

    def fake_open(request, timeout=15):
        calls.append((request.get_full_url(), request.method, request.data))
        url = request.get_full_url()
        if "zones?name=" in url:
            return FakeResponse({"result": [{"id": "z1", "name": "example.ru"}]})
        if "dns_records?" in url:
            return FakeResponse({"result": []})
        return FakeResponse({"result": {"id": "r1"}})

    fake_opener = lambda request, timeout=15: fake_open(request, timeout)
    cloudflare_update(fake_opener, "tok", "example.ru", "home.example.ru", "1.2.3.4")
    assert len(calls) == 3
    assert any(b'"content": "1.2.3.4"' in c[2] for c in calls if c[2])


def test_rfc2136_update_calls_nsupdate(monkeypatch):
    runs = []

    def fake_run(argv, input=None, capture_output=None, text=None, timeout=None):
        runs.append(input)
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("vs_router.agent.ddns_update.subprocess.run", fake_run)
    rfc2136_update("192.0.2.1", "labkey", "secret", "home.example.ru", "1.2.3.4")
    assert any("update add home.example.ru." in r for r in runs)


def test_update_all_status_flow(monkeypatch):
    def fake_cf(opener, token, zone, hostname, address):
        return

    monkeypatch.setattr("vs_router.agent.ddns_update.cloudflare_update", fake_cf)
    monkeypatch.setattr(
        "vs_router.agent.ddns_update.wan_address", lambda iface: "5.6.7.8"
    )
    config = {"ddns": [{
        "name": "j1", "provider": "cloudflare", "hostname": "h.example.ru",
        "zone": "example.ru", "wan_interface": "wan0",
        "api_token": {"encrypted": True, "ciphertext": "x"},
    }]}
    # reveal упадёт без ключа — проверяем failure-статус
    results = update_all(config)
    assert results[0]["status"] == "failed"
