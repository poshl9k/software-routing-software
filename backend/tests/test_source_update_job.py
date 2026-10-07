"""Timer job decisions use fake RPC and no network."""
from types import SimpleNamespace

from vs_router.agent.source_schedule import SourceSchedule
from vs_router.agent.source_update_job import run


class FakeClient:
    def __init__(self, marker=None, history=None):
        self.marker = marker
        self.history = [] if history is None else history
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params))
        if method == 'status':
            return self.marker
        if method == 'source_status':
            return self.history
        self.history.append({'name': params['name'], 'at': 1000.0, 'status': 'ok'})
        return {'status': 'ok'}


def source(name):
    return SimpleNamespace(name=name, url=f'https://example.org/{name}', max_bytes=4096)


def test_due_selection_and_idempotent_rerun():
    client = FakeClient(history=[{'name': 'recent', 'at': 900.0, 'status': 'ok'}])
    schedule = SourceSchedule(mode='interval', interval_hours=1)
    sources = [source('due'), source('recent')]
    assert run(client, schedule, sources, now=1000.0) == 1
    assert [params['name'] for method, params in client.calls if method == 'update_source'] == ['due']
    assert run(client, schedule, sources, now=1000.0) == 0


def test_pending_apply_skips_without_reading_history():
    client = FakeClient(marker={'status': 'pending'})
    assert run(client, SourceSchedule(), [source('due')], now=1000.0) == 0
    assert client.calls == [('status', None)]


def test_no_due_source_is_noop():
    client = FakeClient(history=[{'name': 'recent', 'at': 900.0, 'status': 'ok'}])
    assert run(client, SourceSchedule(), [source('recent')], now=1000.0) == 0
    assert all(method != 'update_source' for method, _ in client.calls)
