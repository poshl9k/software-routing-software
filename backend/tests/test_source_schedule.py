"""Source-update scheduler: interval/window, DST, backoff, jitter, no catch-up.

Pure functions with an injected "now"; the integration test drives the real
downloader against a mocked transport (no socket is ever opened).
"""
import random
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

sys.path.insert(0, "tests")

import pytest
from pydantic import ValidationError

from test_downloader import FakeTransport, fixed_resolver, make_updater, response
from vs_router.agent.source_schedule import (RunState, SourceSchedule, base_next_run,
                                             backoff_delay_seconds, describe, is_due,
                                             next_run, staleness, state_from_history)
from vs_router.schema import TProxyUpdateSchedule

PUBLIC = "93.184.216.34"
HOUR = 3600


class FixedRng:
    def __init__(self, value):
        self.value = value

    def __call__(self, low, high):
        assert 0.0 <= low <= high
        return self.value


def interval_schedule(**overrides):
    fields = dict(mode="interval", interval_hours=6, jitter_seconds=0,
                  backoff_base_seconds=0, backoff_max_seconds=0)
    fields.update(overrides)
    return SourceSchedule(**fields)  # type: ignore[arg-type]


def local_epoch(tz_name, *args):
    return datetime(*args, tzinfo=ZoneInfo(tz_name)).timestamp()


# ---------------------------------------------------------------------------
# interval mode
# ---------------------------------------------------------------------------

def test_interval_first_run_is_due_immediately():
    schedule = interval_schedule()
    state = RunState()
    assert is_due(schedule, now=1000.0, state=state)
    assert base_next_run(schedule, now=1000.0, state=state) == 1000.0


def test_interval_waits_full_period_after_an_attempt():
    schedule = interval_schedule(interval_hours=6)
    state = RunState(last_attempt=1000.0, last_success=1000.0)
    assert not is_due(schedule, now=1000.0 + 6 * HOUR - 1, state=state)
    assert base_next_run(schedule, now=2000.0, state=state) == 1000.0 + 6 * HOUR
    assert is_due(schedule, now=1000.0 + 6 * HOUR, state=state)


def test_interval_overdue_after_long_sleep_fires_once_without_catch_up():
    schedule = interval_schedule(interval_hours=6)
    # Three days of missed 6h slots.
    state = RunState(last_attempt=1000.0, last_success=1000.0)
    now = 1000.0 + 3 * 24 * HOUR
    assert is_due(schedule, now=now, state=state)
    # Exactly "now" — a single run, not twelve.
    assert base_next_run(schedule, now=now, state=state) == now
    # After that single run, the next slot is one interval away.
    after = RunState(last_attempt=now, last_success=now)
    assert not is_due(schedule, now=now, state=after)
    assert base_next_run(schedule, now=now, state=after) == now + 6 * HOUR


def test_interval_uses_last_attempt_not_last_success():
    schedule = interval_schedule(interval_hours=6)
    state = RunState(last_attempt=1000.0, last_success=10.0)
    assert base_next_run(schedule, now=1000.0, state=state) == 1000.0 + 6 * HOUR


# ---------------------------------------------------------------------------
# window mode
# ---------------------------------------------------------------------------

def test_window_before_window_targets_today_start():
    schedule = SourceSchedule(mode="window", timezone="Europe/Moscow",
                              window_start="00:00", window_end="05:00",
                              jitter_seconds=0, backoff_base_seconds=0, backoff_max_seconds=0)
    now = local_epoch("Europe/Moscow", 2026, 4, 10, 22, 30)
    base = base_next_run(schedule, now=now, state=RunState())
    target = datetime.fromtimestamp(base, ZoneInfo("Europe/Moscow"))
    assert (target.year, target.month, target.day, target.hour, target.minute) == (2026, 4, 11, 0, 0)
    assert not is_due(schedule, now=now, state=RunState())


def test_window_inside_window_is_due_now():
    schedule = SourceSchedule(mode="window", timezone="Europe/Moscow",
                              window_start="00:00", window_end="05:00",
                              jitter_seconds=0, backoff_base_seconds=0, backoff_max_seconds=0)
    now = local_epoch("Europe/Moscow", 2026, 4, 10, 2, 15)
    assert is_due(schedule, now=now, state=RunState())
    assert base_next_run(schedule, now=now, state=RunState()) == now


def test_window_after_window_skips_to_tomorrow():
    schedule = SourceSchedule(mode="window", timezone="Europe/Moscow",
                              window_start="00:00", window_end="05:00",
                              jitter_seconds=0, backoff_base_seconds=0, backoff_max_seconds=0)
    now = local_epoch("Europe/Moscow", 2026, 4, 10, 6, 0)
    base = base_next_run(schedule, now=now, state=RunState())
    target = datetime.fromtimestamp(base, ZoneInfo("Europe/Moscow"))
    assert (target.day, target.hour) == (11, 0)


def test_window_runs_once_per_day():
    schedule = SourceSchedule(mode="window", timezone="Europe/Moscow",
                              window_start="00:00", window_end="05:00",
                              jitter_seconds=0, backoff_base_seconds=0, backoff_max_seconds=0)
    ran = RunState(last_attempt=local_epoch("Europe/Moscow", 2026, 4, 10, 1, 0))
    now = local_epoch("Europe/Moscow", 2026, 4, 10, 3, 0)
    assert not is_due(schedule, now=now, state=ran)
    base = base_next_run(schedule, now=now, state=ran)
    target = datetime.fromtimestamp(base, ZoneInfo("Europe/Moscow"))
    assert (target.day, target.hour) == (11, 0)


def test_window_is_dst_aware():
    # A fixed local wall clock resolves to different UTC offsets across a DST change.
    schedule = SourceSchedule(mode="window", timezone="America/New_York",
                              window_start="00:00", window_end="05:00",
                              jitter_seconds=0, backoff_base_seconds=0, backoff_max_seconds=0)
    before_spring = local_epoch("America/New_York", 2026, 3, 7, 23, 30)
    before_fall = local_epoch("America/New_York", 2026, 10, 31, 23, 30)
    tz = ZoneInfo("America/New_York")
    spring = datetime.fromtimestamp(base_next_run(schedule, now=before_spring, state=RunState()), tz)
    fall = datetime.fromtimestamp(base_next_run(schedule, now=before_fall, state=RunState()), tz)
    assert spring.isoformat() == "2026-03-08T00:00:00-05:00"
    assert fall.isoformat() == "2026-11-01T00:00:00-04:00"
    assert spring.utcoffset() != fall.utcoffset()  # fixed local time, shifted UTC


# ---------------------------------------------------------------------------
# backoff and jitter
# ---------------------------------------------------------------------------

def test_backoff_grows_exponentially_and_is_capped():
    schedule = interval_schedule(backoff_base_seconds=300, backoff_max_seconds=86400)
    assert backoff_delay_seconds(schedule, 0) == 0
    assert backoff_delay_seconds(schedule, 1) == 300
    assert backoff_delay_seconds(schedule, 3) == 1200
    assert backoff_delay_seconds(schedule, 20) == 86400


def test_backoff_adds_to_the_interval_base():
    schedule = interval_schedule(interval_hours=6, backoff_base_seconds=300, backoff_max_seconds=86400)
    state = RunState(last_attempt=1000.0, last_success=1000.0, consecutive_failures=3)
    assert base_next_run(schedule, now=1000.0, state=state) == 1000.0 + 6 * HOUR + 1200


def test_jitter_is_injected_and_adds_to_base():
    schedule = interval_schedule(interval_hours=6, jitter_seconds=300)
    state = RunState(last_attempt=1000.0)
    base = base_next_run(schedule, now=1000.0, state=state)
    assert next_run(schedule, now=1000.0, state=state, rng=FixedRng(120.0)) == base + 120
    # A seed makes it deterministic too.
    value = next_run(schedule, now=1000.0, state=state, rng=random.Random(0).uniform)
    assert base <= value <= base + 300


def test_jitter_does_not_change_due_ness():
    schedule = interval_schedule(interval_hours=6, jitter_seconds=3600)
    state = RunState(last_attempt=1000.0)
    now = 1000.0 + 6 * HOUR
    assert is_due(schedule, now=now, state=state)
    assert next_run(schedule, now=now, state=state, rng=FixedRng(3599.0)) > now


# ---------------------------------------------------------------------------
# schema / helpers
# ---------------------------------------------------------------------------

def test_window_model_rejects_invalid_bounds_and_timezone():
    with pytest.raises(ValidationError, match="schedule.invalid_window"):
        SourceSchedule(mode="window", window_start="05:00", window_end="05:00")
    with pytest.raises(ValidationError, match="schedule.invalid_backoff"):
        SourceSchedule(backoff_base_seconds=600, backoff_max_seconds=300)
    with pytest.raises(ValidationError, match="schedule.invalid_timezone"):
        SourceSchedule(timezone="Mars/Olympus")


def test_from_contract_carries_mode_and_window():
    contract = TProxyUpdateSchedule(mode="window", window_start="01:00", window_end="04:00")
    schedule = SourceSchedule.from_contract(contract, timezone="Europe/Moscow",
                                            jitter_seconds=0)
    assert schedule.mode == "window"
    assert (schedule.window_start, schedule.window_end) == ("01:00", "04:00")
    assert schedule.timezone == "Europe/Moscow"
    assert schedule.interval_hours == 6  # default preserved


def test_state_from_history_extracts_attempt_success_and_failures():
    history = [
        {"name": "sub1", "status": "ok", "at": 10.0},
        {"name": "other", "status": "ok", "at": 20.0},
        {"name": "sub1", "status": "failed", "at": 30.0},
        {"name": "sub1", "status": "failed", "at": 40.0},
    ]
    state = state_from_history(history, "sub1")
    assert state == RunState(last_attempt=40.0, last_success=10.0, consecutive_failures=2)
    assert state_from_history(history, "absent") == RunState()


def test_state_from_history_treats_not_modified_as_success():
    history = [
        {"name": "s", "status": "ok", "at": 10.0},
        {"name": "s", "status": "not_modified", "at": 20.0},
    ]
    assert state_from_history(history, "s") == RunState(
        last_attempt=20.0, last_success=20.0, consecutive_failures=0)
    # A trailing 304 resets a failure streak (it is a successful contact).
    assert state_from_history([
        {"name": "s", "status": "failed", "at": 5.0},
        {"name": "s", "status": "not_modified", "at": 20.0},
    ], "s").consecutive_failures == 0


def test_describe_reports_local_next_time_and_due():
    schedule = SourceSchedule(mode="window", timezone="Europe/Moscow",
                              window_start="00:00", window_end="05:00", jitter_seconds=0)
    now = local_epoch("Europe/Moscow", 2026, 4, 10, 22, 0)
    view = describe(schedule, now=now, state=RunState())
    assert view["due"] is False
    assert view["next_run_local"] == "2026-04-11T00:00:00+03:00"
    assert view["mode"] == "window"


def test_staleness():
    assert staleness(now=1000.0, last_success=None).stale is True
    assert staleness(now=1000.0, last_success=1000.0 - 3600).stale is False
    fresh = staleness(now=1000.0, last_success=1000.0 - 10 * 24 * HOUR)
    assert fresh.stale is True and fresh.age_seconds == 10 * 24 * HOUR


# ---------------------------------------------------------------------------
# downloader integration (mocked transport)
# ---------------------------------------------------------------------------

def test_run_scheduled_respects_interval_across_calls(tmp_path):
    updater, store, transport = make_updater(
        tmp_path, responses=[response(200, b'{"outbounds": []}')],
        mapping={"public.example": [PUBLIC]})
    schedule = interval_schedule(interval_hours=6)

    first = updater.run_scheduled(name="sub1", url="https://public.example/x",
                                  kind="subscription", authorized=True,
                                  schedule=schedule, now=100.0)
    assert first["ran"] is True and first["status"] == "ok"
    assert first["next_run"] == 100.0 + 6 * HOUR

    second = updater.run_scheduled(name="sub1", url="https://public.example/x",
                                   kind="subscription", authorized=True,
                                   schedule=schedule, now=100.0)
    assert second["ran"] is False and second["status"] == "not_due"
    assert len(transport.calls) == 1  # not re-fetched while not due


def test_run_scheduled_records_failure_and_backs_off(tmp_path):
    updater, store, _ = make_updater(
        tmp_path, responses=[response(200, b"<html>nope</html>")],
        mapping={"public.example": [PUBLIC]})
    schedule = interval_schedule(interval_hours=6, backoff_base_seconds=300,
                                 backoff_max_seconds=86400)
    outcome = updater.run_scheduled(name="sub1", url="https://public.example/x",
                                    authorized=True, schedule=schedule, now=100.0)
    assert outcome["ran"] is True and outcome["status"] == "failed"
    assert outcome["error"] == "download.invalid_format"
    assert outcome["next_run"] >= 100.0 + 6 * HOUR + 300
    assert store.read_history()[-1]["status"] == "failed"
