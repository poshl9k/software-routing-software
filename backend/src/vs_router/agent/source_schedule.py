"""Source-update scheduler: pure next-run computation for the two schedule modes.

Scope
-----
This is the *scheduler* required by ``docs/sing-box-tproxy-plan.md``
§«Источники списков и обновления»: exactly two mutually-exclusive modes — a
periodic ``interval`` (default 6 h, configurable) or a once-per-day ``window``
(default 00:00–05:00 in the *server* timezone). It is a pure, side-effect-free
function library: no clock, no I/O, no network, no shell. "Now" is always
injected as an epoch-seconds argument, so every branch — including DST
transitions — is exercised deterministically in tests.

Semantics
---------
* **interval** — the next attempt is ``last_attempt + interval``. If that is
  already in the past (the host was asleep or the service was down), the source
  becomes *due now* and fires **exactly once**; there is deliberately no
  catch-up series for the slots that were missed. The timer reference is the
  **last attempt**, not the last success, so a failing source is retried on the
  next interval (subject to backoff) rather than never.
* **window** — one attempt per local day inside ``[window_start, window_end)``.
  If no attempt has happened since today's window opened and the current moment
  is inside the window, the source is due now; if today's window is already past
  (or a run already happened today) the next attempt is tomorrow's window start.
  A day whose window was entirely missed is skipped — again, no catch-up.
* **backoff** — a capped exponential delay, added to the base next-run time,
  growing with ``consecutive_failures`` (``base * 2**(n-1)`` clamped to
  ``backoff_max_seconds``).
* **jitter** — a random offset in ``[0, jitter_seconds]`` added on top of the
  base so many sources do not stampede together. Jitter is *informational /
  projection*: it never gates ``is_due`` (which is computed on the deterministic
  base), so due-ness stays reproducible.
* **DST / timezone** — window arithmetic is done in the schedule's IANA timezone
  via :mod:`zoneinfo`, so the local wall-clock window keeps its meaning across a
  DST change and the returned epoch instant shifts accordingly.

The one honest limitation: a window boundary that falls *inside* a DST gap (a
nonexistent local wall time) is resolved by ``zoneinfo``'s default fold
handling rather than being shifted into the gap end; the default 00:00–05:00
window never hits such a time in the supported regions.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Callable, Literal
from zoneinfo import ZoneInfo

from pydantic import Field, model_validator

from ..schema import Model, TProxyUpdateSchedule

# ---------------------------------------------------------------------------
# Defaults (mirror docs/sing-box-tproxy-plan.md)
# ---------------------------------------------------------------------------

DEFAULT_INTERVAL_HOURS = 6
DEFAULT_WINDOW_START = "00:00"
DEFAULT_WINDOW_END = "05:00"
DEFAULT_JITTER_SECONDS = 300            # spread sources over 5 min
DEFAULT_BACKOFF_BASE_SECONDS = 300      # 5 min after the first failure
DEFAULT_BACKOFF_MAX_SECONDS = 86_400     # 24 h cap

_HHMM = r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$"


class SourceSchedule(Model):
    """A source-update schedule. Two mutually-exclusive modes, one object.

    ``interval_hours`` applies to ``interval``; ``window_start``/``window_end``
    apply to ``window``; both carry the shared jitter/backoff policy. The
    ``timezone`` is an IANA name (the *server* timezone in production); it is an
    explicit field rather than read from the host so the pure functions stay
    deterministic and testable.
    """

    mode: Literal["interval", "window"] = "interval"
    interval_hours: int = Field(default=DEFAULT_INTERVAL_HOURS, ge=1, le=168)
    window_start: str = Field(default=DEFAULT_WINDOW_START, pattern=_HHMM)
    window_end: str = Field(default=DEFAULT_WINDOW_END, pattern=_HHMM)
    timezone: str = "UTC"
    jitter_seconds: int = Field(default=DEFAULT_JITTER_SECONDS, ge=0, le=86_400)
    backoff_base_seconds: int = Field(default=DEFAULT_BACKOFF_BASE_SECONDS, ge=0, le=86_400)
    backoff_max_seconds: int = Field(default=DEFAULT_BACKOFF_MAX_SECONDS, ge=0, le=604_800)

    @model_validator(mode="after")
    def _check(self):
        if self.mode == "window" and self.window_start >= self.window_end:
            raise ValueError("schedule.invalid_window")
        if self.backoff_base_seconds > self.backoff_max_seconds:
            raise ValueError("schedule.invalid_backoff")
        try:
            ZoneInfo(self.timezone)
        except Exception as exc:  # invalid/unknown IANA key
            raise ValueError("schedule.invalid_timezone") from exc
        return self

    @classmethod
    def from_contract(cls, contract: TProxyUpdateSchedule, *, timezone: str = "UTC",
                      **overrides) -> "SourceSchedule":
        """Build from the schema's :class:`TProxyUpdateSchedule` (mode/hours/window).

        The contract model carries no timezone/jitter/backoff, so those keep the
        defaults or the caller's explicit overrides.
        """
        fields = dict(mode=contract.mode, interval_hours=contract.interval_hours,
                      window_start=contract.window_start, window_end=contract.window_end,
                      timezone=timezone)
        fields.update(overrides)
        return cls(**fields)  # type: ignore[arg-type]


@dataclass(frozen=True)
class RunState:
    """The observable state a scheduler decision depends on (all epoch seconds)."""

    last_attempt: float | None = None
    last_success: float | None = None
    consecutive_failures: int = 0


@dataclass(frozen=True)
class Staleness:
    stale: bool
    age_seconds: float | None


def state_from_history(history: list[dict], name: str) -> RunState:
    """Derive :class:`RunState` for ``name`` from the downloader's history.

    History is appended oldest-first (see ``SourceStore.record``). A trailing
    run of ``failed`` entries yields ``consecutive_failures``; the last ``ok``
    entry yields ``last_success``. Anything for another source is ignored.
    """
    entries = [entry for entry in history if entry.get("name") == name]
    last_attempt = entries[-1].get("at") if entries else None
    last_success = None
    for entry in reversed(entries):
        if entry.get("status") == "ok":
            last_success = entry.get("at")
            break
    failures = 0
    for entry in reversed(entries):
        if entry.get("status") == "failed":
            failures += 1
        else:
            break
    return RunState(last_attempt=last_attempt, last_success=last_success,
                    consecutive_failures=failures)


# ---------------------------------------------------------------------------
# Pure computation
# ---------------------------------------------------------------------------

def _zone(schedule: SourceSchedule) -> ZoneInfo:
    return ZoneInfo(schedule.timezone)


def _at_local(day, hhmm: str, tz: ZoneInfo) -> datetime:
    hour, minute = (int(part) for part in hhmm.split(":"))
    return datetime.combine(day, time(hour, minute)).replace(tzinfo=tz)


def backoff_delay_seconds(schedule: SourceSchedule, consecutive_failures: int) -> float:
    """Capped exponential backoff: ``base * 2**(n-1)`` clamped to the maximum."""
    if consecutive_failures <= 0:
        return 0.0
    delay = schedule.backoff_base_seconds * (2 ** (consecutive_failures - 1))
    return float(min(delay, schedule.backoff_max_seconds))


def base_next_run(schedule: SourceSchedule, *, now: float, state: RunState) -> float:
    """Deterministic next attempt instant (epoch seconds), jitter excluded.

    May be ``<= now``; that is precisely how "due" is expressed. The value is
    what :func:`is_due` compares against, so due-ness never depends on jitter.
    """
    if schedule.mode == "interval":
        if state.last_attempt is None:
            base = float(now)
        else:
            base = float(state.last_attempt) + schedule.interval_hours * 3600
            if base <= now:
                # Overdue after a long sleep/outage: fire once now, do not
                # replay every missed slot.
                base = float(now)
    else:
        tz = _zone(schedule)
        local_now = datetime.fromtimestamp(now, tz)
        start_today = _at_local(local_now.date(), schedule.window_start, tz)
        end_today = _at_local(local_now.date(), schedule.window_end, tz)
        ran_today = (state.last_attempt is not None
                     and state.last_attempt >= start_today.timestamp())
        if ran_today:
            target = _at_local(local_now.date() + timedelta(days=1), schedule.window_start, tz)
        elif local_now < start_today:
            target = start_today
        elif local_now < end_today:
            # Inside the window and not yet serviced: due now (no catch-up).
            target = local_now
        else:
            # Window already closed without a run: skip the day.
            target = _at_local(local_now.date() + timedelta(days=1), schedule.window_start, tz)
        base = target.timestamp()
    return base + backoff_delay_seconds(schedule, state.consecutive_failures)


def next_run(schedule: SourceSchedule, *, now: float, state: RunState,
             rng: Callable[[float, float], float] | None = None) -> float:
    """Projected next attempt instant: :func:`base_next_run` plus jitter."""
    base = base_next_run(schedule, now=now, state=state)
    if schedule.jitter_seconds <= 0:
        return base
    generator: Callable[[float, float], float] = (rng if rng is not None
                                                  else random.Random().uniform)
    return base + generator(0.0, float(schedule.jitter_seconds))


def is_due(schedule: SourceSchedule, *, now: float, state: RunState) -> bool:
    """True when the source should be updated at ``now`` (jitter-independent)."""
    return base_next_run(schedule, now=now, state=state) <= now


def describe(schedule: SourceSchedule, *, now: float, state: RunState,
             rng: Callable[[float, float], float] | None = None) -> dict:
    """Serializable view for the UI/status: due flag and the actual next time.

    ``base_run_local``/``next_run_local`` are rendered in the schedule timezone,
    so a DST shift is visible as a different UTC instant for the same local
    wall-clock time.
    """
    tz = _zone(schedule)
    base = base_next_run(schedule, now=now, state=state)
    projected = next_run(schedule, now=now, state=state, rng=rng)
    return {
        "mode": schedule.mode,
        "timezone": schedule.timezone,
        "due": base <= now,
        "next_run": projected,
        "next_run_local": datetime.fromtimestamp(projected, tz).isoformat(),
        "base_run": base,
        "base_run_local": datetime.fromtimestamp(base, tz).isoformat(),
        "interval_hours": schedule.interval_hours,
        "window_start": schedule.window_start,
        "window_end": schedule.window_end,
        "consecutive_failures": state.consecutive_failures,
        "backoff_seconds": backoff_delay_seconds(schedule, state.consecutive_failures),
    }


def staleness(*, now: float, last_success: float | None,
              stale_after_seconds: float = 7 * 24 * 3600) -> Staleness:
    """Age of the last successful update and whether it is stale.

    A source that has never succeeded is reported stale with an unknown age.
    """
    if last_success is None:
        return Staleness(stale=True, age_seconds=None)
    age = now - last_success
    return Staleness(stale=age > stale_after_seconds, age_seconds=age)
