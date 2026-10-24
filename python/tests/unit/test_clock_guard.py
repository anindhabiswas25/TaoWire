"""auth/clock.py: NTP offset classification and failure handling (spec 8.4.4)."""

from __future__ import annotations

import itertools
import sys
import types
from typing import Any

import anyio
import pytest
import structlog.testing

from taowire.auth import clock as clock_mod
from taowire.auth.clock import ClockGuard, ClockReading, ClockStatus, ntplib_query


def fixed(offsets: dict[str, Any]) -> Any:
    def query(server: str, timeout_s: float) -> float:
        value = offsets[server]
        if isinstance(value, BaseException):
            raise value
        return float(value)

    return query


@pytest.mark.parametrize(
    ("offset", "status"),
    [
        (0.0, ClockStatus.OK),
        (0.5, ClockStatus.OK),
        (-0.51, ClockStatus.WARN),
        (2.0, ClockStatus.WARN),
        (2.01, ClockStatus.SKEWED),
        (-30, ClockStatus.SKEWED),
    ],
)
def test_classification(offset: float, status: ClockStatus) -> None:
    readings: list[ClockReading] = []
    guard = ClockGuard(
        ["a"],
        allowed_skew_s=2.0,
        query=fixed({"a": offset}),
        on_reading=readings.append,
    )
    reading = guard.check()
    assert reading == ClockReading(status, offset, "a")
    assert guard.last == reading
    assert readings == [reading]
    assert guard.skewed is (status is ClockStatus.SKEWED)


def test_first_answering_server_wins() -> None:
    guard = ClockGuard(
        ["down", "nan", "b"],
        allowed_skew_s=2.0,
        query=fixed({"down": OSError("timeout"), "nan": float("nan"), "b": 0.1}),
    )
    assert guard.check() == ClockReading(ClockStatus.OK, 0.1, "b")


def test_unreachable_is_unknown_never_an_error() -> None:
    guard = ClockGuard(["x"], allowed_skew_s=2.0, query=fixed({"x": RuntimeError()}))
    assert guard.check() == ClockReading(ClockStatus.UNKNOWN)
    assert not guard.skewed


def test_no_servers_disables_the_check() -> None:
    calls: list[str] = []
    guard = ClockGuard(
        [], allowed_skew_s=2.0, query=lambda s, t: calls.append(s) or 0.0
    )
    assert guard.check().status is ClockStatus.UNKNOWN
    assert calls == []


def test_without_ntplib_the_offset_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "ntplib", None)
    assert ntplib_query() is None
    guard = ClockGuard(["pool.ntp.org"], allowed_skew_s=2.0)
    assert guard.check().status is ClockStatus.UNKNOWN


def test_ntplib_query_uses_ntplib(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class Client:
        def request(self, server: str, version: int, timeout: float) -> Any:
            seen.update(server=server, version=version, timeout=timeout)
            return types.SimpleNamespace(offset=0.25)

    monkeypatch.setitem(sys.modules, "ntplib", types.SimpleNamespace(NTPClient=Client))
    query = ntplib_query()
    assert query is not None
    assert query("time.example", 1.5) == 0.25
    assert seen == {"server": "time.example", "version": 3, "timeout": 1.5}


def test_skew_must_be_positive() -> None:
    with pytest.raises(ValueError, match="allowed_skew_s"):
        ClockGuard([], allowed_skew_s=0)


async def test_check_async_and_periodic_run(monkeypatch: pytest.MonkeyPatch) -> None:
    offsets = itertools.cycle([0.1, 3.0])
    guard = ClockGuard(["a"], allowed_skew_s=2.0, query=lambda s, t: next(offsets))
    assert (await guard.check_async()).status is ClockStatus.OK
    with anyio.move_on_after(0.2):
        await guard.run(interval_s=0.01)
    assert guard.last.status in (ClockStatus.SKEWED, ClockStatus.OK)
    assert clock_mod.CHECK_INTERVAL_S == 600


def test_log_levels() -> None:
    with structlog.testing.capture_logs() as logs:
        ClockGuard(["a"], allowed_skew_s=2, query=fixed({"a": 5})).check()
        ClockGuard(["a"], allowed_skew_s=2, query=fixed({"a": 1})).check()
        ClockGuard(["a"], allowed_skew_s=2, query=fixed({"a": OSError()})).check()
    levels = [e["log_level"] for e in logs if e["log_level"] != "debug"]
    assert levels == ["error", "warning", "info"]
    assert [e["event"] for e in logs if e["log_level"] == "error"] == ["clock_skew"]


async def test_schedule_survives_a_failing_check() -> None:
    calls: list[int] = []

    def flaky(reading: ClockReading) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("gauge exploded")

    guard = ClockGuard(
        ["a"], allowed_skew_s=2.0, query=lambda s, t: 0.1, on_reading=flaky
    )
    with structlog.testing.capture_logs() as logs, anyio.move_on_after(0.3):
        await guard.run(interval_s=0.02)
    assert len(calls) >= 3  # kept checking after the first failure
    assert "clock_check_failed" in [e["event"] for e in logs]
