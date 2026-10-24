"""``scripts/drand_feed.py``: telling a failing drand feed apart from a defect (G3-8).

The log lines are the chain's own, captured from a local chain whose drand
feed was rate-limited (HTTP 429) during the Phase 2 gate re-run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "drand_feed.py"
GENESIS = 1_692_803_367
BEACON = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("drand_feed", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["drand_feed"] = module
    spec.loader.exec_module(module)
    return module


drand = _load()

RATE_LIMITED = [
    f"2026-10-22 19:34:22 Drand: Unexpected status code: 429 from "
    f"https://api{n}.drand.sh/{BEACON}/public/33297403"
    for n in ("", "2", "3")
] + [
    "2026-10-22 19:34:23 Drand: No valid response from any endpoint",
    "2026-10-22 19:34:23 🔖 Pre-sealed block for proposal at 2875.",
]
STARTUP = [
    "2026-10-22 18:21:38 Drand: HTTP Deadline Reached",
    "2026-10-22 18:21:38 Drand: No valid response from any endpoint",
]
IO_ERROR = [
    f"2026-10-22 19:40:01 Drand: HTTP error from https://api.drand.sh/{BEACON}"
    "/public/33297500: Error::IoError",
    f"2026-10-22 19:40:02 Drand: Unexpected status code: 503 from "
    f"https://api.drand.sh/{BEACON}/public/latest",
]


class FakeClient:
    def __init__(self, last: int) -> None:
        self.last = last

    async def query(self, key: tuple[str, str], params: list[Any]) -> Any:
        assert params == []
        if key == ("Drand", "LastStoredRound"):
            return self.last
        assert key == ("Drand", "BeaconConfig")
        return {"period": 3, "genesis_time": GENESIS, "public_key": "0x00"}


def test_classify_counts_by_kind() -> None:
    errors, last = drand.classify(RATE_LIMITED + STARTUP + IO_ERROR)
    assert errors == {"http_429": 3, "deadline": 1, "other": 1, "http_5xx": 1}
    assert last is not None
    assert last.startswith("Unexpected status code: 503")
    assert drand.classify(["block 5 imported", ""]) == ({}, None)


def test_expected_round() -> None:
    assert drand.expected_round(GENESIS, 3, GENESIS) == 1
    assert drand.expected_round(GENESIS, 3, GENESIS + 2.9) == 1
    assert drand.expected_round(GENESIS, 3, GENESIS + 3) == 2


async def feed(last: int, lines: list[str] | None, lag_rounds: int = 0) -> Any:
    now = GENESIS + 3 * (last - 1 + lag_rounds) + 1.0
    return await drand.drand_feed(
        FakeClient(last), now_s=lambda: now, read_log=lambda _c, _w: lines
    )


async def test_healthy_feed_even_with_errors_in_the_log() -> None:
    # Deadline errors happen on a healthy chain too (e.g. at start): only the
    # on-chain lag decides.
    ok = await feed(33_298_414, STARTUP, lag_rounds=2)
    assert ok.healthy
    assert ok.lag_rounds == 2
    assert ok.lag_s == 6.0
    assert ok.verdict() == "drand feed ok: round 33298414, 2 behind"
    assert ok.as_dict()["cause"] is None


async def test_rate_limited_feed_fails_with_the_cause() -> None:
    bad = await feed(33_297_400, RATE_LIMITED * 100, lag_rounds=300)
    assert not bad.healthy
    assert bad.cause == "HTTP 429"
    verdict = bad.verdict()
    assert verdict.startswith("environment: drand feed failing (HTTP 429): ")
    assert "300 rounds (900 s) behind" in verdict
    assert "http_429=300" in verdict
    report = bad.as_dict()
    assert report["healthy"] is False
    assert report["errors"] == {"http_429": 300}


@pytest.mark.parametrize(
    ("lines", "cause"),
    [
        (IO_ERROR, "HTTP 5xx"),
        (STARTUP, "HTTP deadline reached"),
        (IO_ERROR[:1], "drand errors in the chain log"),
        ([], "no pulses stored"),
        (None, "cause unknown"),
    ],
)
async def test_failing_feed_causes(lines: list[str] | None, cause: str) -> None:
    bad = await feed(100, lines, lag_rounds=21)
    assert not bad.healthy
    assert bad.cause == cause
    assert bad.log_checked is (lines is not None)


async def test_never_stored_a_pulse() -> None:
    fresh = await drand.drand_feed(
        FakeClient(0), now_s=lambda: GENESIS + 3e8, read_log=lambda _c, _w: STARTUP
    )
    assert fresh.verdict().startswith(
        "environment: drand feed failing (HTTP deadline reached): "
        "no pulse stored since the chain started; chain log, last 120 s: deadline=1."
    )


async def test_lag_threshold() -> None:
    assert (await feed(100, [], lag_rounds=20)).healthy  # 60 s
    assert not (await feed(100, [], lag_rounds=21)).healthy


def test_container_log_without_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drand.shutil, "which", lambda _name: None)
    assert drand.container_log("local_chain", 10) is None


def test_main_refuses_a_remote_endpoint() -> None:
    with pytest.raises(SystemExit):
        drand.main(["--endpoint", "wss://test.finney.opentensor.ai:443"])
