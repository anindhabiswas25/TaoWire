#!/usr/bin/env python3
"""Is the localnet chain's drand feed working? (spec 14.2, G3-8)

Timelocked weight commits (commit-reveal) are revealed only once the chain has
stored the drand pulse for the commit's reveal round. The localnet chain fetches
pulses from api.drand.sh in an off-chain worker; when that endpoint rate-limits
the host (HTTP 429), no pulse is stored, nothing is revealed, and a test that
waits for a reveal can only time out. This tool tells that apart from a defect.

Two signals:

1. On chain (authoritative): ``Drand.LastStoredRound`` against the round the
   wall clock says is current, from the chain's own ``Drand.BeaconConfig``
   (genesis time and period). A healthy feed is a few rounds behind at most.
2. The cause, from the chain container's log over the last ``--window`` seconds:
   ``Drand: Unexpected status code: 429``, ``HTTP Deadline Reached``, other
   ``Drand:`` errors. Optional: without Docker access the cause is "unknown".

Read-only. Exit status 0 when the feed is healthy, 1 when it is failing, 2 when
the chain could not be read.

Usage:
    python scripts/drand_feed.py [--endpoint ws://127.0.0.1:9944]
        [--container local_chain] [--window 120] [--json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

import bittensor as bt

#: A feed further behind than this is failing (pulses come every 3 s; the
#: off-chain worker catches up within a few blocks when the endpoint answers).
MAX_LAG_S = 60.0
#: Container log lookback for the cause.
WINDOW_S = 120
CONTAINER = "local_chain"
LOCAL_PREFIXES = ("ws://127.0.0.1:", "ws://localhost:")

_STATUS = re.compile(r"Drand: Unexpected status code: (\d{3})")
_DRAND = re.compile(r"Drand: (.*)")


@dataclass(frozen=True)
class DrandFeed:
    """The chain's drand feed at one moment."""

    last_stored_round: int
    expected_round: int
    period_s: int
    lag_rounds: int
    lag_s: float
    errors: dict[str, int] = field(default_factory=dict)
    """``Drand:`` error lines in the container log window, by kind
    (``http_429``, ``http_5xx``, ``deadline``, ``other``); empty without
    Docker access."""
    log_checked: bool = False
    last_error: str | None = None
    window_s: int = WINDOW_S

    @property
    def healthy(self) -> bool:
        """Pulses are being stored (the lag is within :data:`MAX_LAG_S`)."""
        return self.lag_s <= MAX_LAG_S

    @property
    def cause(self) -> str:
        """The most likely reason for a lag, from the log."""
        if self.errors.get("http_429"):
            return "HTTP 429"
        if self.errors.get("http_5xx"):
            return "HTTP 5xx"
        if self.errors.get("deadline"):
            return "HTTP deadline reached"
        if self.errors.get("other"):
            return "drand errors in the chain log"
        return "no pulses stored" if self.log_checked else "cause unknown"

    def verdict(self) -> str:
        """One line for test failures and the probe report."""
        if self.healthy:
            return (
                f"drand feed ok: round {self.last_stored_round}, "
                f"{self.lag_rounds} behind"
            )
        counts = ", ".join(f"{k}={v}" for k, v in sorted(self.errors.items()))
        where = (
            "no pulse stored since the chain started"
            if self.last_stored_round == 0
            else f"last stored round {self.last_stored_round}, {self.lag_rounds} "
            f"rounds ({self.lag_s:.0f} s) behind the wall clock"
        )
        return (
            f"environment: drand feed failing ({self.cause}): {where}"
            + (f"; chain log, last {self.window_s} s: {counts}" if counts else "")
            + ". Timelocked weight commits cannot be revealed until the chain "
            "stores pulses again (spec 14.2)."
        )

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready, with the derived fields."""
        return {
            **asdict(self),
            "healthy": self.healthy,
            "cause": None if self.healthy else self.cause,
            "verdict": self.verdict(),
        }


def classify(lines: Iterable[str]) -> tuple[dict[str, int], str | None]:
    """Count ``Drand:`` error lines by kind; return the counts and the last one."""
    counts: Counter[str] = Counter()
    last: str | None = None
    for line in lines:
        match = _DRAND.search(line)
        if match is None:
            continue
        text = match.group(1).strip()
        status = _STATUS.search(line)
        if status is not None:
            code = status.group(1)
            kind = (
                "http_429"
                if code == "429"
                else "http_5xx"
                if code.startswith("5")
                else "other"
            )
        elif "Deadline Reached" in text:
            kind = "deadline"
        elif "No valid response" in text:
            continue  # follows every failed fetch: not a cause of its own
        else:
            kind = "other"
        counts[kind] += 1
        last = text[:200]
    return dict(counts), last


def container_log(container: str, window_s: int) -> list[str] | None:
    """The container's log lines of the last ``window_s`` seconds, or ``None``."""
    docker = shutil.which("docker")
    if docker is None:
        return None
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv
            [docker, "logs", "--since", f"{window_s}s", container],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    # The node logs to stderr.
    text = (done.stdout + done.stderr).decode("utf-8", errors="replace")
    return text.splitlines()


def expected_round(genesis_time: int, period_s: int, now_s: float) -> int:
    """The latest drand round at ``now_s`` (round 1 is at genesis)."""
    return int((now_s - genesis_time) // period_s) + 1


async def drand_feed(
    client: Any,
    *,
    container: str | None = CONTAINER,
    window_s: int = WINDOW_S,
    now_s: Callable[[], float] = time.time,
    read_log: Callable[[str, int], list[str] | None] = container_log,
) -> DrandFeed:
    """Read the feed from ``client`` (a connected ``bittensor`` async client)."""
    last = int(await client.query(("Drand", "LastStoredRound"), []) or 0)
    config = await client.query(("Drand", "BeaconConfig"), [])
    period = int(config["period"])
    want = expected_round(int(config["genesis_time"]), period, now_s())
    lag = max(0, want - last)
    lines = read_log(container, window_s) if container else None
    errors, last_error = classify(lines) if lines is not None else ({}, None)
    return DrandFeed(
        last_stored_round=last,
        expected_round=want,
        period_s=period,
        lag_rounds=lag,
        lag_s=float(lag * period),
        errors=errors,
        log_checked=lines is not None,
        last_error=last_error,
        window_s=window_s,
    )


async def _read(endpoint: str, container: str | None, window_s: int) -> DrandFeed:
    async with bt.Subtensor(endpoint, fallback_endpoints=[]) as client:
        return await drand_feed(client, container=container, window_s=window_s)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--endpoint", default="ws://127.0.0.1:9944")
    parser.add_argument("--container", default=CONTAINER, help="'' to skip the log")
    parser.add_argument("--window", type=int, default=WINDOW_S)
    parser.add_argument("--json", action="store_true", help="print the full report")
    args = parser.parse_args(argv)
    if not args.endpoint.startswith(LOCAL_PREFIXES):
        parser.error("refusing to run against a non-local endpoint")
    try:
        feed = asyncio.run(_read(args.endpoint, args.container or None, args.window))
    except (OSError, ConnectionError, TimeoutError, KeyError, TypeError) as exc:
        print(f"cannot read the drand feed: {type(exc).__name__}: {exc}")
        return 2
    print(json.dumps(feed.as_dict(), indent=2) if args.json else feed.verdict())
    return 0 if feed.healthy else 1


if __name__ == "__main__":
    sys.exit(main())
