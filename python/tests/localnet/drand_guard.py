"""Fail reveal-dependent localnet tests fast when the chain's drand feed fails (G3-8).

A timelocked weight commit is revealed only after the chain stores the drand
pulse for its reveal round. When api.drand.sh rate-limits the host, no pulse
arrives and a reveal wait can only time out (Phase 2 gate re-run: HTTP 429 for
15+ minutes, then a 600 s timeout). That is an environment failure, not a kit
defect, so these tests check the feed before they commit and while they wait,
and fail with ``environment: drand feed failing (<cause>)`` instead.

Never a reason to turn commit-reveal off: the tests keep waiting for a real
reveal while the feed is healthy.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "drand_feed.py"
#: How often a wait re-reads the feed.
CHECK_EVERY_S = 15.0
#: Consecutive failing reads before a wait gives up (one blip is tolerated).
FAILING_READS = 2
#: The chain container whose log names the cause (``localnet_up.sh`` default).
CONTAINER = os.environ.get("LOCALNET_CHAIN_CONTAINER", "local_chain")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("drand_feed", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["drand_feed"] = module
    spec.loader.exec_module(module)
    return module


drand_feed = _load()


async def require_drand_feed(client: Any) -> Any:
    """Before a commit: fail now if the feed is already failing."""
    feed = await drand_feed.drand_feed(client, container=CONTAINER)
    if not feed.healthy:
        pytest.fail(feed.verdict(), pytrace=False)
    return feed


class DrandWatch:
    """Call :meth:`check` from a wait loop; it reads the feed every
    :data:`CHECK_EVERY_S` and fails the test after :data:`FAILING_READS`
    failing reads in a row."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self._next = 0.0
        self._failing = 0
        self.reads: list[dict[str, Any]] = []

    async def check(self) -> None:
        """Read the feed if it is time; fail the test when it keeps failing."""
        now = time.monotonic()
        if now < self._next:
            return
        self._next = now + CHECK_EVERY_S
        feed = await drand_feed.drand_feed(self._client, container=CONTAINER)
        self.reads.append(feed.as_dict())
        self._failing = 0 if feed.healthy else self._failing + 1
        if self._failing >= FAILING_READS:
            pytest.fail(feed.verdict(), pytrace=False)
