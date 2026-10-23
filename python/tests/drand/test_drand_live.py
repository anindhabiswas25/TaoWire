"""One real timelock round trip through the public drand API (spec 8.10, 3.7).

Opt-in (``just drand-test``; marker ``drand``, not part of ``just test``):
the localnet chain uses the same public endpoint and already gets HTTP 429,
so this makes exactly one fetch.
"""

from __future__ import annotations

import time

import pytest

from tensorwire.chain.gateway import BittensorGateway, TimelockNotReady
from tensorwire.extensions.timelock import Timelock
from tensorwire.observability.metrics import Metrics

pytestmark = [pytest.mark.drand, pytest.mark.asyncio]


async def test_seal_and_open_through_drand() -> None:
    gateway = BittensorGateway("local")  # timelock needs no chain connection
    metrics = Metrics()
    tl = Timelock(gateway, retries=2, timeout_s=60, metrics=metrics)
    sealed = await tl.seal(b"tensorwire drand check", "3s")
    with pytest.raises(TimelockNotReady):
        await tl.open(sealed, wait=False)  # local check, no fetch
    started = time.monotonic()
    assert await tl.open(sealed) == b"tensorwire drand check"
    assert time.monotonic() - started < 60
    assert (
        metrics.registry.get_sample_value("tw_timelock_open_total", {"result": "ok"})
        == 1
    )
