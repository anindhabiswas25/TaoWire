"""RedisNonceStore against a real Redis (13.2).

Skipped unless ``TENSORWIRE_TEST_REDIS_URL`` is set.

Engineer B owns the ``tw-redis`` container; point the variable at it, e.g.
``TENSORWIRE_TEST_REDIS_URL=redis://127.0.0.1:6379/15``.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from tensorwire.auth.clock import ClockStepGuard
from tensorwire.auth.nonce_store import RedisNonceStore, StepGuardedNonceStore
from tensorwire.errors import ReplayStoreUnavailable

URL = os.environ.get("TENSORWIRE_TEST_REDIS_URL")

pytestmark = [
    pytest.mark.redis,
    pytest.mark.skipif(not URL, reason="TENSORWIRE_TEST_REDIS_URL not set"),
]


@pytest.fixture
def store() -> RedisNonceStore:
    assert URL is not None
    return RedisNonceStore(URL, retention=0.3, prefix=f"tw:test:{uuid.uuid4().hex}:")


def test_set_nx_px_on_real_redis(store: RedisNonceStore) -> None:
    assert store.ping()
    assert store.check_and_store("hk", 1)
    assert not store.check_and_store("hk", 1)
    time.sleep(0.4)
    assert store.check_and_store("hk", 1)  # expired by PX
    store.close()


def test_guarded_store_on_real_redis_fails_closed_after_a_step_back() -> None:
    """D21 on a real Redis: the key expires on Redis' clock; the guard holds."""
    assert URL is not None
    wall = [1_700_000_000 * 10**9]
    mono = [100.0]
    inner = RedisNonceStore(URL, retention=0.3, prefix=f"tw:test:{uuid.uuid4().hex}:")
    guard = ClockStepGuard(
        margin_s=0.1, hold_s=0.3, wall_ns=lambda: wall[0], monotonic=lambda: mono[0]
    )
    store = StepGuardedNonceStore(inner, guard)
    nonce = wall[0]
    assert store.check_and_store("hk", nonce)
    time.sleep(0.4)  # Redis forgot it (PX)
    wall[0] -= 10**9  # backwards step of 1 s > margin 0.1 s
    with pytest.raises(ReplayStoreUnavailable):
        store.check_and_store("hk", nonce)
    assert inner.check_and_store("hk", nonce)  # what an unguarded store would do
    mono[0] += 0.3  # both clocks move on: the window closes
    wall[0] += 3 * 10**8
    assert store.check_and_store("hk", nonce + 1)
    assert store.ping()
    store.close()
