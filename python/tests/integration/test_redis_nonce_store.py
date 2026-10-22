"""RedisNonceStore against a real Redis (13.2). Skipped unless TENSORWIRE_TEST_REDIS_URL is set.

Engineer B owns the ``tw-redis`` container; point the variable at it, e.g.
``TENSORWIRE_TEST_REDIS_URL=redis://127.0.0.1:6379/15``.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from tensorwire.auth.nonce_store import RedisNonceStore

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
