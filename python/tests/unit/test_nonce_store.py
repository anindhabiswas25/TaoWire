"""auth/nonce_store.py: memory expiry, Redis SET NX PX, fail-closed on outage (13.2)."""

from __future__ import annotations

import sys

import fakeredis
import pytest
from bittensor import http_auth
from bittensor.keyfiles import Keypair

from tensorwire.auth.nonce_store import MemoryNonceStore, NonceStore, RedisNonceStore
from tensorwire.auth.signer import RequestSigner
from tensorwire.errors import ReplayStoreUnavailable


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------- memory


def test_memory_detects_replay() -> None:
    store = MemoryNonceStore()
    assert store.check_and_store("hk", 1) is True
    assert store.check_and_store("hk", 1) is False
    assert store.check_and_store("hk", 2) is True
    assert store.check_and_store("other", 1) is True


def test_memory_expiry() -> None:
    clock = FakeClock()
    store = MemoryNonceStore(retention=12.0, clock=clock)
    assert store.check_and_store("hk", 1)
    clock.now += 11.9
    assert not store.check_and_store("hk", 1)
    assert store.check_and_store("hk", 2)
    assert len(store) == 2
    clock.now += 0.1  # first entry hits its expiry exactly
    assert len(store) == 1
    assert store.check_and_store(
        "hk", 1
    )  # forgotten: outside the freshness window anyway
    clock.now += 100
    assert len(store) == 0


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf")])
def test_retention_must_be_positive(bad: float) -> None:
    with pytest.raises(ValueError, match="retention"):
        MemoryNonceStore(retention=bad)
    with pytest.raises(ValueError, match="retention"):
        RedisNonceStore("redis://x", retention=bad, client=fakeredis.FakeRedis())


def test_stores_satisfy_protocol() -> None:
    assert isinstance(MemoryNonceStore(), NonceStore)
    assert isinstance(
        RedisNonceStore("redis://x", client=fakeredis.FakeRedis()), NonceStore
    )


def test_memory_store_with_sdk_verify(alice: Keypair, bob: Keypair) -> None:
    store = MemoryNonceStore(retention=12.0)
    headers = RequestSigner(alice).sign(
        method="POST", target="/r", body=b"x", receiver_ss58=bob.ss58_address
    )
    kw = {
        "method": "POST",
        "path": "/r",
        "self_hotkey_ss58": bob.ss58_address,
        "nonce_store": store,
    }
    http_auth.verify(headers, b"x", **kw)
    with pytest.raises(http_auth.ReplayedRequest):
        http_auth.verify(headers, b"x", **kw)


def test_short_retention_is_refused_by_sdk_verify(alice: Keypair, bob: Keypair) -> None:
    """Fact A3: the SDK refuses a store whose retention is shorter than the window."""
    headers = RequestSigner(alice).sign(
        method="POST", target="/r", body=b"", receiver_ss58=bob.ss58_address
    )
    with pytest.raises(ValueError, match="retains entries for 5s"):
        http_auth.verify(
            headers,
            b"",
            method="POST",
            path="/r",
            self_hotkey_ss58=bob.ss58_address,
            nonce_store=MemoryNonceStore(retention=5.0),
        )


# --------------------------------------------------------------- redis


@pytest.fixture
def server() -> fakeredis.FakeServer:
    return fakeredis.FakeServer()


@pytest.fixture
def store(server: fakeredis.FakeServer) -> RedisNonceStore:
    return RedisNonceStore(
        "redis://unused", retention=12.5, client=fakeredis.FakeRedis(server=server)
    )


def test_redis_set_nx_px(store: RedisNonceStore, server: fakeredis.FakeServer) -> None:
    probe = fakeredis.FakeRedis(server=server)
    assert store.retention == 12.5
    assert store.check_and_store("5Hk", 42) is True
    assert store.check_and_store("5Hk", 42) is False
    assert store.check_and_store("5Hk", 43) is True
    assert probe.get("tw:n:5Hk:42") == b"1"
    assert 12_000 < probe.pttl("tw:n:5Hk:42") <= 12_500  # PX = retention in ms


def test_redis_shared_between_workers(server: fakeredis.FakeServer) -> None:
    a = RedisNonceStore("redis://unused", client=fakeredis.FakeRedis(server=server))
    b = RedisNonceStore("redis://unused", client=fakeredis.FakeRedis(server=server))
    assert a.check_and_store("hk", 1)
    assert not b.check_and_store("hk", 1)  # a replay on another worker is caught


def test_redis_prefix(server: fakeredis.FakeServer) -> None:
    s = RedisNonceStore(
        "redis://unused", prefix="sn7:", client=fakeredis.FakeRedis(server=server)
    )
    s.check_and_store("hk", 1)
    assert fakeredis.FakeRedis(server=server).exists("sn7:hk:1")


def test_redis_outage_fails_closed(
    store: RedisNonceStore, server: fakeredis.FakeServer
) -> None:
    assert store.ping() is True
    server.connected = False
    with pytest.raises(ReplayStoreUnavailable) as info:
        store.check_and_store("hk", 1)
    assert info.value.http_status == 503
    assert info.value.code == "tw.replay_store_unavailable"
    assert store.ping() is False


def test_redis_outage_propagates_through_sdk_verify(
    store: RedisNonceStore, server: fakeredis.FakeServer, alice: Keypair, bob: Keypair
) -> None:
    """The SDK does not swallow the store error: 503, not an AuthError."""
    server.connected = False
    headers = RequestSigner(alice).sign(
        method="POST", target="/r", body=b"", receiver_ss58=bob.ss58_address
    )
    with pytest.raises(ReplayStoreUnavailable):
        http_auth.verify(
            headers,
            b"",
            method="POST",
            path="/r",
            self_hotkey_ss58=bob.ss58_address,
            nonce_store=store,
        )


def test_redis_from_url_uses_short_timeouts() -> None:
    s = RedisNonceStore("redis://127.0.0.1:1/0")
    kwargs = s._r.connection_pool.connection_kwargs
    assert kwargs["socket_timeout"] == 0.25
    assert kwargs["socket_connect_timeout"] == 0.5
    with pytest.raises(ReplayStoreUnavailable):
        s.check_and_store("hk", 1)  # nothing listens on port 1
    s.close()


def test_redis_extra_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "redis", None)
    with pytest.raises(RuntimeError, match=r"tensorwire\[redis\]"):
        RedisNonceStore("redis://x")


def test_memory_store_survives_a_wall_clock_step_back() -> None:
    """A backwards wall-clock step must not make a forgotten nonce fresh again.

    Freshness is judged on the wall clock; the pair stays until its nonce is
    older than the retention there too (Go/Rust MemoryStore do the same).
    """
    mono, wall = [0.0], [1_000 * 10**9]
    nonce = wall[0]
    store = MemoryNonceStore(12, clock=lambda: mono[0], wall_ns=lambda: wall[0])
    assert store.check_and_store("hk", nonce)
    mono[0], wall[0] = 20.0, nonce + 5 * 10**9  # 20 s passed, wall stepped back 15 s
    assert not store.check_and_store("hk", nonce)
    mono[0], wall[0] = 21.0, nonce + 13 * 10**9
    assert store.check_and_store("hk", nonce)
