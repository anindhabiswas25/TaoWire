"""testing/: dev keys, FakeClock, FakeMetagraphSource, SignedClient (spec 8.13)."""

from __future__ import annotations

import pytest

from tensorwire.chain.metagraph_cache import StalenessStage
from tensorwire.crypto import CRYPTO_ED25519, CRYPTO_SR25519
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import DEV_NAMES, dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource

APPENDIX_C_ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
APPENDIX_C_ALICE_ED = "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"


def test_dev_keys_match_appendix_c() -> None:
    assert dev_key("alice").ss58 == APPENDIX_C_ALICE
    assert dev_key("alice", "ed25519").ss58 == APPENDIX_C_ALICE_ED
    assert dev_key("alice").keypair.crypto_type == CRYPTO_SR25519
    assert dev_key("alice", "ed25519").keypair.crypto_type == CRYPTO_ED25519
    assert dev_key("bob") is dev_key("bob")  # cached
    assert len({dev_key(n).ss58 for n in DEV_NAMES}) == 5


def test_dev_key_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown test key"):
        dev_key("mallory")
    with pytest.raises(ValueError, match="unsupported scheme"):
        dev_key("alice", "ecdsa")  # type: ignore[arg-type]


def test_dev_key_signer_uses_the_given_clock() -> None:
    clock = FakeClock(start_ns=1_752_076_800_000_000_000)
    headers = (
        dev_key("alice")
        .signer(clock_ns=clock.now_ns)
        .sign(method="POST", target="/x", body=b"", receiver_ss58=dev_key("bob").ss58)
    )
    assert headers["X-Bittensor-Nonce"] == "1752076800000000000"


def test_fake_clock() -> None:
    clock = FakeClock(start_ns=10**18, monotonic_start=5.0)
    clock.advance(1.5)
    assert (clock.now_ns(), clock.monotonic(), clock.time()) == (
        10**18 + 1_500_000_000,
        6.5,
        1e9 + 1.5,
    )
    clock.step_wall(-2)
    assert clock.now_ns() == 10**18 - 500_000_000
    assert clock.monotonic() == 6.5
    with pytest.raises(ValueError, match="forward"):
        clock.advance(-1)


async def test_fake_metagraph_source_stages() -> None:
    clock = FakeClock()
    chain = FakeChain(monotonic=clock.monotonic)
    chain.add_subnet(1, tempo=10)
    chain.register(1, dev_key("alice").ss58)
    await chain.connect()
    source = FakeMetagraphSource(chain, 1, clock=clock.monotonic)
    assert source.netuid == 1
    assert (source.snapshot(), source.age_s(), source.by_hotkey("x")) == (
        None,
        None,
        None,
    )
    assert source.stage() is StalenessStage.KNOWN_CALLERS_ONLY
    await source.start()
    assert source.started
    # tempo 10 → max 240 s, soft capped at half of it (B's for_tempo rule)
    assert (source.thresholds.soft_age_s, source.thresholds.max_age_s) == (120, 240)
    assert source.by_hotkey(dev_key("alice").ss58) is not None
    clock.advance(120)
    assert source.stage() is StalenessStage.DEGRADED
    clock.advance(121)
    assert source.stage() is StalenessStage.KNOWN_CALLERS_ONLY
    await source.stop()
    assert source.stopped


async def test_fake_metagraph_source_respects_operator_settings() -> None:
    clock = FakeClock()
    chain = FakeChain(monotonic=clock.monotonic)
    chain.add_subnet(1)
    await chain.connect()
    source = FakeMetagraphSource(
        chain, 1, soft_age_s=5, max_age_s=50, clock=clock.monotonic
    )
    await source.refresh_now()
    assert (source.thresholds.soft_age_s, source.thresholds.max_age_s) == (5, 50)
