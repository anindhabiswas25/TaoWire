"""The timelock extension on the fake backend (spec 8.10, D30; no network)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import structlog
from pydantic import BaseModel

from tensorwire.chain.gateway import (
    TimelockMalformed,
    TimelockNotReady,
    TimelockUnavailable,
)
from tensorwire.config import ValidatorSettings
from tensorwire.extensions.timelock import (
    SealedChallenge,
    SealedResponse,
    Timelock,
    parse_reveal_in,
)
from tensorwire.observability.metrics import Metrics
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.validator.client import MinerResult

pytestmark = pytest.mark.asyncio

START = 1_760_000_000.0


class Clock:
    """Wall time that only moves when someone sleeps."""

    def __init__(self) -> None:
        self.now = START
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += max(0.0, seconds)
        await asyncio.sleep(0)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def chain(clock: Clock) -> FakeChain:
    return FakeChain(wall_clock=clock)


def timelock(chain: FakeChain, clock: Clock, **kw: Any) -> Timelock:
    return Timelock(chain, sleep=clock.sleep, clock=clock, **kw)


def opens(metrics: Metrics, result: str) -> float:
    value = metrics.registry.get_sample_value(
        "tw_timelock_open_total", {"result": result}
    )
    return value or 0.0


class Task(BaseModel):
    question: str


class Answer(BaseModel):
    value: int


async def test_seal_then_open_after_the_reveal(chain: FakeChain, clock: Clock) -> None:
    metrics = Metrics()
    tl = timelock(chain, clock, metrics=metrics)
    sealed = await tl.seal(b"secret", "20s")
    assert chain.timelock_parse(sealed).reveal_at_s >= clock.now + 20
    assert await tl.open(sealed) == b"secret"  # waits (on the fake clock)
    assert clock.slept
    assert clock.slept[0] >= 20
    assert opens(metrics, "ok") == 1


async def test_not_ready_without_wait(chain: FakeChain, clock: Clock) -> None:
    metrics = Metrics()
    tl = timelock(chain, clock, metrics=metrics)
    sealed = await tl.seal(b"x", 9)
    with pytest.raises(TimelockNotReady) as early:
        await tl.open(sealed, wait=False)
    assert 9 <= early.value.remaining_s <= 12
    assert opens(metrics, "not_ready") == 1
    assert chain.calls["timelock_signature"] == 0  # no drand call when early


async def test_a_reveal_past_the_deadline_never_waits(
    chain: FakeChain, clock: Clock
) -> None:
    metrics = Metrics()
    tl = timelock(chain, clock, metrics=metrics, timeout_s=10)
    sealed = await tl.seal(b"x", "1m")
    with structlog.testing.capture_logs() as logs, pytest.raises(TimelockUnavailable):
        await tl.open(sealed)
    assert clock.slept == []
    assert opens(metrics, "unavailable") == 1
    (warning,) = [e for e in logs if e["event"] == "timelock_unavailable"]
    assert warning["log_level"] == "warning"
    assert warning["code"] == "tw.timelock_unavailable"


async def test_retries_then_success(chain: FakeChain, clock: Clock) -> None:
    tl = timelock(chain, clock, retries=3)
    sealed = await tl.seal(b"x", 3)
    clock.now += 10
    chain.fail_next("timelock_signature", 2, error=TimelockUnavailable("HTTP 429"))
    assert await tl.open(sealed) == b"x"
    assert chain.calls["timelock_signature"] == 3
    assert clock.slept == [0.5, 1.0]  # backoff, doubling


async def test_retries_exhausted_is_unavailable(chain: FakeChain, clock: Clock) -> None:
    metrics = Metrics()
    tl = timelock(chain, clock, retries=2, metrics=metrics)
    sealed = await tl.seal(b"x", 3)
    clock.now += 10
    chain.fail_next("timelock_signature", 10, error=TimelockUnavailable("HTTP 503"))
    with pytest.raises(TimelockUnavailable):
        await tl.open(sealed)
    assert chain.calls["timelock_signature"] == 3  # 1 + 2 retries
    assert opens(metrics, "unavailable") == 1
    assert opens(metrics, "ok") == 0


async def test_retries_stop_at_the_deadline(chain: FakeChain, clock: Clock) -> None:
    tl = timelock(chain, clock, retries=10, timeout_s=2)
    sealed = await tl.seal(b"x", 3)
    clock.now += 10
    chain.fail_next("timelock_signature", 100, error=TimelockUnavailable("timeout"))
    with pytest.raises(TimelockUnavailable):
        await tl.open(sealed)
    assert sum(clock.slept) <= 2.0  # never past the deadline
    assert chain.calls["timelock_signature"] < 11


async def test_a_lagging_beacon_is_waited_for(chain: FakeChain, clock: Clock) -> None:
    tl = timelock(chain, clock)
    sealed = await tl.seal(b"x", 3)
    clock.now += 10
    chain.fail_next("timelock_signature", error=TimelockNotReady(1.0))
    assert await tl.open(sealed) == b"x"
    assert chain.calls["timelock_signature"] == 2


@pytest.mark.parametrize("junk", ["", "zz", "00" * 8, "deadbeef" * 4])
async def test_junk_costs_no_drand_call(
    chain: FakeChain, clock: Clock, junk: str
) -> None:
    with pytest.raises(TimelockMalformed):
        await timelock(chain, clock).open(junk)
    assert chain.calls["timelock_signature"] == 0


async def test_the_limiter_bounds_concurrent_fetches(clock: Clock) -> None:
    release = asyncio.Event()
    in_flight = 0
    peak = 0

    class SlowDrand(FakeChain):
        async def timelock_signature(
            self, reveal_round: int, *, timeout_s: float
        ) -> str:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await release.wait()
            in_flight -= 1
            return await super().timelock_signature(reveal_round, timeout_s=timeout_s)

    chain = SlowDrand(wall_clock=clock)
    tl = timelock(chain, clock, concurrency=2)
    sealed = []
    for i in range(5):  # five different rounds: five fetches
        sealed.append(await tl.seal(b"x", 3 + 3 * i))
    clock.now += 30
    tasks = [asyncio.create_task(tl.open(s)) for s in sealed]
    for _ in range(20):
        await asyncio.sleep(0)
    assert (peak, tl.in_flight) == (2, 2)  # the other three wait for a token
    release.set()
    assert await asyncio.gather(*tasks) == [b"x"] * 5
    assert peak == 2


async def test_sealed_challenge_round_trip(chain: FakeChain, clock: Clock) -> None:
    tl = timelock(chain, clock)
    challenge = await tl.seal_challenge(Task(question="2+2"))
    assert isinstance(challenge, SealedChallenge)
    wire = SealedChallenge.model_validate_json(challenge.model_dump_json())
    # Opened right away with the default 30 s reveal and 30 s timeout: the
    # wait until the reveal does not count against the drand deadline.
    assert await tl.open_challenge(wire, Task) == Task(question="2+2")
    far = await tl.seal_challenge(Task(question="?"), reveal_in="1h")
    with pytest.raises(TimelockUnavailable):
        await tl.open_challenge(far, Task, max_wait_s=60)


def result(uid: int, data: Any, *, ok: bool = True) -> MinerResult:
    return MinerResult(
        uid=uid,
        hotkey=f"5H{uid}",
        ok=ok,
        status=200 if ok else 500,
        latency_ms=1.0,
        data=data,
        error_code=None if ok else "tw.handler_error",
        attempts=1,
        response_verified=ok,
    )


def miner(chain: FakeChain, clock: Clock, uid: int) -> Timelock:
    return timelock(chain, clock, own_hotkey=f"5H{uid}")


async def test_open_results(chain: FakeChain, clock: Clock) -> None:
    tl = timelock(chain, clock)
    good = await miner(chain, clock, 1).seal_response(Answer(value=4), reveal_in=3)
    parsed = await miner(chain, clock, 2).seal_response(Answer(value=4), reveal_in=3)
    wrong_model = await miner(chain, clock, 4).seal_response(
        Task(question="?"), reveal_in=3
    )
    late = await miner(chain, clock, 7).seal_response(Answer(value=5), reveal_in="1h")
    results = {
        1: result(1, good.model_dump_json().encode()),
        2: result(2, parsed),  # already parsed as a SealedResponse
        3: result(3, b'{"sealed": true, "ciphertext": "zz", "reveal_round": 1}'),
        4: result(4, wrong_model.model_dump_json().encode()),
        5: result(5, None, ok=False),
        6: result(6, b"not json"),
        7: result(7, late.model_dump_json().encode()),
    }
    opened = await tl.open_results(results, Answer, timeout_s=30)
    assert opened[1].data == Answer(value=4)
    assert opened[1].ok
    assert opened[1].response_verified  # still the miner's signed answer
    assert opened[2].data == Answer(value=4)
    assert (opened[3].ok, opened[3].error_code) == (False, "tw.invalid_response")
    assert opened[4].error_code == "tw.invalid_response"
    assert opened[5] is results[5]
    assert opened[6].error_code == "tw.invalid_response"
    assert (opened[7].ok, opened[7].error_code) == (False, "tw.timelock_unavailable")


async def test_a_sealed_answer_is_bound_to_its_miner(
    chain: FakeChain, clock: Clock
) -> None:
    """Security review: a copied ciphertext is not the copier's answer."""
    tl = timelock(chain, clock)
    honest = await miner(chain, clock, 1).seal_response(Answer(value=4), reveal_in=3)
    copied = {
        2: result(2, honest.model_dump_json().encode())
    }  # only the copier sent it
    opened = await tl.open_results(copied, Answer, timeout_s=30)
    assert opened[2].error_code == "tw.invalid_response"
    both = {
        1: result(1, honest.model_dump_json().encode()),
        3: result(3, honest.model_dump_json().encode()),  # the same ciphertext twice
    }
    opened = await tl.open_results(both, Answer, timeout_s=30)
    assert [opened[u].error_code for u in (1, 3)] == ["tw.invalid_response"] * 2
    with pytest.raises(RuntimeError, match="own_hotkey"):
        await tl.seal_response(Answer(value=1))  # a validator's Timelock


async def test_a_stale_challenge_is_refused_without_a_fetch(
    chain: FakeChain, clock: Clock
) -> None:
    tl = timelock(chain, clock)
    challenge = await tl.seal_challenge(Task(question="old"), reveal_in=3)
    clock.now += 600  # revealed ten minutes ago: outside the cache window
    with pytest.raises(TimelockMalformed):
        await tl.open_challenge(challenge, Task)
    assert chain.calls["timelock_signature"] == 0


async def test_settings_and_limits(chain: FakeChain, tw_env: Any) -> None:
    settings = ValidatorSettings(
        netuid=1,
        wallet_name="v",
        timelock_concurrency=3,
        timelock_retries=0,
        timelock_timeout_s=5,
    )
    tl = Timelock.from_settings(settings, chain)
    assert (tl.retries, tl.timeout_s) == (0, 5.0)
    for bad in ({"concurrency": 0}, {"retries": 11}, {"timeout_s": 0.5}):
        with pytest.raises(ValueError, match="must be"):
            Timelock(chain, **bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "seconds"),
    [("30s", 30.0), ("2m", 120.0), ("1h", 3600.0), (12, 12.0), ("7", 7.0)],
)
async def test_parse_reveal_in(value: Any, seconds: float) -> None:
    assert parse_reveal_in(value) == seconds


@pytest.mark.parametrize("value", [0, -1, "0s", float("nan"), True, None, "x"])
async def test_parse_reveal_in_refuses(value: Any) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - several messages
        parse_reveal_in(value)


async def test_sealed_response_is_a_flagged_model() -> None:
    model = SealedResponse(ciphertext="ab", reveal_round=1)
    assert model.sealed is True
    assert SealedResponse.model_validate_json(model.model_dump_json()) == model


async def test_one_signature_serves_every_ciphertext_of_a_round(
    chain: FakeChain, clock: Clock
) -> None:
    tl = timelock(chain, clock)
    first = await tl.seal(b"a", 3)
    second = await tl.seal(b"b", 3)  # same round
    clock.now += 10
    assert await asyncio.gather(tl.open(first), tl.open(second)) == [b"a", b"b"]
    assert await tl.open(first) == b"a"  # cached
    assert chain.calls["timelock_signature"] == 1


async def test_junk_of_a_good_round_costs_no_fetch_and_no_retries(
    clock: Clock,
) -> None:
    """Security review: with a checked signature a failure is the ciphertext."""
    refused: set[str] = set()

    class Strict(FakeChain):  # a decrypt that, like the real one, can refuse
        def timelock_decrypt(self, sealed_hex: str, signature_hex: str) -> bytes:
            if sealed_hex in refused:
                raise TimelockMalformed("does not open")
            return super().timelock_decrypt(sealed_hex, signature_hex)

    chain = Strict(wall_clock=clock)
    tl = timelock(chain, clock, retries=3)
    good = await tl.seal(b"honest", 3)
    junk = await tl.seal(b"junk", 3)  # same round
    refused.add(junk)
    clock.now += 10
    assert await tl.open(good) == b"honest"
    with pytest.raises(TimelockMalformed):
        await tl.open(junk)
    assert chain.calls["timelock_signature"] == 1  # no retry, no second fetch


async def test_a_lagging_beacon_never_uses_a_retry(
    chain: FakeChain, clock: Clock
) -> None:
    tl = timelock(chain, clock, retries=0)
    sealed = await tl.seal(b"x", 3)
    clock.now += 10
    chain.fail_next("timelock_signature", 3, error=TimelockNotReady(0.003))
    assert await tl.open(sealed) == b"x"  # retries=0 and still fine
    assert chain.calls["timelock_signature"] == 4


async def test_one_fetch_never_takes_the_whole_deadline(
    chain: FakeChain, clock: Clock
) -> None:
    seen: list[float] = []
    original = chain.timelock_signature

    async def spy(reveal_round: int, *, timeout_s: float) -> str:
        seen.append(timeout_s)
        return await original(reveal_round, timeout_s=timeout_s)

    chain.timelock_signature = spy  # type: ignore[method-assign]
    tl = timelock(chain, clock, timeout_s=120)
    sealed = await tl.seal(b"x", 3)
    clock.now += 10
    await tl.open(sealed)
    assert seen == [10.0]


async def test_a_failed_fetch_lets_the_waiters_try_again(
    chain: FakeChain, clock: Clock
) -> None:
    tl = timelock(chain, clock, retries=0)
    sealed = await tl.seal(b"x", 3)
    clock.now += 10
    chain.fail_next("timelock_signature", error=TimelockUnavailable("429"))
    first, second = await asyncio.gather(
        tl.open(sealed), tl.open(sealed), return_exceptions=True
    )
    outcomes = sorted([type(first).__name__, type(second).__name__])
    assert outcomes in (["TimelockUnavailable", "bytes"], ["bytes", "bytes"])


async def test_open_results_refuses_answers_sealed_before_the_query(
    chain: FakeChain, clock: Clock
) -> None:
    tl = timelock(chain, clock)
    old = await miner(chain, clock, 1).seal_response(Answer(value=1), reveal_in=3)
    clock.now += 60
    sent_at = clock.now
    fresh = await miner(chain, clock, 2).seal_response(Answer(value=2), reveal_in=3)
    results = {
        1: result(1, old.model_dump_json().encode()),
        2: result(2, fresh.model_dump_json().encode()),
    }
    opened = await tl.open_results(results, Answer, not_before=sent_at)
    assert opened[1].error_code == "tw.invalid_response"
    assert opened[2].data == Answer(value=2)
    assert chain.calls["timelock_signature"] == 1  # none for the replayed one
