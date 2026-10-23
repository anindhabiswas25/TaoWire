"""A sealed challenge answered with a sealed response, scored (spec 8.10, 16.1 row 11).

The validator seals the task (``Timelock.seal_challenge``); the miner opens
it at the reveal (``miner.timelock.open_challenge``) and answers with a
``SealedResponse``; the runner (``Task(sealed=True)``) opens the answers
before ``score``. FakeChain's round clock runs on real time here, so the
reveals (about 3 s each) really pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from tensorwire.config import MinerSettings, ValidatorSettings
from tensorwire.extensions.timelock import SealedChallenge, SealedResponse
from tensorwire.miner.app import Miner
from tensorwire.miner.routes import RouteContext
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.testing.pytest_plugin import TEST_NETUID
from tensorwire.testing.transport import AppRouter
from tensorwire.validator.client import MinerResult
from tensorwire.validator.loop import SubnetValidator, Task, ValidatorRunner

ROUTE = "/v1/sealed"
IP = "44.0.0.9"


class Question(BaseModel):
    a: int
    b: int


class Answer(BaseModel):
    total: int


class SealedValidator(SubnetValidator):
    def __init__(self) -> None:
        self.seen: dict[int, MinerResult] = {}

    async def make_task(self, round_id: int) -> Task:
        assert self.timelock is not None  # set by the runner
        challenge = await self.timelock.seal_challenge(Question(a=2, b=40), reveal_in=2)
        return Task(
            route=ROUTE,
            body=challenge.model_dump_json().encode(),
            response_model=Answer,
            sealed=True,
            expected=42,
        )

    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        self.seen = results
        return {
            uid: 1.0 if r.ok and r.data.total == task.expected else 0.0
            for uid, r in results.items()
        }


async def test_sealed_challenge_and_sealed_response_are_scored(
    tw_env: Any, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    fake_chain.set_axon(TEST_NETUID, dev_key("bob").ss58, f"{IP}:8091", protocol=87)
    gateway = fake_chain.with_signer(dev_key("bob").ss58)
    miner = Miner(
        MinerSettings(
            netuid=TEST_NETUID,
            wallet_name="bob",
            wallet_path=tmp_path / "wallets",
            external_ip=IP,
            ntp_servers=(),
            handler_timeout_s=30,
        ),
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, TEST_NETUID, clock=tw_clock.monotonic),
        hotkey=dev_key("bob").keypair,
        clock_ns=tw_clock.now_ns,
        monotonic=tw_clock.monotonic,
        check_sdk=False,
    )

    @miner.route(ROUTE, request=SealedChallenge, response=SealedResponse)
    async def solve(challenge: SealedChallenge, ctx: RouteContext) -> SealedResponse:
        question = await miner.timelock.open_challenge(challenge, Question)
        return await miner.timelock.seal_response(
            Answer(total=question.a + question.b), reveal_in=2
        )

    router = AppRouter()
    vgateway = fake_chain.with_signer(dev_key("alice").ss58)
    validator = SealedValidator()
    runner = ValidatorRunner(
        validator,
        ValidatorSettings(
            netuid=TEST_NETUID,
            wallet_name="validator",
            wallet_path=tmp_path / "vwallets",
            state_dir=tmp_path / "vstate",
            query_timeout_s=20,
            timelock_timeout_s=20,
        ),
        gateway=vgateway,
        metagraph=FakeMetagraphSource(vgateway, TEST_NETUID, clock=tw_clock.monotonic),
        hotkey=dev_key("alice").keypair,
        transport=router,
        clock_ns=tw_clock.now_ns,
        check_sdk=False,
    )
    async with miner.running() as app:
        router.add(f"{IP}:8091", app)
        await runner.start()
        try:
            await runner.run_round()
        finally:
            await runner.stop()
    (bob,) = [r for r in validator.seen.values() if r.hotkey == dev_key("bob").ss58]
    assert bob.ok, bob
    assert bob.response_verified  # the sealed body was the miner's signed answer
    assert bob.data == Answer(total=42)
    text = runner.metrics.render().decode()
    assert 'tw_timelock_open_total{result="ok"} 1.0' in text
