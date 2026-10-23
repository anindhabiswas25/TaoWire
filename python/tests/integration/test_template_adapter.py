"""``compat.TemplateValidatorAdapter`` (spec 10b.2.4): the template's validator
base on the kit's runner, against a real compat miner on FakeChain."""

from __future__ import annotations

import asyncio
import math
import socket
import sys
import threading
import time
import typing
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import structlog

from tensorwire.compat import Axon, Synapse, TemplateValidatorAdapter
from tensorwire.compat.template import _TemplateRounds
from tensorwire.config import ValidatorSettings
from tensorwire.miner.app import Miner
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.testing.pytest_plugin import TEST_NETUID
from tensorwire.testing.transport import AppRouter
from tensorwire.validator.loop import Task

MINER_AXON = "44.1.2.3:8091"  # the plugin miner's TW_EXTERNAL_IP:TW_BIND_PORT


class Dummy(Synapse):
    dummy_input: int
    dummy_output: typing.Optional[int] = None  # noqa: UP045 - template code as is
    required_hash_fields: typing.ClassVar[tuple[str, ...]] = ("dummy_input",)

    def deserialize(self) -> int | None:  # type: ignore[override]
        return self.dummy_output


class Validator(TemplateValidatorAdapter):
    """The template's ``forward`` (sample all miners, reward ``2 * step``)."""

    async def forward(self) -> None:
        uids = [
            uid
            for uid in range(self.metagraph.n)
            if self.metagraph.axons[uid].is_serving
        ][: self.config.neuron.sample_size]
        responses = await self.dendrite(
            axons=[self.metagraph.axons[uid] for uid in uids],
            synapse=Dummy(dummy_input=self.step),
            deserialize=True,
        )
        rewards = [1.0 if r == self.step * 2 else 0.0 for r in responses]
        self.update_scores(rewards, uids)


def settings(tmp_path: Path, **extra: Any) -> ValidatorSettings:
    return ValidatorSettings(
        netuid=TEST_NETUID,
        wallet_name="validator",
        wallet_path=tmp_path / "wallets",
        state_dir=tmp_path / "state",
        weights_version_key=7,
        **extra,
    )


def parts(
    fake_chain: FakeChain, clock: FakeClock, router: AppRouter, key: str = "alice"
) -> dict[str, Any]:
    gateway = fake_chain.with_signer(dev_key(key).ss58)
    return {
        "hotkey": dev_key(key).keypair,
        "gateway": gateway,
        "metagraph_source": FakeMetagraphSource(
            gateway, TEST_NETUID, clock=clock.monotonic
        ),
        "transport": router,
        "check_sdk": False,
    }


@pytest.fixture
async def router(tw_miner_kwargs: dict[str, Any]) -> AsyncIterator[AppRouter]:
    miner = Miner(**tw_miner_kwargs)
    axon = Axon(miner=miner)

    async def forward(synapse: Dummy) -> Dummy:
        synapse.dummy_output = synapse.dummy_input * 2
        return synapse

    axon.attach(forward_fn=forward)
    async with miner.running() as app:
        yield AppRouter({MINER_AXON: app})


@pytest.fixture(autouse=True)
def _no_cli_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["validator"])


async def test_steps_score_and_set_weights_with_the_kit_version_key(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    v = Validator(settings=settings(tmp_path), **parts(fake_chain, tw_clock, router))
    await v.start()
    try:
        miner_uid = v.metagraph.hotkeys.index(dev_key("bob").ss58)
        assert v.uid == v.hotkeys.index(dev_key("alice").ss58)
        assert v.block == v.runner.metagraph.snapshot().block
        assert v.gateway is not None
        report = await v.step_once()
        assert report is not None
        assert (report.n_ok, report.n_btauth, report.n_v10) == (1, 1, 0)
        assert v.step == 1
        assert v.scores[miner_uid] == pytest.approx(0.1)
        assert len(v.scores) == v.metagraph.n
        assert report.weights.reason == "not_due"  # the chain's rate limit
        fake_chain.advance(100)
        report = await v.step_once()
        assert report is not None
        assert report.weights.reason == "submitted"
        assert v.scores[miner_uid] == pytest.approx(0.19)
        (submission,) = fake_chain.weight_submissions()
        assert submission.version_key == 7  # TW_WEIGHTS_VERSION_KEY, not spec_version
        assert set(submission.weights) == {miner_uid}
        metrics = v.runner.metrics.render().decode()
        assert 'tw_validator_miners_by_protocol{protocol="btauth/1"} 1.0' in metrics
        decision = await v.set_weights()
        assert decision.reason == "not_due"
    finally:
        await v.stop()
        await v.stop()  # safe twice

    # The step count and scores persist in TW_STATE_DIR.
    again = Validator(
        settings=settings(tmp_path), **parts(fake_chain, tw_clock, router)
    )
    await again.start()
    try:
        assert again.step == 2
        assert again.scores[miner_uid] == pytest.approx(0.19)
    finally:
        await again.stop()


async def test_disable_set_weights(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    config = SimpleNamespace(neuron=SimpleNamespace(disable_set_weights=True))
    v = Validator(
        config, settings=settings(tmp_path), **parts(fake_chain, tw_clock, router)
    )
    await v.start()
    try:
        report = await v.step_once()
        assert report is not None
        assert report.weights.reason == "disabled"
        assert fake_chain.weight_submissions() == ()
    finally:
        await v.stop()


async def test_update_scores_rules(
    router: AppRouter,
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
) -> None:
    v = Validator(settings=settings(tmp_path), **parts(fake_chain, tw_clock, router))
    await v.start()
    try:
        miner_uid = v.metagraph.hotkeys.index(dev_key("bob").ss58)
        own = v.uid
        with pytest.raises(ValueError, match="Shape mismatch"):
            v.update_scores([1.0, 0.5], [miner_uid])
        v.update_scores([], [])  # nothing happens
        v.update_scores(
            [math.nan, 5.0, 1.0], [miner_uid, own, 9999]
        )  # 9999: no such uid
        assert v.scores[miner_uid] == 0.0
        assert v.scores[own] == pytest.approx(0.1)  # clamped to 1, EMA 0.1
        with structlog.testing.capture_logs() as logs:
            v.update_scores([7.0], [own])  # warned once only
        assert not [e for e in logs if e["event"] == "template_reward_clamped"]
        v.resync_metagraph()
        v.save_state()
        v.load_state()
    finally:
        await v.stop()


def test_config_comes_from_settings_and_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Custom(Validator):
        @classmethod
        def add_args(cls, parser: Any) -> None:
            super().add_args(parser)
            parser.add_argument("--custom.flag", type=int, default=3)

    monkeypatch.setattr(
        sys,
        "argv",
        ["v", "--neuron.num_concurrent_forwards", "2", "--custom.flag", "9", "--x"],
    )
    s = settings(tmp_path, sample_size=5, query_timeout_s=3.0, score_alpha=0.2)
    config = Custom.config_from(s)
    assert config.netuid == TEST_NETUID
    assert config.custom.flag == 9
    n = config.neuron
    assert (n.num_concurrent_forwards, n.sample_size, n.timeout) == (2, 5, 3.0)
    assert n.moving_average_alpha == 0.2
    assert n.epoch_length == s.min_weight_interval_blocks
    assert n.full_path == str(s.state_dir)
    assert (n.vpermit_tao_limit, n.disable_set_weights) == (4096, False)
    given = TemplateValidatorAdapter.config_from(s, SimpleNamespace(netuid=99))
    assert given.netuid == TEST_NETUID  # the kit's netuid wins
    assert given.neuron.name == "validator"


async def test_before_start(tmp_path: Path) -> None:
    v = Validator(settings=settings(tmp_path), check_sdk=False)
    with pytest.raises(RuntimeError, match="not started"):
        _ = v.dendrite
    with pytest.raises(RuntimeError, match="not started"):
        await v.set_weights()
    with pytest.raises(RuntimeError, match="not started"):
        v.update_scores([1.0], [0])
    with pytest.raises(NotImplementedError):
        await TemplateValidatorAdapter(
            settings=settings(tmp_path), check_sdk=False
        ).forward()
    task = Task(route="/x", body=b"")
    with pytest.raises(NotImplementedError):
        await _TemplateRounds().make_task(1)
    with pytest.raises(NotImplementedError):
        await _TemplateRounds().score(task, {})


def test_run_exits_3_when_not_registered(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    v = Validator(
        settings=settings(tmp_path), **parts(fake_chain, tw_clock, AppRouter(), "dave")
    )
    with pytest.raises(SystemExit) as exit_info:
        v.run()
    assert exit_info.value.code == 3


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Counting(TemplateValidatorAdapter):
    """No queries: rewards the miner every step (background-mode test)."""

    async def forward(self) -> None:
        self.update_scores([1.0], [self.metagraph.hotkeys.index(dev_key("bob").ss58)])


def test_with_block_runs_steps_in_the_background_and_serves_metrics(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    port = _free_port()
    s = settings(tmp_path, round_interval_s=1, metrics_bind=f"127.0.0.1:{port}")
    v = Counting(settings=s, **parts(fake_chain, tw_clock, AppRouter()))
    with v:
        assert v.is_running
        v.run_in_background_thread()  # already running: nothing happens
        deadline = time.monotonic() + 20
        while v.step < 2 and time.monotonic() < deadline:
            time.sleep(0.1)
        ready = httpx.get(f"http://127.0.0.1:{port}/readyz", timeout=5)
        metrics = httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=5).text
    assert v.step >= 2
    assert ready.json() == {"status": "ready"}
    assert "tw_validator_round_duration_seconds_count" in metrics
    assert not v.is_running
    v.stop_run_thread()  # not running: nothing happens


def test_sigterm_in_a_with_block_stops_cleanly(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    import os
    import signal

    s = settings(tmp_path, round_interval_s=1, metrics_bind=f"127.0.0.1:{_free_port()}")
    v = Counting(settings=s, **parts(fake_chain, tw_clock, AppRouter()))
    timer = threading.Timer(1.5, os.kill, (os.getpid(), signal.SIGTERM))

    def main_block() -> None:  # neurons/validator.py's __main__ in v10
        with v:
            timer.start()
            while True:
                time.sleep(0.1)

    with pytest.raises(KeyboardInterrupt):
        main_block()
    assert not v.is_running
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL


async def test_no_snapshot_skips_the_step(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    v = Validator(settings=settings(tmp_path), **parts(fake_chain, tw_clock, router))
    await v.start()
    try:
        source: Any = v.runner.metagraph
        real = source.snapshot
        source.snapshot = lambda: None
        assert await v.step_once() is None
        source.snapshot = real
        assert await asyncio.wait_for(v.step_once(), 10) is not None
    finally:
        await v.stop()
