"""The template's neuron surface on the kit (10b.2.4, D18): ``TemplateMinerAdapter``
and what ``TemplateValidatorAdapter`` offers a customised base (eager start,
``wallet`` / ``subtensor`` / ``sync``)."""

from __future__ import annotations

import os
import signal
import socket
import sys
import threading
import time
import typing
from pathlib import Path
from typing import Any

import httpx
import pytest

from tensorwire.compat import Synapse, TemplateMinerAdapter, TemplateValidatorAdapter
from tensorwire.compat.neuron import interrupt
from tensorwire.compat.template_miner import EPOCH_POLL_S
from tensorwire.config import HostPort, ValidatorSettings
from tensorwire.miner.app import Miner
from tensorwire.testing.client import SignedClient
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.testing.pytest_plugin import TEST_NETUID
from tensorwire.testing.transport import AppRouter

ALICE = dev_key("alice")
BOB = dev_key("bob")


class Dummy(Synapse):
    dummy_input: int
    dummy_output: typing.Optional[int] = None  # noqa: UP045 - template code as is
    required_hash_fields: typing.ClassVar[tuple[str, ...]] = ("dummy_input",)


class TemplateMiner(TemplateMinerAdapter):
    """A customised template miner after ``migrate apply`` (TWM031)."""

    def __init__(self, config: Any = None, *, miner: Miner | None = None) -> None:
        super().__init__(config, miner=miner)
        self.axon.attach(forward_fn=self.forward, blacklist_fn=self.blacklist)
        self.blacklisted: set[str] = set()
        self.resyncs = 0

    async def forward(self, synapse: Dummy) -> Dummy:
        synapse.dummy_output = synapse.dummy_input * 2
        return synapse

    async def blacklist(self, synapse: Dummy) -> tuple[bool, str]:
        hotkey = synapse.dendrite.hotkey  # type: ignore[union-attr]
        return hotkey in self.blacklisted, "blacklisted"

    def resync_metagraph(self) -> None:
        self.resyncs += 1


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(autouse=True)
def _no_cli_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["neuron"])


# ---------------------------------------------------------------- miner adapter


async def test_miner_adapter_serves_the_subnets_forward_and_blacklist(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    miner = Miner(**tw_miner_kwargs)
    m = TemplateMiner(miner=miner)
    assert m.config.netuid == TEST_NETUID
    assert m.config.wallet.name == "miner"
    assert m.config.neuron.epoch_length == 100
    assert m.wallet.hotkey.ss58_address == BOB.ss58  # before start: the given key
    async with miner.running() as app:
        assert m.uid == m.metagraph.hotkeys.index(BOB.ss58)
        assert m.block == m.subtensor.get_current_block()
        assert m.subtensor.is_hotkey_registered(hotkey_ss58=BOB.ss58)
        assert m.wallet.hotkey.ss58_address == BOB.ss58
        client = SignedClient(app, receiver_ss58=BOB.ss58, clock_ns=tw_clock.now_ns)
        r = await client.post("/Dummy", json={"dummy_input": 21})
        assert (r.status_code, r.json()["dummy_output"]) == (200, 42)
        m.blacklisted.add(ALICE.ss58)
        r = await client.post("/Dummy", json={"dummy_input": 1})
        assert r.status_code == 403
        await client.aclose()


async def test_miner_adapter_syncs_once_per_epoch(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["miner", "--neuron.epoch_length", "3"])
    miner = Miner(**tw_miner_kwargs)
    m = TemplateMiner(miner=miner)
    assert m.config.neuron.epoch_length == 3
    assert not m.epoch_tick()  # not serving yet
    async with miner.running():
        assert not m.epoch_tick()  # first look: the epoch starts here
        fake_chain.advance(2)
        await miner.lifecycle.runtime.metagraph.refresh_now()
        assert not m.epoch_tick()
        fake_chain.advance(1)
        await miner.lifecycle.runtime.metagraph.refresh_now()
        assert m.epoch_tick()
        assert (m.resyncs, m.step) == (1, 1)


def test_miner_reads_the_chain_before_it_serves(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    """v10's BaseNeuron.__init__ checked registration: one pre-flight read."""
    m = TemplateMiner(miner=Miner(**tw_miner_kwargs))
    assert m.subtensor.is_hotkey_registered(hotkey_ss58=BOB.ss58)
    assert m.uid == m.metagraph.hotkeys.index(BOB.ss58)
    block = m.block
    fake_chain.advance(5)
    assert m.block == block  # the pre-flight snapshot, until the miner serves


async def test_in_async_code_the_miner_reads_after_it_starts(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    m = TemplateMiner(miner=Miner(**tw_miner_kwargs))
    with pytest.raises(RuntimeError, match="has not started"):
        _ = m.uid


def _real_ports(kwargs: dict[str, Any]) -> tuple[dict[str, Any], int]:
    port = _free_port()
    settings = kwargs["settings"].model_copy(
        update={
            "bind_host": "127.0.0.1",
            "bind_port": port,
            "metrics_bind": HostPort("127.0.0.1", _free_port()),
        }
    )
    return {**kwargs, "settings": settings}, port


def test_miner_with_block_serves_in_the_background(
    tw_miner_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("tensorwire.compat.template_miner.EPOCH_POLL_S", 0.2)
    kwargs, port = _real_ports(tw_miner_kwargs)
    m = TemplateMiner(miner=Miner(**kwargs))
    with m:
        assert m.is_running
        m.run_in_background_thread()  # already running: nothing happens
        ready = httpx.get(f"http://127.0.0.1:{port}/readyz", timeout=5)
        assert ready.status_code == 200
        time.sleep(0.5)  # the epoch thread runs alongside
    assert not m.is_running
    m.stop_run_thread()  # not running: nothing happens
    with pytest.raises(httpx.ConnectError):
        httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1)
    assert EPOCH_POLL_S == 12.0


def test_sigterm_in_a_miner_with_block_stops_cleanly(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    kwargs, _port = _real_ports(tw_miner_kwargs)
    m = TemplateMiner(miner=Miner(**kwargs))
    timer = threading.Timer(1.0, os.kill, (os.getpid(), signal.SIGTERM))

    def main_block() -> None:  # neurons/miner.py's __main__ in v10
        with m:
            timer.start()
            while True:
                time.sleep(0.1)

    with pytest.raises(KeyboardInterrupt):
        main_block()
    assert not m.is_running
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL


def test_miner_run_blocks_until_sigterm(tw_miner_kwargs: dict[str, Any]) -> None:
    kwargs, port = _real_ports(tw_miner_kwargs)
    m = TemplateMiner(miner=Miner(**kwargs))
    seen: list[int] = []

    def probe() -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                seen.append(httpx.get(f"http://127.0.0.1:{port}/healthz").status_code)
                break
            except httpx.ConnectError:
                time.sleep(0.1)
        os.kill(os.getpid(), signal.SIGTERM)

    # uvicorn re-raises SIGTERM after its graceful shutdown; as in a
    # process manager, the default action would end this process.
    previous = signal.signal(signal.SIGTERM, interrupt)
    threading.Thread(target=probe, daemon=True).start()
    try:
        with pytest.raises(SystemExit) as info:
            m.run()
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert info.value.code == 130
    assert seen == [200]
    assert m._epochs is None


def test_unregistered_miner_refuses_in_the_background(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    from tensorwire.errors import StartupError

    fake_chain.deregister(TEST_NETUID, BOB.ss58)
    kwargs, _port = _real_ports(tw_miner_kwargs)
    m = TemplateMiner(miner=Miner(**kwargs))
    with pytest.raises(StartupError, match="not registered"):
        m.run_in_background_thread()
    assert not m.is_running


# ---------------------------------------------------------------- validator adapter


def validator_kwargs(
    fake_chain: FakeChain, clock: FakeClock, tmp_path: Path, **extra: Any
) -> dict[str, Any]:
    gateway = fake_chain.with_signer(ALICE.ss58)
    return {
        "settings": ValidatorSettings(
            netuid=TEST_NETUID,
            wallet_name="validator",
            wallet_path=tmp_path / "wallets",
            state_dir=tmp_path / "state",
            metrics_bind=f"127.0.0.1:{_free_port()}",
            round_interval_s=1,
            network="local",
            **extra,
        ),
        "hotkey": ALICE.keypair,
        "gateway": gateway,
        "metagraph_source": FakeMetagraphSource(
            gateway, TEST_NETUID, clock=clock.monotonic
        ),
        "transport": AppRouter(),
        "check_sdk": False,
    }


class EagerValidator(TemplateValidatorAdapter):
    """v10 code that reads the chain in ``__init__``, as the template allowed."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.seen = list(self.metagraph.hotkeys)
        self.me = self.wallet.hotkey.ss58_address
        self.endpoint = self.subtensor.chain_endpoint
        self.at_block = self.subtensor.get_current_block()
        self.synced = 0

    async def forward(self) -> None:
        self.update_scores([1.0], [self.uid])

    def resync_metagraph(self) -> None:
        self.synced += 1
        super().resync_metagraph()


def test_validator_reads_the_chain_in_init_and_runs_on_that_loop(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    v = EagerValidator(**validator_kwargs(fake_chain, tw_clock, tmp_path))
    assert ALICE.ss58 in v.seen
    assert v.me == ALICE.ss58
    assert (v.endpoint, v.at_block) == ("local", v.block)
    assert v.config.wallet.name == "validator"
    assert v.config.subtensor.network == "local"
    with pytest.raises(AttributeError, match="coldkey"):
        _ = v.wallet.coldkey
    with v:
        deadline = time.monotonic() + 20
        while v.step < 2 and time.monotonic() < deadline:
            time.sleep(0.1)
    assert v.step >= 2
    assert v.synced >= 2  # sync() runs after every step's forwards
    assert v._loop is None


def test_validator_run_on_its_own_loop_stops_on_sigterm(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    v = EagerValidator(**validator_kwargs(fake_chain, tw_clock, tmp_path))
    timer = threading.Timer(1.5, os.kill, (os.getpid(), signal.SIGTERM))
    timer.start()
    with pytest.raises(SystemExit) as info:
        v.run()
    assert info.value.code == 130
    assert v.step >= 1
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL


async def test_in_async_code_the_validator_must_be_started_first(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    v = TemplateValidatorAdapter(**validator_kwargs(fake_chain, tw_clock, tmp_path))
    with pytest.raises(RuntimeError, match="await start"):
        _ = v.metagraph
    await v.start()
    await v.start()  # a second start does nothing
    try:
        assert v.subtensor.is_hotkey_registered(hotkey_ss58=ALICE.ss58)
        v.set_weights()  # the kit's schedule decides; nothing happens here
    finally:
        await v.stop()


async def test_a_customised_sync_runs_every_step(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    calls: list[str] = []

    class Custom(TemplateValidatorAdapter):
        async def forward(self) -> None:
            calls.append("forward")

        def sync(self) -> None:
            calls.append("sync")
            super().sync()

        def should_set_weights(self) -> bool:
            return True  # template code may still ask; set_weights() is harmless

    v = Custom(**validator_kwargs(fake_chain, tw_clock, tmp_path))
    await v.start()
    try:
        await v.step_once()
    finally:
        await v.stop()
    assert calls == ["forward", "sync"]
