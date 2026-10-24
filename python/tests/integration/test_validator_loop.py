"""The validator loop end to end, in process (spec 8.9).

ValidatorRunner (alice, permit) queries two real miners (bob, charlie) on a
FakeChain through ``AppRouter``, scores them, keeps the EMA in SQLite and
submits weights when the chain's schedule allows.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from taowire.config import MinerSettings, ValidatorSettings
from taowire.errors import StartupError
from taowire.miner.app import Miner
from taowire.miner.routes import RouteContext
from taowire.testing.clock import FakeClock
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.metagraph import FakeMetagraphSource
from taowire.testing.pytest_plugin import TEST_NETUID
from taowire.testing.transport import AppRouter
from taowire.validator.client import MinerResult
from taowire.validator.loop import SubnetValidator, Task, ValidatorRunner

ROUTE = "/v1/upper"
MINERS = {"bob": "44.0.0.1", "charlie": "44.0.0.2"}


class Req(BaseModel):
    text: str


class Resp(BaseModel):
    result: str


class UpperValidator(SubnetValidator):
    def __init__(self) -> None:
        self.rounds: list[int] = []

    async def make_task(self, round_id: int) -> Task:
        self.rounds.append(round_id)
        text = f"round {round_id}"
        return Task(
            route=ROUTE,
            body=Req(text=text).model_dump_json().encode(),
            response_model=Resp,
            expected=text.upper(),
        )

    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        return {
            uid: 1.0 if r.ok and r.data.result == task.expected else 0.0
            for uid, r in results.items()
        }


def miner_for(
    name: str, chain: FakeChain, clock: FakeClock, tmp: Path, wrong: bool
) -> Miner:
    gateway = chain.with_signer(dev_key(name).ss58)
    miner = Miner(
        MinerSettings(
            netuid=TEST_NETUID,
            wallet_name=name,
            wallet_path=tmp / "wallets",
            external_ip=MINERS[name],
            ntp_servers=(),
        ),
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, TEST_NETUID, clock=clock.monotonic),
        hotkey=dev_key(name).keypair,
        clock_ns=clock.now_ns,
        monotonic=clock.monotonic,
        check_sdk=False,
    )

    @miner.route(ROUTE, request=Req, response=Resp)
    async def upper(req: Req, ctx: RouteContext) -> Resp:
        return Resp(result=req.text.lower() if wrong else req.text.upper())

    return miner


@pytest.fixture
async def router(
    tw_env: Any, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> AsyncIterator[AppRouter]:
    fake_chain.set_hyperparameters(TEST_NETUID, tempo=20, weights_rate_limit=5)
    r = AppRouter()
    async with contextlib.AsyncExitStack() as stack:
        for name, ip in MINERS.items():
            fake_chain.set_axon(
                TEST_NETUID, dev_key(name).ss58, f"{ip}:8091", protocol=87
            )
            miner = miner_for(
                name, fake_chain, tw_clock, tmp_path, wrong=name == "charlie"
            )
            r.add(f"{ip}:8091", await stack.enter_async_context(miner.running()))
        yield r


def runner(
    chain: FakeChain, clock: FakeClock, tmp: Path, router: AppRouter, **kw: Any
) -> ValidatorRunner:
    settings = ValidatorSettings(
        netuid=TEST_NETUID,
        wallet_name="validator",
        wallet_path=tmp / "vwallets",
        state_dir=tmp / "vstate",
        score_alpha=0.5,
        min_weight_interval_blocks=5,
    )
    gateway = chain.with_signer(dev_key("alice").ss58)
    options: dict[str, Any] = {
        "gateway": gateway,
        "metagraph": FakeMetagraphSource(gateway, TEST_NETUID, clock=clock.monotonic),
        "hotkey": dev_key("alice").keypair,
        "transport": router,
        "clock_ns": clock.now_ns,
        "check_sdk": False,
    }
    options.update(kw)
    return ValidatorRunner(UpperValidator(), settings, **options)


async def test_rounds_score_and_set_weights(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path, router)
    async with r.running():
        first = await r.run_round()
        assert first is not None
        assert first.round_id == 1
        assert first.n_queried == 2  # alice (permit) is not queried
        assert first.n_ok == 2
        assert first.n_btauth == 2
        assert first.n_v10 == 0
        assert first.weights is not None
        assert first.weights.reason == "not_due"  # registered at this block
        fake_chain.advance(5)
        second = await r.run_round()
        assert second is not None
        assert second.weights is not None
        assert second.weights.submitted
        assert r.store is not None
        scores = r.store.scores()
    bob_uid = 0
    assert scores[bob_uid] == 0.75  # EMA, alpha 0.5, two correct answers
    assert sum(scores.values()) == 0.75  # charlie answers wrongly: 0
    (sub,) = fake_chain.weight_submissions()
    assert sub.hotkey == dev_key("alice").ss58
    assert sub.weights == {bob_uid: 0.75}


async def test_scores_survive_a_restart(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    async with runner(fake_chain, tw_clock, tmp_path, router).running() as r:
        await r.run_round()
    tw_clock.advance(1)  # a restarted process signs with later nonces
    async with runner(fake_chain, tw_clock, tmp_path, router).running() as r:
        report = await r.run_round()
        assert report is not None
        assert report.round_id == 2
        assert r.store is not None
        assert r.store.scores()[0] == 0.75


async def test_hotkey_change_resets_and_forgets(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path, router)
    async with r.running():
        await r.run_round()
        fake_chain.deregister(TEST_NETUID, dev_key("bob").ss58)
        fake_chain.register(TEST_NETUID, dev_key("eve").ss58, uid=0)
        await r.metagraph.refresh_now()
        await r.run_round()
        assert r.store is not None
        assert r.store.hotkeys().get(0) is None  # eve has no axon: not queried


async def test_reprobe_once_per_tempo(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path, router)
    calls: list[int] = []
    async with r.running():
        assert r.client is not None
        r.client.reprobe = lambda: calls.append(1)  # type: ignore[method-assign]
        await r.run_round()
        fake_chain.advance(19)
        await r.metagraph.refresh_now()
        await r.run_round()
        assert calls == []
        fake_chain.advance(1)
        await r.metagraph.refresh_now()
        await r.run_round()
        assert calls == [1]


async def test_health_app(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path, router)
    app = r.health_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://h"
    ) as http:
        assert (await http.get("/readyz")).status_code == 503
        async with r.running():
            await r.run_round()
            assert (await http.get("/healthz")).json() == {"status": "ok"}
            assert (await http.get("/readyz")).json() == {"status": "ready"}
            text = (await http.get("/metrics")).text
            assert "tw_validator_round_duration_seconds_count 1.0" in text
            assert 'tw_validator_miners_by_protocol{protocol="btauth/1"} 2.0' in text


async def test_unregistered_validator_exits_3(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path, router, hotkey=dev_key("dave").keypair)
    with pytest.raises(StartupError) as info:
        await r.start()
    assert info.value.exit_code == 3
    # the lock was released on the way out
    again = runner(
        fake_chain, tw_clock, tmp_path, router, hotkey=dev_key("dave").keypair
    )
    with pytest.raises(StartupError):
        await again.start()


async def test_second_process_with_the_same_hotkey_is_refused(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    async with runner(fake_chain, tw_clock, tmp_path, router).running():
        with pytest.raises(StartupError, match="one validator process"):
            await runner(fake_chain, tw_clock, tmp_path, router).start()


async def test_unencrypted_coldkey_is_refused(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    wallet = tmp_path / "vwallets" / "validator"
    wallet.mkdir(parents=True)
    (wallet / "coldkey").write_text('{"secretPhrase": "x"}')
    with pytest.raises(StartupError, match="unencrypted coldkey"):
        await runner(fake_chain, tw_clock, tmp_path, router).start()


async def test_round_before_start_is_an_error(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path, router)
    with pytest.raises(RuntimeError, match="not started"):
        await r.run_round()
    bare = ValidatorRunner(UpperValidator(), r.settings)
    with pytest.raises(RuntimeError, match="not started"):
        _ = bare.gateway
    with pytest.raises(RuntimeError, match="not started"):
        _ = bare.metagraph


def _auto(r: ValidatorRunner) -> None:
    until = dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=10)
    r.settings = r.settings.model_copy(
        update={"legacy_v10_client": "auto", "legacy_v10_client_until": until}
    )


async def test_legacy_auto_builds_the_real_bridge_by_default(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    from taowire.extensions.legacy_v10.client import LegacyClient, ProtocolSelector

    r = runner(fake_chain, tw_clock, tmp_path, router)  # no legacy=
    _auto(r)
    async with r.running():
        assert r.client is not None
        assert r.client.legacy_enabled
        assert isinstance(r.client._legacy, LegacyClient)
        assert isinstance(r.client._selector, ProtocolSelector)
        report = await r.run_round()
    assert report is not None
    assert report.n_btauth == 2  # TaoWire miners advertise tag 87: btauth/1


async def test_legacy_auto_refuses_an_ed25519_hotkey(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    # Spec 8.11.3 / D12: v10 Axons verify sr25519 only.
    r = runner(
        fake_chain,
        tw_clock,
        tmp_path,
        router,
        hotkey=dev_key("alice", "ed25519").keypair,
    )
    _auto(r)
    with pytest.raises(StartupError) as info:
        await r.start()
    message = str(info.value)
    assert "TW_LEGACY_V10_CLIENT=auto" in message
    assert "TW_LEGACY_V10_CLIENT_UNTIL" in message
    assert "ed25519" in message
    assert r.client is None


async def test_ed25519_hotkey_starts_with_the_legacy_client_off(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    key = dev_key("alice", "ed25519")
    fake_chain.register(TEST_NETUID, key.ss58, validator_permit=True)
    gateway = fake_chain.with_signer(key.ss58)
    r = runner(
        fake_chain,
        tw_clock,
        tmp_path,
        router,
        hotkey=key.keypair,
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, TEST_NETUID, clock=tw_clock.monotonic),
    )
    async with r.running():
        assert r.client is not None
        assert not r.client.legacy_enabled


async def test_tls_pinning_policy_starts(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    """D31: allowed now that pinning is tested (integration/test_tls_modes.py)."""
    r = runner(fake_chain, tw_clock, tmp_path, router)
    r.settings = r.settings.model_copy(
        update={"scheme_policy": "https-if-tls-published"}
    )
    async with r.running():
        assert r.client is not None
        assert r.client.scheme_policy == "https-if-tls-published"


async def test_legacy_auto_without_the_bridge(
    router: AppRouter,
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A build without extensions/legacy_v10 (the import fails).
    monkeypatch.setitem(sys.modules, "taowire.extensions.legacy_v10.client", None)
    r = runner(fake_chain, tw_clock, tmp_path, router)
    _auto(r)
    with pytest.raises(StartupError, match="not in this build"):
        await r.start()


async def test_legacy_auto_uses_an_injected_bridge(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    built: list[Any] = []

    class Sel:
        def choose(self, n: Any) -> str:
            return "btauth/1"

        def after_btauth(self, n: Any, **kw: Any) -> bool:
            return False

        def reprobe(self) -> None: ...

        def forget(self, hk: str) -> None: ...

    def factory(settings: Any, signer: Any) -> tuple[Any, Any]:
        built.append(signer.ss58_address)
        return object(), Sel()

    r = runner(fake_chain, tw_clock, tmp_path, router, legacy=factory)
    _auto(r)
    async with r.running():
        report = await r.run_round()
    assert built == [dev_key("alice").ss58]
    assert report is not None
    assert report.n_ok == 2


def _days_left(r: ValidatorRunner, direction: str) -> float | None:
    return r.metrics.registry.get_sample_value(
        "tw_legacy_v10_days_remaining", {"direction": direction}
    )


async def test_outbound_days_remaining_is_current_at_every_scrape(
    router: AppRouter, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    # Spec 8.11.2 / G3-5: computed at scrape time, not once at startup.
    r = runner(
        fake_chain,
        tw_clock,
        tmp_path,
        router,
        legacy=lambda settings, signer: (object(), _StaticSelector()),
    )
    today = dt.datetime.fromtimestamp(tw_clock.time(), dt.timezone.utc).date()
    r.settings = r.settings.model_copy(
        update={
            "legacy_v10_client": "auto",
            "legacy_v10_client_until": today + dt.timedelta(days=3),
        }
    )
    assert _days_left(r, "outbound") is None
    async with r.running():
        assert _days_left(r, "outbound") == 3.0
        tw_clock.advance(86_400)  # the date changes in a running process
        assert _days_left(r, "outbound") == 2.0
        assert b'tw_legacy_v10_days_remaining{direction="outbound"} 2.0' in (
            r.metrics.render()
        )
        tw_clock.advance(3 * 86_400)
        assert _days_left(r, "outbound") == 0.0  # never negative


class _StaticSelector:
    def choose(self, n: Any) -> str:
        return "btauth/1"

    def after_btauth(self, n: Any, **kw: Any) -> bool:
        return False

    def reprobe(self) -> None: ...

    def forget(self, hk: str) -> None: ...
