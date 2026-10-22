"""ValidatorRunner: startup failures, run/serve, readiness, resilience (spec 8.9)."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog
from bittensor import sp_core

from tensorwire.chain.gateway import ChainUnavailable
from tensorwire.config import ValidatorSettings
from tensorwire.errors import ConfigError, StartupError
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.testing.pytest_plugin import TEST_NETUID, TWEnv
from tensorwire.validator.client import MinerResult
from tensorwire.validator.loop import SubnetValidator, Task, ValidatorRunner


class Echo(SubnetValidator):
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def make_task(self, round_id: int) -> Task:
        if self.fail:
            raise RuntimeError("task bug")
        return Task(route="/v1/x", body=b"{}")

    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        return {}


def settings(tmp: Path, **kw: Any) -> ValidatorSettings:
    options: dict[str, Any] = {
        "netuid": TEST_NETUID,
        "wallet_name": "validator",
        "wallet_path": tmp / "wallets",
        "state_dir": tmp / "state",
        "round_interval_s": 1,
    }
    options.update(kw)
    return ValidatorSettings(**options)


def runner(
    chain: FakeChain, clock: FakeClock, tmp: Path, *, fail: bool = False, **kw: Any
) -> ValidatorRunner:
    gateway = chain.with_signer(dev_key("alice").ss58)
    options: dict[str, Any] = {
        "gateway": gateway,
        "metagraph": FakeMetagraphSource(gateway, TEST_NETUID, clock=clock.monotonic),
        "hotkey": dev_key("alice").keypair,
        "check_sdk": False,
    }
    options.update(kw)
    return ValidatorRunner(Echo(fail), settings(tmp), **options)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


async def test_chain_unavailable_at_startup(
    tw_env: TWEnv, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    fake_chain.fail_next("connect", error=ChainUnavailable("down"))
    r = runner(fake_chain, tw_clock, tmp_path)
    with pytest.raises(StartupError, match="chain unavailable"):
        await r.start()
    await r.stop()


async def test_startup_timeout(
    tw_env: TWEnv, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    class Slow(FakeMetagraphSource):
        async def start(self) -> None:
            await asyncio.sleep(10)

    gateway = fake_chain.with_signer(dev_key("alice").ss58)
    r = ValidatorRunner(
        Echo(),
        settings(tmp_path, startup_timeout_s=0.05),
        gateway=gateway,
        metagraph=Slow(gateway, TEST_NETUID),
        hotkey=dev_key("alice").keypair,
        check_sdk=False,
    )
    with pytest.raises(StartupError, match="no metagraph within"):
        await r.start()


async def test_builds_real_chain_parts_and_loads_the_hotkey_file(
    tw_env: TWEnv,
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tensorwire.validator import loop

    key = tmp_path / "wallets" / "validator" / "hotkeys" / "default"
    key.parent.mkdir(parents=True)
    key.write_bytes(
        sp_core.serialized_keypair_to_keyfile_data(dev_key("alice").keypair)
    )
    (tmp_path / "wallets" / "validator" / "coldkey").write_bytes(
        sp_core.serialized_keypair_to_keyfile_data(dev_key("alice").keypair)
    )
    gateway = fake_chain.with_signer(dev_key("alice").ss58)
    built: list[str] = []

    class Gateway:
        @staticmethod
        def from_settings(s: Any, hotkey: Any) -> FakeChain:  # noqa: ARG004
            built.append(hotkey.ss58_address)
            return gateway

    class Cache:
        @staticmethod
        def from_settings(gw: Any, s: Any, *, on_refresh_failure: Any) -> Any:  # noqa: ARG004
            built.append("cache")
            return FakeMetagraphSource(gw, s.netuid, clock=tw_clock.monotonic)

    monkeypatch.setattr(loop, "BittensorGateway", Gateway)
    monkeypatch.setattr(loop, "MetagraphCache", Cache)
    r = ValidatorRunner(
        Echo(), settings(tmp_path, refuse_if_coldkey_present=False), check_sdk=True
    )
    with structlog.testing.capture_logs() as logs:
        async with r.running():
            assert r.hotkey_ss58 == dev_key("alice").ss58
    assert built == [dev_key("alice").ss58, "cache"]
    events = {e["event"] for e in logs}
    assert "unencrypted_coldkey_present" in events
    assert "unsafe_setting_active" in events


def test_from_env(tw_env: TWEnv, tmp_path: Path) -> None:
    tw_env.set(netuid=5, wallet_name="v", state_dir=tmp_path)
    r = ValidatorRunner.from_env(Echo())
    assert r.settings.netuid == 5


async def test_round_without_snapshot_is_skipped(
    tw_env: TWEnv, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path)
    async with r.running():
        r._metagraph.snapshot = lambda: None  # type: ignore[union-attr, method-assign]
        with structlog.testing.capture_logs() as logs:
            assert await r.run_round() is None
    assert logs[0]["event"] == "round_skipped"


async def test_run_forever_survives_a_bad_round(
    tw_env: TWEnv, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path, fail=True)
    async with r.running():
        with structlog.testing.capture_logs() as logs:
            task = asyncio.create_task(r.run_forever())
            await asyncio.sleep(0.05)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
    assert any(e["event"] == "round_failed" for e in logs)


async def test_readiness_reasons(
    tw_env: TWEnv, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    gateway = fake_chain.with_signer(dev_key("alice").ss58)
    source = FakeMetagraphSource(
        gateway,
        TEST_NETUID,
        clock=tw_clock.monotonic,
        soft_age_s=10,
        max_age_s=20,
    )
    r = runner(fake_chain, tw_clock, tmp_path, gateway=gateway, metagraph=source)
    async with r.running():
        await r.run_round()
        assert r.readiness() == (True, [])
        tw_clock.advance(30)
        r._last_round_at = -1e9  # long ago
        assert r.weights is not None
        r.weights.stopped = "not_authorized"
        ready, reasons = r.readiness()
    assert not ready
    assert reasons == ["metagraph_stale", "rounds_stalled", "weights_stopped"]


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (StartupError("not registered", exit_code=3), 3),
        (ConfigError("bad"), 2),
        (KeyboardInterrupt(), 130),
    ],
)
def test_run_exit_codes(
    tw_env: TWEnv,
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
    code: int,
) -> None:
    r = runner(fake_chain, tw_clock, tmp_path)

    async def boom() -> None:
        raise error

    monkeypatch.setattr(r, "_serve", boom)
    with pytest.raises(SystemExit) as info:
        r.run()
    assert info.value.code == code


async def test_serve_runs_rounds_and_health_until_sigterm(
    tw_env: TWEnv, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    port = _free_port()
    gateway = fake_chain.with_signer(dev_key("alice").ss58)
    r = ValidatorRunner(
        Echo(),
        settings(tmp_path, metrics_bind=f"127.0.0.1:{port}"),
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, TEST_NETUID, clock=tw_clock.monotonic),
        hotkey=dev_key("alice").keypair,
        check_sdk=False,
    )
    serve = asyncio.create_task(r._serve())
    async with httpx.AsyncClient() as http:
        for _ in range(100):
            try:
                ready = await http.get(f"http://127.0.0.1:{port}/readyz")
            except httpx.TransportError:
                await asyncio.sleep(0.05)
                continue
            if ready.status_code == 200:
                break
            await asyncio.sleep(0.05)
        assert ready.status_code == 200
        metrics = (await http.get(f"http://127.0.0.1:{port}/metrics")).text
    assert "tw_validator_round_duration_seconds" in metrics
    os.kill(os.getpid(), signal.SIGTERM)
    await asyncio.wait_for(serve, timeout=10)
    assert r.client is None  # stopped and closed
