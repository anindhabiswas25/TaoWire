"""miner/lifecycle.py: startup steps 1-9, refusals, axon publishing (8.7.3)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
import structlog.testing
from bittensor import sp_core
from pydantic import SecretStr

from tensorwire.auth.nonce_store import MemoryNonceStore, RedisNonceStore
from tensorwire.auth.sdk_check import SdkReport
from tensorwire.chain.gateway import ChainUnavailable, MetagraphView
from tensorwire.config import MinerSettings
from tensorwire.errors import StartupError
from tensorwire.miner import lifecycle as lifecycle_mod
from tensorwire.miner.app import Miner
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.testing.pytest_plugin import TEST_NETUID

pytestmark = pytest.mark.asyncio

BOB = dev_key("bob")


def build(kwargs: dict[str, Any], **changes: Any) -> Miner:
    settings_changes = changes.pop("settings", {})
    settings: MinerSettings = kwargs["settings"].model_copy(update=settings_changes)
    return Miner(**{**kwargs, "settings": settings, **changes})


def keyfile(path: Path, *, password: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = sp_core.serialized_keypair_to_keyfile_data(BOB.keypair)
    if password is not None:
        data = sp_core.encrypt_keyfile_data(data, password)
    path.write_bytes(data)


def events(logs: list[dict[str, Any]], level: str | None = None) -> list[str]:
    return [e["event"] for e in logs if level is None or e["log_level"] == level]


# ---------------------------------------------------------------- happy path


async def test_startup_publishes_axon_and_becomes_ready(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    miner = build(tw_miner_kwargs)
    with pytest.raises(RuntimeError, match="has not started"):
        _ = miner.lifecycle.runtime
    async with miner.running():
        assert miner.lifecycle.ready
        pubs = fake_chain.axon_publications(TEST_NETUID)
        assert [(p.ip, p.port, p.protocol_tag, p.tls_cert_hex) for p in pubs] == [
            ("44.1.2.3", 8091, 87, None)
        ]
        assert miner.lifecycle.runtime.axon_in_sync is True
        assert isinstance(miner.lifecycle.runtime.store, MemoryNonceStore)
        verdict = await miner.lifecycle.readiness()
        assert (verdict.ready, verdict.degraded) == (True, ())
    assert not miner.lifecycle.ready
    assert not fake_chain.connected
    await miner.lifecycle.stop()  # idempotent


async def test_axon_already_on_chain_is_not_republished(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    fake_chain.set_axon(TEST_NETUID, BOB.ss58, "44.1.2.3:8091", protocol=87)
    async with build(tw_miner_kwargs).running():
        assert fake_chain.axon_publications() == ()


@pytest.mark.parametrize(
    ("axon", "protocol"),
    [("44.1.2.3:9999", 87), ("44.1.2.4:8091", 87), ("44.1.2.3:8091", 4)],
)
async def test_axon_drift_in_host_port_or_protocol_is_republished(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, axon: str, protocol: int
) -> None:
    fake_chain.set_axon(TEST_NETUID, BOB.ss58, axon, protocol=protocol)
    async with build(tw_miner_kwargs).running():
        assert len(fake_chain.axon_publications()) == 1


async def test_no_publish_when_not_the_publisher(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    miner = build(tw_miner_kwargs, settings={"axon_publisher": False})
    with structlog.testing.capture_logs() as logs:
        async with miner.running():
            assert fake_chain.axon_publications() == ()
            verdict = await miner.lifecycle.readiness()
            assert verdict.ready
            assert verdict.degraded == ("axon_not_published",)
    assert "axon_differs_from_config" in events(logs, "warning")


async def test_serve_axon_rate_limited_is_retried_after_the_window(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    fake_chain.reject_next("serve_axon", "rate_limited")
    miner = build(tw_miner_kwargs)
    miner.lifecycle.parts.axon_retry_poll_s = 0.01
    with structlog.testing.capture_logs() as logs:
        async with miner.running():
            assert miner.lifecycle.runtime.axon_in_sync is False
            assert fake_chain.axon_publications() == ()
            start = fake_chain.current_block
            with anyio.fail_after(2):
                while not fake_chain.axon_publications():
                    fake_chain.advance(5)
                    await asyncio.sleep(0.01)
            waited = fake_chain.axon_publications()[0].block - start
            assert waited >= lifecycle_mod.SERVING_RATE_LIMIT_BLOCKS
            assert miner.lifecycle.runtime.axon_in_sync is True
    assert "serve_axon_rate_limited" in events(logs, "warning")


async def test_axon_retry_survives_chain_outage(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    fake_chain.reject_next("serve_axon", "rate_limited")
    fake_chain.fail_next("block", times=1)
    with structlog.testing.capture_logs() as logs:
        async with build(tw_miner_kwargs).running():
            await asyncio.sleep(0.05)
    assert "axon_retry_deferred" in events(logs, "warning")


@pytest.mark.parametrize("failure", ["rejected", "unavailable"])
async def test_serve_axon_failures_are_logged_not_fatal(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, failure: str
) -> None:
    if failure == "rejected":
        fake_chain.reject_next("serve_axon", "invalid_argument")
    else:
        fake_chain.fail_next("serve_axon")
    miner = build(tw_miner_kwargs)
    with structlog.testing.capture_logs() as logs:
        async with miner.running():
            assert miner.lifecycle.ready
            assert (await miner.lifecycle.readiness()).degraded == (
                "axon_not_published",
            )
    expected = "serve_axon_rejected" if failure == "rejected" else "serve_axon_failed"
    assert expected in events(logs, "error")


async def test_axon_drift_check_republishes(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lifecycle_mod, "AXON_DRIFT_INTERVAL_S", 0.01)
    fake_chain.set_hyperparameters(TEST_NETUID, serving_rate_limit=0)
    miner = build(tw_miner_kwargs)
    async with miner.running():
        fake_chain.set_axon(TEST_NETUID, BOB.ss58, "44.9.9.9:1")
        await miner.lifecycle.runtime.metagraph.refresh_now()
        with anyio.fail_after(2):
            while len(fake_chain.axon_publications()) < 2:
                await asyncio.sleep(0.01)


# ---------------------------------------------------------------- refusals


async def test_unregistered_hotkey_exits_with_code_3(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    fake_chain.deregister(TEST_NETUID, BOB.ss58)
    with pytest.raises(StartupError, match="register first: btcli") as info:
        await build(tw_miner_kwargs).lifecycle.start()
    assert info.value.exit_code == 3
    assert not fake_chain.connected


async def test_unencrypted_coldkey_refuses_start(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    settings: MinerSettings = tw_miner_kwargs["settings"]
    keyfile(settings.wallet_path / settings.wallet_name / "coldkey")
    with pytest.raises(StartupError, match="unencrypted coldkey"):
        await build(tw_miner_kwargs).lifecycle.start()
    miner = build(tw_miner_kwargs, settings={"refuse_if_coldkey_present": False})
    with structlog.testing.capture_logs() as logs:
        async with miner.running():
            pass
    assert "unencrypted_coldkey_present" in events(logs, "warning")
    assert "TW_REFUSE_IF_COLDKEY_PRESENT" in str(miner.metrics.render().decode())


async def test_encrypted_coldkey_only_warns(tw_miner_kwargs: dict[str, Any]) -> None:
    settings: MinerSettings = tw_miner_kwargs["settings"]
    keyfile(settings.wallet_path / settings.wallet_name / "coldkey", password="pw")
    with structlog.testing.capture_logs() as logs:
        async with build(tw_miner_kwargs).running():
            pass
    assert "coldkey_present" in events(logs, "warning")


async def test_hotkey_is_loaded_from_the_wallet_directory(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    settings: MinerSettings = tw_miner_kwargs["settings"]
    keyfile(settings.wallet_path / settings.wallet_name / "hotkeys" / "default")
    miner = build(tw_miner_kwargs, hotkey=None)
    async with miner.running():
        assert miner.lifecycle.runtime.hotkey_ss58 == BOB.ss58


async def test_missing_hotkey_file_refuses_start(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    with pytest.raises(StartupError, match="hotkey file not found"):
        await build(tw_miner_kwargs, hotkey=None).lifecycle.start()


async def test_chain_unavailable_at_startup(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    fake_chain.fail_next("metagraph", error=ChainUnavailable("all endpoints down"))
    with pytest.raises(StartupError, match="chain unavailable at startup"):
        await build(tw_miner_kwargs).lifecycle.start()
    assert not fake_chain.connected


async def test_startup_timeout(tw_miner_kwargs: dict[str, Any]) -> None:
    class Hanging(FakeMetagraphSource):
        async def start(self) -> None:
            await asyncio.sleep(10)

    source = Hanging(tw_miner_kwargs["gateway"], TEST_NETUID)
    miner = build(
        tw_miner_kwargs, metagraph=source, settings={"startup_timeout_s": 0.05}
    )
    with pytest.raises(StartupError, match="TW_STARTUP_TIMEOUT_S"):
        await miner.lifecycle.start()
    assert source.stopped


async def test_real_chain_not_in_this_build(
    tw_miner_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Passes with or without Engineer B's chain classes merged.
    monkeypatch.delattr(lifecycle_mod.gateway_module, "BittensorGateway", raising=False)
    monkeypatch.delattr(lifecycle_mod.cache_module, "MetagraphCache", raising=False)
    with pytest.raises(StartupError, match="real chain gateway is not in this build"):
        await build(tw_miner_kwargs, gateway=None, metagraph=None).lifecycle.start()


async def test_real_chain_factories_are_used_when_present(
    tw_miner_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    chain: FakeChain = tw_miner_kwargs["gateway"]
    built: dict[str, Any] = {}

    class Gateway:
        @staticmethod
        def from_settings(settings: MinerSettings, hotkey: Any) -> FakeChain:
            built["gateway"] = (settings.netuid, hotkey.ss58_address)
            return chain

    class Cache:
        @staticmethod
        def from_settings(
            gateway: Any, settings: MinerSettings, *, on_refresh_failure: Any
        ) -> FakeMetagraphSource:
            built["cache"] = gateway
            on_refresh_failure()
            return FakeMetagraphSource(gateway, settings.netuid)

    monkeypatch.setattr(
        lifecycle_mod.gateway_module, "BittensorGateway", Gateway, raising=False
    )
    monkeypatch.setattr(
        lifecycle_mod.cache_module, "MetagraphCache", Cache, raising=False
    )
    miner = build(tw_miner_kwargs, gateway=None, metagraph=None)
    async with miner.running():
        assert built == {"gateway": (TEST_NETUID, BOB.ss58), "cache": chain}
    refresh_failures = miner.metrics.registry.get_sample_value(
        "tw_metagraph_refresh_failures_total"
    )
    assert refresh_failures == 1


async def test_metagraph_without_gateway_is_refused(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    with pytest.raises(StartupError, match="without its gateway"):
        await build(tw_miner_kwargs, gateway=None).lifecycle.start()


@pytest.mark.parametrize("multi", [{"workers": 2}, {"instance_count": 3}])
async def test_memory_nonce_store_with_several_workers_is_refused(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, multi: dict[str, int]
) -> None:
    # Config refuses this combination too; the lifecycle re-checks it for
    # stores passed in code.
    miner = build(tw_miner_kwargs, nonce_store=MemoryNonceStore(60))
    miner.lifecycle.settings = miner.settings.model_copy(update=multi)
    with pytest.raises(StartupError, match="lets replays through"):
        await miner.lifecycle.start()
    assert not fake_chain.connected


async def test_unsafe_memory_store_multiworker_is_allowed_with_warnings(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    miner = build(
        tw_miner_kwargs,
        settings={"workers": 2, "unsafe_allow_memory_nonce_multiworker": True},
    )
    with structlog.testing.capture_logs() as logs:
        async with miner.running():
            pass
    warnings = events(logs, "warning")
    assert "memory_nonce_store_multiworker" in warnings
    assert "per_process_rate_limits" in warnings
    assert "unsafe_setting_active" in warnings
    value = miner.metrics.registry.get_sample_value(
        "tw_unsafe_settings_active",
        {"name": "TW_UNSAFE_ALLOW_MEMORY_NONCE_MULTIWORKER"},
    )
    assert value == 1


async def test_redis_url_builds_the_shared_store(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    miner = build(
        tw_miner_kwargs,
        settings={"redis_url": SecretStr("redis://127.0.0.1:1/0"), "workers": 2},
    )
    async with miner.running():
        rt = miner.lifecycle.runtime
        assert isinstance(rt.store, RedisNonceStore)
        assert rt.store_backend == "redis"
        verdict = await miner.lifecycle.readiness()
        assert verdict.reasons == ("nonce_store_unreachable",)


async def test_redis_url_without_the_extra_refuses_start(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "redis", None)
    miner = build(tw_miner_kwargs, settings={"redis_url": SecretStr("redis://x:1")})
    with pytest.raises(StartupError, match=r"tensorwire\[redis\]"):
        await miner.lifecycle.start()
    assert not fake_chain.connected


# ---------------------------------------------------------------- checks


async def test_sdk_check_runs_and_warns_when_untested(
    tw_miner_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle_mod, "check_sdk", lambda: SdkReport("11.4.0", False))
    with structlog.testing.capture_logs() as logs:
        async with build(tw_miner_kwargs, check_sdk=True).running():
            pass
    assert "sdk_version_untested" in events(logs, "warning")


async def test_unsupported_sdk_refuses_start(
    tw_miner_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse() -> SdkReport:
        raise StartupError("bittensor 12.0.0 is not supported")

    monkeypatch.setattr(lifecycle_mod, "check_sdk", refuse)
    with pytest.raises(StartupError, match=r"12\.0\.0"):
        await build(tw_miner_kwargs, check_sdk=True).lifecycle.start()


async def test_clock_skew_makes_readyz_fail(tw_miner_kwargs: dict[str, Any]) -> None:
    miner = build(
        tw_miner_kwargs,
        settings={"ntp_servers": ("ntp.test",)},
        ntp_query=lambda server, timeout: 7.5,
    )
    async with miner.running():
        verdict = await miner.lifecycle.readiness()
        assert verdict.reasons == ("clock_skew",)
        assert miner.metrics.registry.get_sample_value("tw_clock_offset_seconds") == 7.5


async def test_degraded_warning_is_rate_limited(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    miner = build(tw_miner_kwargs)
    async with miner.running():
        source = miner.lifecycle.runtime.metagraph
        tw_clock.advance(source.thresholds.soft_age_s + 1)
        with structlog.testing.capture_logs() as logs:
            for _ in range(3):
                await miner.lifecycle.readiness()
            tw_clock.advance(lifecycle_mod.DEGRADED_WARN_INTERVAL_S)
            await miner.lifecycle.readiness()
        assert events(logs, "warning") == ["metagraph_degraded", "metagraph_degraded"]
        reg = miner.metrics.registry
        assert reg.get_sample_value("tw_metagraph_degraded") == 1
        assert reg.get_sample_value("tw_metagraph_age_seconds") == pytest.approx(
            source.thresholds.soft_age_s + 1 + lifecycle_mod.DEGRADED_WARN_INTERVAL_S
        )


async def test_gauge_loop_updates_metrics(
    tw_miner_kwargs: dict[str, Any],
    tw_clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lifecycle_mod, "_GAUGE_INTERVAL_S", 0.01)
    miner = build(tw_miner_kwargs)
    async with miner.running():
        tw_clock.advance(10_000)
        with anyio.fail_after(2):
            while miner.metrics.registry.get_sample_value("tw_metagraph_degraded") != 2:
                await asyncio.sleep(0.01)


async def test_stop_before_start_is_harmless(tw_miner_kwargs: dict[str, Any]) -> None:
    miner = build(tw_miner_kwargs)
    await miner.lifecycle.stop()
    assert (await miner.lifecycle.readiness()).reasons == ("starting",)


async def test_snapshot_listener_sees_every_refresh(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    seen: list[MetagraphView] = []
    miner = build(tw_miner_kwargs)
    async with miner.running():
        miner.lifecycle.runtime.metagraph.add_refresh_listener(seen.append)
        await miner.lifecycle.runtime.metagraph.refresh_now()
    assert len(seen) == 1
