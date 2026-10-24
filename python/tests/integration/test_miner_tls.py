"""Miner TLS startup: certificate checks, ServeAxonTls publish and read-back (16.3).

ADR-0011 point 3: the chain accepts ``ServeAxonTls`` even when it stores no
certificate, so the miner reads the key back after publishing.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from pathlib import Path
from typing import Any

import anyio
import pytest
import structlog.testing

from taowire.chain.gateway import ChainUnavailable, TxOutcome
from taowire.config import MinerSettings
from taowire.errors import ConfigError, StartupError
from taowire.miner.app import Miner
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.pytest_plugin import MINER_KEY, TEST_NETUID, TWEnv
from taowire.testing.tls import TestCertificate, make_certificate
from taowire.tls import load_published_certificate

pytestmark = pytest.mark.asyncio

BOB = dev_key(MINER_KEY).ss58


def build(kwargs: dict[str, Any], **settings: Any) -> Miner:
    current: MinerSettings = kwargs["settings"]
    return Miner(**{**kwargs, "settings": current.model_copy(update=settings)})


@pytest.fixture
def cert(tmp_path: Path) -> TestCertificate:
    return make_certificate(tmp_path / "tls", kind="p256")


def tls(cert: TestCertificate) -> dict[str, Path]:
    return {"tls_cert_file": cert.cert_file, "tls_key_file": cert.key_file}


def stored(chain: FakeChain) -> bytes | None:
    neuron = chain._state.subnets[TEST_NETUID].neurons
    return next(n.tls_key for n in neuron.values() if n.hotkey == BOB)


async def test_startup_publishes_the_certificate_key(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, cert: TestCertificate
) -> None:
    key = load_published_certificate(cert.cert_file)
    miner = build(tw_miner_kwargs, **tls(cert))
    async with miner.running():
        (pub,) = fake_chain.axon_publications(TEST_NETUID)
        assert pub.tls_cert_hex == "0x" + key.hex()
        assert stored(fake_chain) == key
        assert miner.lifecycle.tls_key == key
        assert miner.lifecycle.runtime.axon_in_sync is True
    options = miner.uvicorn_options()
    assert options["ssl_certfile"] == str(cert.cert_file)


async def test_key_already_on_chain_is_not_republished(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, cert: TestCertificate
) -> None:
    fake_chain.set_axon(TEST_NETUID, BOB, "44.1.2.3:8091", protocol=87)
    fake_chain.set_tls_key(TEST_NETUID, BOB, load_published_certificate(cert.cert_file))
    async with build(tw_miner_kwargs, **tls(cert)).running():
        assert fake_chain.axon_publications() == ()


async def test_a_rotated_certificate_is_republished(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    cert: TestCertificate,
    tmp_path: Path,
) -> None:
    old = make_certificate(tmp_path / "old", kind="ed25519")
    fake_chain.set_axon(TEST_NETUID, BOB, "44.1.2.3:8091", protocol=87)
    fake_chain.set_tls_key(TEST_NETUID, BOB, load_published_certificate(old.cert_file))
    async with build(tw_miner_kwargs, **tls(cert)).running():
        assert len(fake_chain.axon_publications()) == 1
        assert stored(fake_chain) == load_published_certificate(cert.cert_file)


@pytest.mark.parametrize("left", [None, b"\x07"])
async def test_a_key_the_chain_did_not_store_refuses_startup(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    cert: TestCertificate,
    monkeypatch: pytest.MonkeyPatch,
    left: bytes | None,
) -> None:
    real = fake_chain.serve_axon

    async def drops_certificate(*args: Any, **kwargs: Any) -> TxOutcome:
        outcome = await real(*args, **kwargs)
        fake_chain.set_tls_key(TEST_NETUID, BOB, left)
        return outcome

    monkeypatch.setattr(fake_chain, "serve_axon", drops_certificate)
    miner = build(tw_miner_kwargs, **tls(cert))
    message = "did not store" if left is None else "another TLS key"
    with pytest.raises(StartupError, match=message):
        await miner.lifecycle.start()
    assert not fake_chain.connected  # startup cleaned up


async def test_unreadable_read_back_refuses_startup(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    cert: TestCertificate,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tw_miner_kwargs["metagraph"]
    real = fake_chain.serve_axon

    async def fail() -> None:
        raise ChainUnavailable("down")

    async def then_chain_down(*args: Any, **kwargs: Any) -> TxOutcome:
        monkeypatch.setattr(source, "refresh_now", fail)
        return await real(*args, **kwargs)

    monkeypatch.setattr(fake_chain, "serve_axon", then_chain_down)
    miner = build(tw_miner_kwargs, **tls(cert))
    with pytest.raises(StartupError, match="could not be read back"):
        await miner.lifecycle.start()


async def test_read_back_failure_later_is_logged_not_fatal(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    cert: TestCertificate,
) -> None:
    miner = build(tw_miner_kwargs, **tls(cert))
    async with miner.running():
        fake_chain.set_tls_key(TEST_NETUID, BOB, b"\x07")  # someone else's key
        fake_chain.advance(1000)  # past the serving rate limit
        await tw_miner_kwargs["metagraph"].refresh_now()
        real = fake_chain.serve_axon

        async def drops_certificate(*args: Any, **kwargs: Any) -> TxOutcome:
            outcome = await real(*args, **kwargs)
            fake_chain.set_tls_key(TEST_NETUID, BOB, None)
            return outcome

        fake_chain.serve_axon = drops_certificate  # type: ignore[method-assign]
        with structlog.testing.capture_logs() as logs:
            assert await miner.lifecycle.sync_axon() is False
        assert "tls_key_not_published" in [e["event"] for e in logs]
        assert miner.lifecycle.runtime.axon_in_sync is False


async def test_plain_http_miner_with_a_published_key_is_warned(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> None:
    fake_chain.set_tls_key(TEST_NETUID, BOB, b"\x01" + b"\x11" * 32)
    with structlog.testing.capture_logs() as logs:
        async with build(tw_miner_kwargs).running():
            pass
    assert "tls_key_published_but_tls_off" in [e["event"] for e in logs]


async def test_proxy_mode_publishes_the_proxy_certificate(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, cert: TestCertificate
) -> None:
    miner = build(tw_miner_kwargs, tls_published_cert_file=cert.cert_file)
    async with miner.running():
        assert stored(fake_chain) == load_published_certificate(cert.cert_file)
    assert "ssl_certfile" not in miner.uvicorn_options()  # the proxy terminates TLS


async def test_bad_certificate_refuses_startup_before_the_chain(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, tmp_path: Path
) -> None:
    rsa = make_certificate(tmp_path / "rsa", kind="rsa")
    with pytest.raises(StartupError, match="Ed25519 or ECDSA P-256"):
        await build(tw_miner_kwargs, **tls(rsa)).lifecycle.start()
    assert fake_chain.calls["connect"] == 0


async def test_a_new_key_waits_out_the_rate_limit_before_serving(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, cert: TestCertificate
) -> None:
    """Spec 16.3: a new certificate is published before it is served."""
    fake_chain.set_hyperparameters(TEST_NETUID, serving_rate_limit=20)
    fake_chain.reject_next("serve_axon", "rate_limited")
    miner = build(tw_miner_kwargs, **tls(cert))
    miner.lifecycle.parts.axon_retry_poll_s = 0.01
    start = asyncio.get_running_loop().create_task(miner.lifecycle.start())
    with anyio.fail_after(2):
        while not start.done():
            assert not miner.lifecycle.ready
            fake_chain.advance(5)
            await asyncio.sleep(0.01)
    await start
    try:
        assert miner.lifecycle.ready
        assert stored(fake_chain) == load_published_certificate(cert.cert_file)
    finally:
        await miner.lifecycle.stop()


async def test_a_second_rate_limit_refuses_startup(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, cert: TestCertificate
) -> None:
    fake_chain.set_hyperparameters(TEST_NETUID, serving_rate_limit=0)
    fake_chain.reject_next("serve_axon", "rate_limited", times=2)
    miner = build(tw_miner_kwargs, **tls(cert))
    miner.lifecycle.parts.axon_retry_poll_s = 0.01
    with pytest.raises(StartupError, match="after the serving rate limit"):
        await miner.lifecycle.start()


async def test_chain_down_while_waiting_refuses_startup(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, cert: TestCertificate
) -> None:
    fake_chain.reject_next("serve_axon", "rate_limited")
    fake_chain.fail_next("serving_rate_limit")
    with pytest.raises(StartupError, match="chain unavailable"):
        await build(tw_miner_kwargs, **tls(cert)).lifecycle.start()


async def test_drift_check_publishes_a_renewed_proxy_certificate(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    cert: TestCertificate,
    tmp_path: Path,
) -> None:
    miner = build(tw_miner_kwargs, tls_published_cert_file=cert.cert_file)
    async with miner.running():
        renewed = make_certificate(tmp_path / "renewed", kind="ed25519")
        cert.cert_file.write_bytes(renewed.cert_file.read_bytes())  # the proxy renewed
        fake_chain.advance(1000)
        with structlog.testing.capture_logs() as logs:
            assert await miner.lifecycle.sync_axon() is True
        assert stored(fake_chain) == load_published_certificate(renewed.cert_file)
        assert "tls_certificate_changed" in [e["event"] for e in logs]
        cert.cert_file.write_text("broken")  # a half-written renewal
        with structlog.testing.capture_logs() as logs:
            assert await miner.lifecycle.sync_axon() is True  # keeps the last key
        assert "tls_certificate_unreadable" in [e["event"] for e in logs]


async def test_tls_with_the_v10_bridge_is_warned(
    tw_miner_kwargs: dict[str, Any], cert: TestCertificate
) -> None:
    until = dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)
    miner = build(tw_miner_kwargs, legacy_v10_until=until, **tls(cert))
    with structlog.testing.capture_logs() as logs:
        async with miner.running():
            pass
    assert "legacy_v10_with_tls" in [e["event"] for e in logs]


# ------------------------------------------------------------ settings


async def test_settings_rules(tw_env: TWEnv, cert: TestCertificate) -> None:
    base = {"netuid": "1", "external_ip": "44.1.2.3", "wallet_name": "m"}
    tw_env.set(**base, tls_published_cert_file=str(cert.cert_file))
    with pytest.raises(ConfigError, match="TW_TRUSTED_PROXIES"):
        MinerSettings.from_env()
    tw_env.set(trusted_proxies="10.0.0.0/8")
    assert MinerSettings.from_env().tls_published_cert_file == cert.cert_file
    tw_env.set(tls_cert_file=str(cert.cert_file), tls_key_file=str(cert.key_file))
    with pytest.raises(ConfigError, match="mutually exclusive"):
        MinerSettings.from_env()
    tw_env.unset("tls_published_cert_file", "tls_key_file")
    with pytest.raises(ConfigError, match="both TW_TLS_CERT_FILE"):
        MinerSettings.from_env()
