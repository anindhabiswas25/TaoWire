"""``tensorwire doctor`` (spec 8.14), on FakeChain with injected network parts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from bittensor import sp_core
from typer.testing import CliRunner

from tensorwire.cli.doctor import Doctor
from tensorwire.cli.main import app
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.pytest_plugin import TWEnv
from tensorwire.validator.lock import HotkeyLock

NETUID = 3
BOB = dev_key("bob")
ALICE = dev_key("alice")


def write_key(path: Path, name: str = "bob", password: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = sp_core.serialized_keypair_to_keyfile_data(dev_key(name).keypair)
    if password is not None:
        data = sp_core.encrypt_keyfile_data(data, password)
    path.write_bytes(data)


@pytest.fixture
def chain() -> FakeChain:
    c = FakeChain()
    c.add_subnet(NETUID)
    c.register(NETUID, BOB.ss58, axon="44.1.2.3:8091", axon_protocol=87)
    c.register(NETUID, ALICE.ss58, validator_permit=True)
    return c


@pytest.fixture
def env(tw_env: TWEnv, tmp_path: Path) -> TWEnv:
    tw_env.set(
        netuid=NETUID,
        wallet_name="w",
        wallet_path=tmp_path / "wallets",
        state_dir=tmp_path / "state",
        external_ip="44.1.2.3",
        ntp_servers="ntp.test",
    )
    write_key(tmp_path / "wallets" / "w" / "hotkeys" / "default")
    return tw_env


def healthy(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"status": "ok"})


def doctor(chain: FakeChain, role: Any = "miner", **kw: Any) -> Doctor:
    options: dict[str, Any] = {
        "gateway_factory": lambda settings, signer: chain,
        "ntp_query": lambda server, timeout: 0.01,
        "http_transport": httpx.MockTransport(healthy),
    }
    options.update(kw)
    return Doctor(role, **options)


def by_name(d: Doctor) -> dict[str, tuple[str, str]]:
    return {c.name: (c.status, c.detail) for c in d.checks}


async def test_healthy_miner(env: TWEnv, chain: FakeChain) -> None:
    d = doctor(chain)
    await d.run()
    checks = by_name(d)
    assert not d.failed, checks
    for name in ("python", "settings", "hotkey", "coldkey", "chain", "registered"):
        assert checks[name][0] == "ok", name
    assert checks["axon"] == ("ok", "44.1.2.3:8091 protocol 87")
    assert checks["port"][0] == "ok"
    assert "from this host only" in checks["port"][1]
    assert checks["clock"][0] == "ok"
    assert checks["redis"][0] == "skip"
    assert checks["workers"] == ("ok", "single process")
    assert BOB.ss58 in checks["hotkey"][1]


async def test_problems_are_reported(
    env: TWEnv, chain: FakeChain, tmp_path: Path
) -> None:
    write_key(tmp_path / "wallets" / "w" / "coldkey")  # unencrypted coldkey
    chain.set_axon(NETUID, BOB.ss58, "44.9.9.9:1", protocol=4)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    d = doctor(
        chain,
        ntp_query=lambda server, timeout: 5.0,
        http_transport=httpx.MockTransport(refused),
        python_version=(3, 9),
    )
    await d.run()
    checks = by_name(d)
    assert d.failed
    assert checks["python"][0] == "fail"
    assert checks["coldkey"][0] == "fail"
    assert checks["axon"][0] == "warn"
    assert "publishes it at startup" in checks["axon"][1]
    assert checks["port"][0] == "warn"
    assert checks["clock"][0] == "fail"


async def test_unsafe_settings_and_encrypted_coldkey_warn(
    env: TWEnv, chain: FakeChain, tmp_path: Path
) -> None:
    env.set(refuse_if_coldkey_present=False, allow_private_axons=True)
    write_key(tmp_path / "wallets" / "w" / "coldkey", password="pw")
    d = doctor(chain, ntp_query=lambda server, timeout: 0.7)
    await d.run()
    checks = by_name(d)
    assert checks["settings"][0] == "warn"
    assert "TW_REFUSE_IF_COLDKEY_PRESENT" in checks["settings"][1]
    assert checks["coldkey"] == ("warn", "an encrypted coldkey is on this host")
    assert checks["clock"][0] == "warn"


async def test_unknown_clock_and_probe_url(env: TWEnv, chain: FakeChain) -> None:
    def no_ntp(server: str, timeout: float) -> float:
        raise OSError("down")

    seen: list[str] = []

    def probe(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(503)

    d = doctor(
        chain,
        ntp_query=no_ntp,
        probe_url="https://probe.example/check",
        http_transport=httpx.MockTransport(probe),
    )
    await d.run()
    checks = by_name(d)
    assert checks["clock"][0] == "warn"
    assert seen == ["https://probe.example/check"]
    assert checks["port"] == ("warn", "external probe: HTTP 503")


async def test_bad_settings_stop_early(tw_env: TWEnv, chain: FakeChain) -> None:
    tw_env.set(netuid=NETUID)  # no wallet name, no external IP
    d = doctor(chain)
    await d.run()
    assert [c.name for c in d.checks] == ["python", "sdk", "settings"]
    assert d.checks[-1].status == "fail"


async def test_missing_hotkey_and_dead_chain(
    env: TWEnv, chain: FakeChain, tmp_path: Path
) -> None:
    env.set(wallet_name="other")
    chain.fail_next("connect")
    d = doctor(chain)
    await d.run()
    checks = by_name(d)
    assert checks["hotkey"][0] == "fail"
    assert "hotkey file not found" in checks["hotkey"][1]
    assert checks["chain"][0] == "fail"
    assert "registered" not in checks


async def test_unregistered(env: TWEnv, chain: FakeChain) -> None:
    chain.deregister(NETUID, BOB.ss58)
    d = doctor(chain)
    await d.run()
    status, detail = by_name(d)["registered"]
    assert status == "fail"
    assert "btcli tx burned-register --netuid 3 -w w -H default" in detail


async def test_metagraph_failure(env: TWEnv, chain: FakeChain) -> None:
    chain.fail_next("metagraph")
    d = doctor(chain)
    await d.run()
    assert by_name(d)["registered"][0] == "fail"


async def test_redis_and_workers(env: TWEnv, chain: FakeChain) -> None:
    env.set(redis_url="redis://127.0.0.1:1/0", workers=2)

    class Store:
        def __init__(self, url: str) -> None:
            self.url = url

        def ping(self) -> bool:
            return False

        def close(self) -> None:
            pass

    d = doctor(chain, redis_factory=Store)
    await d.run()
    checks = by_name(d)
    assert checks["redis"] == ("fail", "unreachable")
    assert checks["workers"][0] == "warn"
    assert "127.0.0.1:1" not in json.dumps(checks)  # the URL is never printed


async def test_redis_extra_missing(env: TWEnv, chain: FakeChain) -> None:
    env.set(redis_url="redis://127.0.0.1:1/0")

    def missing(url: str) -> Any:
        raise RuntimeError("RedisNonceStore needs the redis extra")

    d = doctor(chain, redis_factory=missing)
    await d.run()
    assert by_name(d)["redis"][0] == "fail"


async def test_validator(env: TWEnv, chain: FakeChain, tmp_path: Path) -> None:
    env.unset("external_ip")
    write_key(tmp_path / "wallets" / "w" / "hotkeys" / "default", "alice")
    holder = HotkeyLock(tmp_path / "state", ALICE.ss58)
    holder.acquire()
    try:
        d = doctor(chain, "validator")
        await d.run()
    finally:
        holder.release()
    checks = by_name(d)
    assert checks["permit"] == ("ok", "validator permit held")
    assert checks["lock"][0] == "warn"
    assert "port" not in checks
    chain.set_permit(NETUID, ALICE.ss58, False)
    d = doctor(chain, "validator")
    await d.run()
    checks = by_name(d)
    assert checks["permit"][0] == "warn"
    assert checks["lock"][0] == "ok"


def test_cli_output(env: TWEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    bad = runner.invoke(app, ["doctor", "--role", "sidecar"])
    assert bad.exit_code == 2

    async def fake_run(self: Doctor) -> list[Any]:
        self.add("python", "ok", "3.12")
        self.add("chain", "fail", "down")
        return self.checks

    monkeypatch.setattr(Doctor, "run", fake_run)
    text = runner.invoke(app, ["doctor"])
    assert text.exit_code == 1
    assert "[FAIL] chain" in text.stdout
    as_json = runner.invoke(app, ["doctor", "--role", "validator", "--json"])
    assert json.loads(as_json.stdout)[0] == {
        "name": "python",
        "status": "ok",
        "detail": "3.12",
    }
