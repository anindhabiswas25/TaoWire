"""Integration test 10 (spec 13.4): the validator client against three real miners.

Three in-process miners on one FakeChain, reached through ``AppRouter`` at
their on-chain axons: one good, one slow (past the client's deadline), one
whose answer is changed after it was signed. Plus the client rules of 8.8
that need a real miner: target binding, fresh signature per attempt, no
request to a neuron without an axon.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
from collections.abc import AsyncIterator, MutableMapping
from typing import Any

import pytest
from pydantic import BaseModel

from tensorwire.chain.gateway import NeuronView
from tensorwire.config import MinerSettings
from tensorwire.miner.app import Miner
from tensorwire.miner.routes import RouteContext
from tensorwire.observability.metrics import Metrics
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.testing.pytest_plugin import TEST_NETUID
from tensorwire.testing.transport import AppRouter
from tensorwire.validator.client import MinerResult, ValidatorClient

pytestmark = pytest.mark.asyncio

ROUTE = "/v1/upper"
GOOD, SLOW, TAMPERED = "bob", "charlie", "eve"
ADDRESSES = {GOOD: "44.0.0.1", SLOW: "44.0.0.2", TAMPERED: "44.0.0.3"}
PORT = 8091


class Req(BaseModel):
    text: str


class Resp(BaseModel):
    result: str


def tamper(app: Any) -> Any:
    """ASGI wrapper that flips one byte of every response body (after signing)."""

    async def wrapped(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        async def send_tampered(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.body" and message.get("body"):
                body = bytearray(message["body"])
                body[-3] ^= 0x20  # same length, different bytes
                message["body"] = bytes(body)
            await send(message)

        await app(scope, receive, send_tampered)

    return wrapped


def build_miner(name: str, chain: FakeChain, clock: FakeClock, tmp: Any) -> Miner:
    settings = MinerSettings(
        netuid=TEST_NETUID,
        wallet_name=name,
        wallet_path=tmp / "wallets",
        external_ip=ADDRESSES[name],
        bind_port=PORT,
        ntp_servers=(),
    )
    key = dev_key(name)
    gateway = chain.with_signer(key.ss58)
    miner = Miner(
        settings,
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, TEST_NETUID, clock=clock.monotonic),
        hotkey=key.keypair,
        clock_ns=clock.now_ns,
        monotonic=clock.monotonic,
        check_sdk=False,
    )
    delay = 5.0 if name == SLOW else 0.0

    @miner.route(ROUTE, request=Req, response=Resp)
    async def upper(req: Req, ctx: RouteContext) -> Resp:
        if delay:
            await asyncio.sleep(delay)
        return Resp(result=req.text.upper())

    return miner


@pytest.fixture
async def fleet(
    tw_env: Any, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Any
) -> AsyncIterator[tuple[AppRouter, dict[str, NeuronView]]]:
    fake_chain.register(TEST_NETUID, dev_key(TAMPERED).ss58)
    for name, ip in ADDRESSES.items():
        hotkey = dev_key(name).ss58
        fake_chain.set_axon(TEST_NETUID, hotkey, f"{ip}:{PORT}", protocol=87)
    router = AppRouter()
    async with contextlib.AsyncExitStack() as stack:
        for name, ip in ADDRESSES.items():
            miner = build_miner(name, fake_chain, tw_clock, tmp_path)
            app = await stack.enter_async_context(miner.running())
            router.add(f"{ip}:{PORT}", tamper(app) if name == TAMPERED else app)
        await fake_chain.connect()
        mg = await fake_chain.metagraph(TEST_NETUID)
        neurons = {name: mg.by_hotkey(dev_key(name).ss58) for name in ADDRESSES}
        yield router, {k: v for k, v in neurons.items() if v is not None}


def client(router: AppRouter, clock: FakeClock, **kw: Any) -> ValidatorClient:
    options: dict[str, Any] = {"timeout_s": 0.5, "transport": router}
    options.update(kw)
    return ValidatorClient(dev_key("alice").signer(clock_ns=clock.now_ns), **options)


async def test_10_three_miners(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    router, neurons = fleet
    metrics = Metrics()
    async with client(router, tw_clock, metrics=metrics) as vc:
        results = await vc.query_many(
            list(neurons.values()), ROUTE, b'{"text":"hello"}', response_model=Resp
        )
    by_name: dict[str, MinerResult] = {
        name: results[n.uid] for name, n in neurons.items()
    }

    good = by_name[GOOD]
    assert good.ok
    assert good.status == 200
    assert good.data == Resp(result="HELLO")
    assert good.response_verified
    assert good.error_code is None
    assert good.attempts == 1
    assert good.protocol == "btauth/1"
    assert good.latency_ms is not None

    slow = by_name[SLOW]
    assert not slow.ok
    assert slow.error_code == "tw.timeout"
    assert slow.status is None
    assert slow.attempts == 2  # idempotent: retried once with a fresh signature

    bad = by_name[TAMPERED]
    assert not bad.ok
    assert bad.status == 200
    assert bad.error_code == "tw.bad_response_signature"
    assert not bad.response_verified
    assert bad.data is None

    text = metrics.render().decode()
    assert 'tw_validator_miner_results_total{code="ok",ok="true"} 1.0' in text
    assert 'code="tw.timeout",ok="false"} 1.0' in text


async def test_non_idempotent_timeout_is_not_retried(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    router, neurons = fleet
    async with client(router, tw_clock) as vc:
        r = await vc.query(neurons[SLOW], ROUTE, b'{"text":"x"}', idempotent=False)
    assert r.error_code == "tw.timeout"
    assert r.attempts == 1


async def test_unverified_mode_accepts_unsigned_changes(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    router, neurons = fleet
    async with client(router, tw_clock, verify_responses=False) as vc:
        r = await vc.query(neurons[TAMPERED], ROUTE, b'{"text":"abc"}')
    assert r.ok
    assert not r.response_verified
    assert isinstance(r.data, bytes)


async def test_miner_error_code_is_passed_through_and_verified(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    router, neurons = fleet
    async with client(router, tw_clock) as vc:
        r = await vc.query(neurons[GOOD], ROUTE, b'{"nope":1}', response_model=Resp)
    assert r.status == 422
    assert r.error_code == "tw.invalid_request"
    assert r.response_verified  # post-auth errors are signed
    assert r.attempts == 1  # 4xx is never retried


async def test_wrong_response_shape_is_invalid_response(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    class Other(BaseModel):
        missing: int

    router, neurons = fleet
    async with client(router, tw_clock) as vc:
        r = await vc.query(neurons[GOOD], ROUTE, b'{"text":"a"}', response_model=Other)
    assert r.error_code == "tw.invalid_response"
    assert r.response_verified


async def test_response_cap(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    router, neurons = fleet
    async with client(router, tw_clock, max_response_bytes=5) as vc:
        r = await vc.query(neurons[GOOD], ROUTE, b'{"text":"abcdef"}')
    assert r.error_code == "tw.response_too_large"


async def test_connect_error_is_retried(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    router, neurons = fleet
    router.remove(f"{ADDRESSES[GOOD]}:{PORT}")
    async with client(router, tw_clock) as vc:
        r = await vc.query(neurons[GOOD], ROUTE, b"{}")
    assert r.error_code == "tw.connect_error"
    assert r.attempts == 2


async def test_no_axon_is_never_contacted(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    router, neurons = fleet
    unserved = dataclasses.replace(neurons[GOOD], axon=None)
    async with client(router, tw_clock) as vc:
        r = await vc.query(unserved, ROUTE, b"{}")
    assert r.error_code == "tw.no_axon"
    assert r.attempts == 0


async def test_percent_encoded_target_is_signed_as_sent(
    fleet: tuple[AppRouter, dict[str, NeuronView]], tw_clock: FakeClock
) -> None:
    # The miner verifies the raw target; a 200 proves both sides agree byte for byte.
    router, neurons = fleet
    async with client(router, tw_clock) as vc:
        r = await vc.query(neurons[GOOD], ROUTE + "?q=a%20b&r=%2F", b'{"text":"a"}')
    assert r.status == 200, r.error_code
    assert r.response_verified
