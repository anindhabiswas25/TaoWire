"""One time budget per query, v10 fallback included (spec 8.8, G3-4).

A slow fake miner answers btauth/1 in the v10 shape (as a v10 Axon does),
so the real ``ProtocolSelector`` switches and the real ``LegacyClient``
sends one v10 attempt. Every attempt for one miner must finish within
``max_attempts x timeout``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import time
from collections.abc import Callable
from typing import ClassVar

import httpx
import pytest

from tensorwire.chain.axon import parse_axon
from tensorwire.chain.gateway import NeuronView
from tensorwire.compat import Synapse
from tensorwire.crypto import HotkeySigner
from tensorwire.extensions.legacy_v10 import wire
from tensorwire.extensions.legacy_v10.client import LegacyClient, ProtocolSelector
from tensorwire.testing.keys import dev_key
from tensorwire.validator.client import ValidatorClient

MINER = dev_key("bob")
NEURON = NeuronView(
    uid=3,
    hotkey=MINER.ss58,
    coldkey=MINER.ss58,
    validator_permit=False,
    active=True,
    total_stake_tao=0.0,
    alpha_stake=0.0,
    tao_stake=0.0,
    axon=parse_axon("44.0.0.1:8091"),
    last_update=0,
    incentive=0.0,
    dividends=0.0,
    axon_protocol=4,  # a v10 miner does not advertise TW_PROTOCOL_TAG
)


class Echo(Synapse):
    text: str
    result: str | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("text",)


class SlowV10Miner:
    """A v10 Axon: btauth/1 gets a v10-shaped error, v10 gets a v10 answer."""

    def __init__(
        self,
        btauth: list[tuple[float, int]],
        v10_delay_s: float,
        on_btauth: list[float] | None = None,
        clock: list[float] | None = None,
    ) -> None:
        self.btauth = list(btauth)  # (delay, status) per btauth/1 request
        self.v10_delay_s = v10_delay_s
        self.on_btauth = on_btauth  # fake-clock advance per btauth/1 request
        self.clock = clock
        self.btauth_seen = 0
        self.v10_seen: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        if "bt_header_dendrite_nonce" in request.headers:
            self.v10_seen.append(request)
            await asyncio.sleep(self.v10_delay_s)
            parsed = wire.parse_request_headers(request.headers.multi_items())
            synapse = wire.decode_request_body(Echo, request.content)
            assert isinstance(synapse, Echo)
            synapse.result = synapse.text.upper()
            body, headers = wire.encode_response(
                parsed,
                status=200,
                status_message="Success",
                process_time_s=self.v10_delay_s,
                axon_ip="44.0.0.1",
                axon_port=8091,
                axon_hotkey=MINER.ss58,
                name="Echo",
                synapse=synapse,
            )
            return httpx.Response(200, content=body, headers=headers)
        delay, status = self.btauth[self.btauth_seen]
        if self.on_btauth is not None and self.clock is not None:
            self.clock[0] += self.on_btauth[self.btauth_seen]
        self.btauth_seen += 1
        await asyncio.sleep(delay)
        return httpx.Response(
            status,
            json={"message": "Internal Server Error #x"},
            headers={"bt_header_axon_status_code": str(status)},
        )


def client(
    miner: SlowV10Miner,
    *,
    timeout_s: float,
    max_attempts: int = 2,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[ValidatorClient, ProtocolSelector]:
    until = dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)
    selector = ProtocolSelector(87, until=until)
    vc = ValidatorClient(
        dev_key("alice").signer(),
        timeout_s=timeout_s,
        max_attempts=max_attempts,
        legacy=LegacyClient(HotkeySigner(dev_key("alice").keypair)),
        selector=selector,
        transport=httpx.MockTransport(miner),
        monotonic=monotonic,
    )
    return vc, selector


async def test_slow_btauth_retries_leave_the_v10_attempt_only_the_time_left() -> None:
    # Budget 2 x 0.5 s. A busy v10 Axon answers 503 (retried), then 500
    # (the v10 marker), each after 0.35 s: 0.3 s are left for the v10 attempt,
    # and this v10 miner needs 2 s. Before G3-4 the v10 attempt got a fresh
    # 0.5 s, so the query took 1.2 s.
    miner = SlowV10Miner([(0.35, 503), (0.35, 500)], v10_delay_s=2.0)
    vc, selector = client(miner, timeout_s=0.5)
    started = time.monotonic()
    r = await vc.query(NEURON, "/Echo", b"{}", legacy_synapse=Echo(text="a"))
    elapsed = time.monotonic() - started
    assert miner.btauth_seen == 2
    assert len(miner.v10_seen) == 1
    assert (r.ok, r.error_code, r.protocol, r.attempts) == (
        False,
        "tw.timeout",
        "v10",
        3,
    )
    assert elapsed < 1.0 + 0.1, elapsed
    # The v10 request asks the miner for at most the time left.
    assert float(miner.v10_seen[0].headers["timeout"]) <= 0.31
    assert selector.known(NEURON.hotkey) == "v10"
    await vc.aclose()


async def test_the_v10_attempt_answers_within_the_time_left() -> None:
    miner = SlowV10Miner([(0.05, 500)], v10_delay_s=0.1)
    vc, _ = client(miner, timeout_s=0.5)
    started = time.monotonic()
    r = await vc.query(NEURON, "/Echo", b"{}", legacy_synapse=Echo(text="a"))
    assert time.monotonic() - started < 1.0
    assert (r.ok, r.protocol, r.attempts) == (True, "v10", 2)
    assert isinstance(r.data, Echo)
    assert r.data.result == "A"
    # Per-attempt deadline, not the whole budget: min(0.5, 0.95).
    assert float(miner.v10_seen[0].headers["timeout"]) == pytest.approx(0.5)
    await vc.aclose()


async def test_no_time_left_means_no_v10_attempt() -> None:
    # A fake clock the miner moves forward: each btauth/1 attempt "takes" the
    # whole per-attempt timeout, so nothing is left for v10.
    clock = [100.0]
    miner = SlowV10Miner(
        [(0.0, 503), (0.0, 500)], v10_delay_s=0.0, on_btauth=[1.0, 1.0], clock=clock
    )
    vc, selector = client(miner, timeout_s=1.0, monotonic=lambda: clock[0])
    r = await vc.query(NEURON, "/Echo", b"{}", legacy_synapse=Echo(text="a"))
    assert miner.btauth_seen == 2
    assert miner.v10_seen == []
    assert (r.ok, r.error_code, r.protocol, r.attempts) == (
        False,
        "tw.timeout",
        "v10",
        2,
    )
    assert selector.known(NEURON.hotkey) == "v10"  # next round goes straight to v10
    await vc.aclose()


async def test_no_retry_once_the_budget_is_spent() -> None:
    clock = [0.0]
    miner = SlowV10Miner(
        [(0.0, 503), (0.0, 503)], v10_delay_s=0.0, on_btauth=[2.0, 0.0], clock=clock
    )
    vc, _ = client(miner, timeout_s=1.0, monotonic=lambda: clock[0])
    r = await vc.query(NEURON, "/x", b"{}")
    assert miner.btauth_seen == 1
    assert (r.error_code, r.attempts) == ("tw.http_503", 1)
    await vc.aclose()


async def test_a_remembered_v10_miner_gets_one_attempt_deadline() -> None:
    miner = SlowV10Miner([(0.05, 500)], v10_delay_s=5.0)
    vc, _ = client(miner, timeout_s=0.3, max_attempts=3)
    await vc.query(NEURON, "/Echo", b"{}", legacy_synapse=Echo(text="a"))
    started = time.monotonic()
    r = await vc.query(NEURON, "/Echo", b"{}", legacy_synapse=Echo(text="b"))
    assert time.monotonic() - started < 0.3 + 0.1
    assert miner.btauth_seen == 1  # went straight to v10
    assert (r.error_code, r.protocol, r.attempts) == ("tw.timeout", "v10", 1)
    await vc.aclose()
