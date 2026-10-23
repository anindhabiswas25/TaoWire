"""Integration tests 12 and 13: the legacy v10 bridge in the kit (spec 13.4, 8.11).

12. Server side: captured ``legacy_v10.json`` requests reach a real ``Miner``
    on ``compat.Synapse`` routes, the kit computes the body hash, answers in
    v10 shape (signed after verification), and replay, caller policy and the
    end date still apply.
13. Client side: ``ValidatorClient`` with ``LegacyClient`` + ``ProtocolSelector``
    against a fake v10 Axon falls back to v10 once and remembers it; re-probe
    switches an upgraded miner back; a hotkey that answered over btauth/1 is
    never downgraded, unless its own signed ``ServeAxon`` moves its protocol
    tag away from the kit's (D16), which the running validator picks up at
    its next metagraph refresh.

Needs Engineer A's ``compat`` and ``validator`` packages; skipped without them.
"""

# (ruff files the tensorwire modules that exist only on eng-a/core as third-party
# on eng-b/chain; known-first-party is requested in COORDINATION.md.)
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import time
from collections.abc import AsyncIterator
from typing import Any, ClassVar

import httpx
import pydantic
import pytest
import structlog

from legacy_v10_models import BY_ID, body_bytes, nonce_of, request_headers

pytest.importorskip("tensorwire.compat.synapse", reason="needs Engineer A's compat")
pytest.importorskip("tensorwire.validator.client", reason="needs A's validator")

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from tensorwire import crypto
from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.chain.gateway import NeuronView
from tensorwire.compat.synapse import Synapse
from tensorwire.config import MinerSettings, ValidatorSettings
from tensorwire.errors import ConfigError, Forbidden, HandlerError
from tensorwire.extensions.legacy_v10 import wire
from tensorwire.extensions.legacy_v10.client import (
    LegacyClient,
    ProtocolSelector,
)
from tensorwire.extensions.legacy_v10.server import LegacyServer
from tensorwire.miner.app import Miner
from tensorwire.miner.routes import RouteContext
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.testing.pytest_plugin import TEST_NETUID
from tensorwire.testing.transport import AppRouter
from tensorwire.validator.client import MinerResult, ValidatorClient
from tensorwire.validator.loop import SubnetValidator, Task, ValidatorRunner

TODAY = dt.datetime.now(dt.timezone.utc).date()
UNTIL = TODAY + dt.timedelta(days=30)
BOB = dev_key("bob").ss58
ALICE = dev_key("alice").ss58


class Dummy(Synapse):
    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


class StreamDummy(Synapse):
    dummy_input: int
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


class TextOps(Synapse):
    text: str
    op: str
    count: int = 1
    ratio: float = 0.5
    tags: list[str] = pydantic.Field(default_factory=list)
    weights: dict[str, float] = pydantic.Field(default_factory=dict)
    flag: bool = False
    maybe: int | None = None
    result: str | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = (
        "op",
        "text",
        "count",
        "ratio",
        "tags",
        "weights",
        "flag",
        "maybe",
    )


# ------------------------------------------------------------------ test 12


@pytest.fixture
def tw_clock() -> FakeClock:
    """The capture time of vector V1, so the captured requests are fresh."""
    return FakeClock(start_ns=nonce_of(BY_ID["V1"]) + 1_000_000)


@pytest.fixture
def day() -> list[dt.date]:
    return [TODAY]


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any], day: list[dt.date]) -> Miner:
    kwargs = dict(tw_miner_kwargs)
    kwargs["settings"] = kwargs["settings"].model_copy(
        update={"legacy_v10_until": UNTIL}
    )

    def bridge(**kw: Any) -> LegacyServer:
        return LegacyServer(**kw, today=lambda: day[0])

    miner = Miner(**kwargs, legacy_server=bridge)

    @miner.route("/Dummy", request=Dummy, response=Dummy, legacy_synapse=Dummy)
    async def dummy(s: Dummy, ctx: RouteContext) -> Dummy:
        assert s.dendrite is not None
        assert s.dendrite.hotkey == ctx.caller.hotkey_ss58  # verified, not body-claimed
        s.dummy_output = s.dummy_input * 2
        return s

    @miner.route("/TextOps", request=TextOps, response=TextOps, legacy_synapse=TextOps)
    async def text_ops(s: TextOps, ctx: RouteContext) -> TextOps:
        s.result = s.text.upper() * s.count
        return s

    @miner.route(
        "/StreamDummy", request=StreamDummy, legacy_synapse=StreamDummy, stream=True
    )
    async def stream_dummy(s: StreamDummy, ctx: RouteContext) -> AsyncIterator[Any]:
        yield {"n": s.dummy_input}

    return miner


async def post(app: Any, path: str, headers: Any, body: bytes) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://44.1.2.3:8091"
    ) as http:
        return await http.post(path, headers=headers, content=body)


def kit_request(key: str, clock: FakeClock, value: int = 3) -> wire.EncodedRequest:
    return wire.encode_request(
        Dummy(dummy_input=value),
        signer=crypto.HotkeySigner(dev_key(key).keypair),
        axon_hotkey=BOB,
        axon_ip="44.1.2.3",
        axon_port=8091,
        nonce=clock.now_ns(),
        uuid="0f6e3a1c-0000-4000-8000-000000000001",
        timeout=12.0,
    )


def assert_signed_by_bob(response: httpx.Response, sender: str) -> None:
    h = response.headers
    message = wire.response_message(
        int(h["bt_header_axon_nonce"]), sender, BOB, h["bt_header_axon_uuid"]
    )
    assert crypto.verify(
        message.encode(),
        crypto.signature_from_hex(h["bt_header_axon_signature"]),
        BOB,
        crypto.CRYPTO_SR25519,
    )


async def test_12_captured_v10_requests_are_served(
    miner_app: Any, tw_miner: Miner
) -> None:
    v1 = BY_ID["V1"]
    r = await post(miner_app, "/Dummy", request_headers(v1), body_bytes(v1["request"]))
    assert r.status_code == 200, r.text
    assert r.headers["bt_header_axon_status_code"] == "200"
    assert r.headers["bt_header_axon_hotkey"] == BOB
    captured = json.loads(body_bytes(v1["response"]))
    ours = r.json()
    assert ours["dummy_output"] == captured["dummy_output"] == 14
    assert ours["dendrite"]["hotkey"] == ALICE
    assert "x-tw-resp-signature" not in r.headers
    assert_signed_by_bob(r, ALICE)
    # Unicode text and every field type (V2), hashed by the kit.
    v2 = BY_ID["V2"]
    r2 = await post(
        miner_app, "/TextOps", request_headers(v2), body_bytes(v2["request"])
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["result"] == ('HÉLLO ☃ 你好 "QUOTED" \\ BACK') * 3
    text = tw_miner.metrics.render().decode()
    assert 'tw_legacy_v10_requests_total{direction="inbound",result="ok"} 2.0' in text


async def test_12_replay_and_tampering_are_rejected(miner_app: Any) -> None:
    v1 = BY_ID["V1"]
    first = await post(
        miner_app, "/Dummy", request_headers(v1), body_bytes(v1["request"])
    )
    assert first.status_code == 200
    for vector in ("N3", "V1"):  # N3 is V1's exact bytes again
        again = BY_ID[vector]
        r = await post(
            miner_app, "/Dummy", request_headers(again), body_bytes(again["request"])
        )
        assert r.status_code == 401
        assert r.headers["bt_header_axon_status_code"] == "401"
        assert "message" in r.json()
        assert "bt_header_axon_signature" not in r.headers  # never signed before auth
    n4 = BY_ID["N4"]
    r = await post(miner_app, "/Dummy", request_headers(n4), body_bytes(n4["request"]))
    assert r.status_code == 401
    n2 = BY_ID["N2"]  # signed for another axon
    r = await post(miner_app, "/Dummy", request_headers(n2), body_bytes(n2["request"]))
    assert r.status_code == 401


@pytest.mark.parametrize(
    ("key", "code"),
    [
        ("charlie", "tw.forbidden_not_validator"),
        ("dave", "tw.forbidden_not_registered"),
    ],
)
async def test_12_caller_policy_still_applies(
    miner_app: Any, tw_clock: FakeClock, key: str, code: str
) -> None:
    req = kit_request(key, tw_clock)
    r = await post(miner_app, req.path, req.headers, req.body)
    assert r.status_code == 403
    assert r.headers["bt_header_axon_status_code"] == "403"
    # v10 answers carry the public message only; the tw.* code is in the logs.
    assert r.json() == {"message": Forbidden(code=code).public_message}
    assert_signed_by_bob(r, dev_key(key).ss58)  # rejected after authentication


async def test_12_rejected_after_the_end_date(
    miner_app: Any, tw_clock: FakeClock, day: list[dt.date]
) -> None:
    ok = kit_request("alice", tw_clock)
    assert (await post(miner_app, ok.path, ok.headers, ok.body)).status_code == 200
    day[0] = UNTIL
    tw_clock.advance(0.001)
    late = kit_request("alice", tw_clock, value=4)
    r = await post(miner_app, late.path, late.headers, late.body)
    assert r.status_code == 410
    assert r.headers["bt_header_axon_status_code"] == "410"
    assert "bt_header_axon_signature" not in r.headers


class Scores(Synapse):
    dummy_input: int
    score: float | None = None
    extra: dict[str, Any] = pydantic.Field(default_factory=dict)
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


def _scores_miner(kwargs: dict[str, Any], update: dict[str, Any]) -> Miner:
    kwargs = dict(kwargs)
    kwargs["settings"] = kwargs["settings"].model_copy(
        update={"legacy_v10_until": UNTIL}
    )
    miner = Miner(**kwargs, legacy_server=LegacyServer)

    @miner.route("/Scores", request=Scores, response=Scores, legacy_synapse=Scores)
    async def scores(s: Scores, ctx: RouteContext) -> Scores:
        return s.model_copy(update=update)

    return miner


def _scores_request(clock: FakeClock) -> wire.EncodedRequest:
    return wire.encode_request(
        Scores(dummy_input=1),
        signer=crypto.HotkeySigner(dev_key("alice").keypair),
        axon_hotkey=BOB,
        axon_ip="44.1.2.3",
        axon_port=8091,
        nonce=clock.now_ns(),
        uuid="0f6e3a1c-0000-4000-8000-000000000002",
        timeout=12.0,
    )


@pytest.mark.parametrize(
    ("update", "field"),
    [
        ({"extra": {"r": float("inf")}}, "extra.r"),
        ({"score": 1.0, "extra": {"w": [0.5, float("nan")]}}, "extra.w[1]"),
    ],
)
async def test_12_non_finite_answer_is_a_handler_error(
    tw_miner_kwargs: dict[str, Any],
    tw_clock: FakeClock,
    update: dict[str, Any],
    field: str,
) -> None:
    # 8.11.2 (D11): JSON would turn inf / nan under Any into null; the answer is
    # never silently changed: 500 tw.handler_error in v10 shape, the log names
    # the field.
    miner = _scores_miner(tw_miner_kwargs, update)
    req = _scores_request(tw_clock)
    async with miner.running() as app:
        with structlog.testing.capture_logs() as logs:
            r = await post(app, req.path, req.headers, req.body)
    assert r.status_code == 500, r.text
    assert r.headers["bt_header_axon_status_code"] == "500"
    assert r.json() == {"message": HandlerError().public_message}
    assert_signed_by_bob(r, ALICE)  # post-auth error: signed, as other 500s
    events = [e for e in logs if e["event"] == "legacy_non_finite_answer"]
    assert [(e["field"], e["synapse"], e["log_level"]) for e in events] == [
        (field, "Scores", "error")
    ]
    text = miner.metrics.render().decode()
    assert 'direction="inbound",result="tw.handler_error"} 1.0' in text


async def test_12_non_finite_typed_float_is_sent_unchanged(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    # A float field keeps inf in JSON mode: sent as Infinity, as a v10 Dendrite
    # sends requests, and parsed back to inf. Nothing changed, so 200.
    miner = _scores_miner(tw_miner_kwargs, {"score": float("inf")})
    req = _scores_request(tw_clock)
    async with miner.running() as app:
        r = await post(app, req.path, req.headers, req.body)
    assert r.status_code == 200, r.text
    assert b'"score":Infinity' in r.content
    decoded = wire.decode_response(Scores, r.status_code, r.headers.items(), r.content)
    assert isinstance(decoded.synapse, Scores)
    assert decoded.synapse.score == float("inf")


def test_12_end_date_limits_at_startup(tw_miner_kwargs: dict[str, Any]) -> None:
    settings = tw_miner_kwargs["settings"]
    for bad in (TODAY, TODAY - dt.timedelta(days=1), TODAY + dt.timedelta(days=181)):
        with pytest.raises(ConfigError, match="end date"):
            MinerSettings.model_validate(
                {**settings.model_dump(), "legacy_v10_until": bad}
            )


# ------------------------------------------------------------------ test 13

V10_ADDRESS = "44.0.0.9:8091"


class FakeV10Axon:
    """A v10 Axon at one address: v10 requests are served (via the kit's own
    v10 server code); anything else gets the v10 answer to a btauth/1 request
    (HTTP 500 with ``bt_header_axon_status_code``, vector N7)."""

    def __init__(self, clock: FakeClock) -> None:
        self.btauth_hits = 0
        self.v10_hits = 0
        self.legacy = LegacyServer(
            signer=crypto.HotkeySigner(dev_key("bob").keypair),
            store=MemoryNonceStore(60.0),
            until=UNTIL,
            external_ip="44.0.0.9",
            external_port=8091,
            now_ns=clock.now_ns,
        )
        self.app = Starlette(routes=[Route("/Dummy", self.dummy, methods=["POST"])])

    async def dummy(self, request: Request) -> Response:
        started = time.perf_counter()
        if not self.legacy.is_legacy(request.headers):
            self.btauth_hits += 1
            return JSONResponse(
                {"message": "Internal Server Error #00000000"},
                status_code=500,
                headers={"bt_header_axon_status_code": "500"},
            )
        self.v10_hits += 1
        verified = await self.legacy.verify(
            list(request.headers.items()),
            await request.body(),
            synapse_cls=Dummy,
            body_hash=None,
        )
        synapse = verified.synapse
        assert isinstance(synapse, Dummy)
        out = synapse.model_copy(update={"dummy_output": synapse.dummy_input * 2})
        content, headers = self.legacy.respond(
            request.headers,
            request=verified,
            status=200,
            synapse=out,
            error=None,
            process_time_s=time.perf_counter() - started,
        )
        response = Response(content=content, status_code=200)
        for name, value in headers:
            response.headers.append(name, value)
        return response


class Switch:
    """One address whose app can be swapped (a miner upgrading in place)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        await self.app(scope, receive, send)


class _NoRounds(SubnetValidator):
    """The runner only refreshes and queries here; no rounds of its own."""

    async def make_task(self, round_id: int) -> Task:
        return Task(route="/Dummy", body=b"{}")

    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        return {}


def upgraded_miner(chain: FakeChain, clock: FakeClock, tmp: Any) -> Miner:
    settings = MinerSettings(
        netuid=TEST_NETUID,
        wallet_name="bob",
        wallet_path=tmp / "wallets",
        external_ip="44.0.0.9",
        bind_port=8091,
        auto_serve_axon=False,
        ntp_servers=(),
    )
    gateway = chain.with_signer(BOB)
    miner = Miner(
        settings,
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, TEST_NETUID, clock=clock.monotonic),
        hotkey=dev_key("bob").keypair,
        clock_ns=clock.now_ns,
        monotonic=clock.monotonic,
        check_sdk=False,
    )

    @miner.route("/Dummy", request=Dummy, response=Dummy)
    async def dummy(s: Dummy, ctx: RouteContext) -> Dummy:
        s.dummy_output = s.dummy_input * 2
        return s

    return miner


@pytest.fixture
async def v10_world(
    tw_env: Any, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Any
) -> AsyncIterator[tuple[ValidatorClient, FakeV10Axon, Switch, Any, NeuronView]]:
    fake_chain.set_axon(TEST_NETUID, BOB, V10_ADDRESS, protocol=4)
    await fake_chain.connect()
    neuron = (await fake_chain.metagraph(TEST_NETUID)).by_hotkey(BOB)
    assert neuron is not None
    fake = FakeV10Axon(tw_clock)
    switch = Switch(fake.app)
    miner = upgraded_miner(fake_chain, tw_clock, tmp_path)
    async with miner.running() as upgraded_app:
        client = ValidatorClient(
            dev_key("alice").signer(clock_ns=tw_clock.now_ns),
            timeout_s=2.0,
            transport=AppRouter({V10_ADDRESS: switch}),
            legacy=LegacyClient(
                crypto.HotkeySigner(dev_key("alice").keypair), now_ns=tw_clock.now_ns
            ),
            selector=ProtocolSelector(87, until=UNTIL),
        )
        async with client:
            yield client, fake, switch, upgraded_app, neuron


async def ask(client: ValidatorClient, neuron: NeuronView, value: int) -> Any:
    synapse = Dummy(dummy_input=value)
    return await client.query(
        neuron,
        "/Dummy",
        synapse.model_dump_json(include={"dummy_input"}).encode(),
        response_model=Dummy,
        legacy_synapse=synapse,
    )


async def test_13_auto_falls_back_once_and_remembers(
    v10_world: tuple[ValidatorClient, FakeV10Axon, Switch, Any, NeuronView],
) -> None:
    client, fake, _, _, neuron = v10_world
    first = await ask(client, neuron, 5)
    assert first.ok, first
    assert first.protocol == "v10"
    assert first.response_verified is False
    assert first.data.dummy_output == 10
    assert (fake.btauth_hits, fake.v10_hits) == (1, 1)  # one probe, one v10 retry
    second = await ask(client, neuron, 6)
    assert second.ok
    assert second.protocol == "v10"
    assert (fake.btauth_hits, fake.v10_hits) == (1, 2)  # remembered: no probe


async def test_13_reprobe_switches_an_upgraded_miner_back_and_never_downgrades(
    v10_world: tuple[ValidatorClient, FakeV10Axon, Switch, Any, NeuronView],
) -> None:
    client, fake, switch, upgraded_app, neuron = v10_world
    assert (await ask(client, neuron, 1)).protocol == "v10"
    switch.app = upgraded_app  # the miner upgrades in place
    client.reprobe()  # the validator loop does this once per tempo
    upgraded = await ask(client, neuron, 2)
    assert upgraded.ok, upgraded
    assert upgraded.protocol == "btauth/1"
    assert upgraded.response_verified is True
    # Something at that address now answers like a v10 Axon (a downgrade
    # attempt): the hotkey has spoken verified btauth/1, so no v10 is sent.
    switch.app = fake.app
    v10_before = fake.v10_hits
    forced = await ask(client, neuron, 3)
    assert not forced.ok
    assert forced.protocol == "btauth/1"
    assert fake.v10_hits == v10_before
    client.reprobe()
    assert (await ask(client, neuron, 4)).protocol == "btauth/1"
    assert fake.v10_hits == v10_before


async def test_13_on_chain_tag_means_btauth_only(
    v10_world: tuple[ValidatorClient, FakeV10Axon, Switch, Any, NeuronView],
) -> None:
    client, fake, _, _, neuron = v10_world
    tagged = dataclasses.replace(neuron, axon_protocol=87)
    result = await ask(client, tagged, 1)
    assert not result.ok
    assert result.protocol == "btauth/1"
    assert fake.v10_hits == 0


async def test_13_signed_tag_change_reaches_a_rolled_back_miner_over_v10(
    tw_env: Any, fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Any
) -> None:
    """D16 (8.11.3 step 5, 10b.5 stage 2 rollback) end to end, in the running
    validator: after Bob answered over btauth/1, a v10-shaped answer never
    downgrades him; once his own ``ServeAxon`` moves his tag away from the
    kit's, the next metagraph refresh lets the next query reach him over v10.
    Unit detail of the trigger: ``test_validator_protocol_tag.py``."""
    settings = ValidatorSettings(
        netuid=TEST_NETUID,
        wallet_name="alice",
        wallet_path=tmp_path / "w",
        state_dir=tmp_path / "s",
        legacy_v10_client="auto",
        legacy_v10_client_until=UNTIL,
        allow_private_axons=True,
    )
    fake_chain.set_axon(TEST_NETUID, BOB, V10_ADDRESS, protocol=settings.protocol_tag)
    fake = FakeV10Axon(tw_clock)
    miner = upgraded_miner(fake_chain, tw_clock, tmp_path)
    gateway = fake_chain.with_signer(ALICE)
    source = FakeMetagraphSource(gateway, TEST_NETUID, clock=tw_clock.monotonic)
    async with miner.running() as upgraded_app:
        switch = Switch(upgraded_app)
        runner = ValidatorRunner(
            _NoRounds(),
            settings,
            gateway=gateway,
            metagraph=source,
            hotkey=dev_key("alice").keypair,
            transport=AppRouter({V10_ADDRESS: switch}),
            clock_ns=tw_clock.now_ns,
            legacy=lambda s, signer: (
                LegacyClient(signer, now_ns=tw_clock.now_ns),
                ProtocolSelector(s.protocol_tag, until=UNTIL),
            ),
            check_sdk=False,
        )

        async def refresh() -> NeuronView:
            mg = await source.refresh_now()
            await runner.begin_round(mg)
            neuron = mg.by_hotkey(BOB)
            assert neuron is not None
            return neuron

        async with runner.running():
            client = runner.client
            assert client is not None
            first = await ask(client, await refresh(), 1)
            assert (first.ok, first.protocol, first.response_verified) == (
                True, "btauth/1", True,
            )  # fmt: skip
            switch.app = fake.app  # Bob rolls back to v10 at the same address
            held = await ask(client, await refresh(), 2)  # tag unchanged
            assert (held.ok, held.protocol, fake.v10_hits) == (False, "btauth/1", 0)
            fake_chain.set_axon(TEST_NETUID, BOB, V10_ADDRESS, protocol=4)
            with structlog.testing.capture_logs() as logs:
                neuron = await refresh()  # his signed ServeAxon is on chain now
            assert any(e["event"] == "legacy_v10_protocol_tag_changed" for e in logs)
            back = await ask(client, neuron, 3)
            assert (back.ok, back.protocol) == (True, "v10")
            assert back.data.dummy_output == 6
            assert fake.v10_hits == 1


async def test_d33_a_v10_request_to_a_streaming_route_is_invalid_request(
    miner_app: Any, tw_miner: Miner, tw_clock: FakeClock
) -> None:
    """No streaming over the v10 wire (D33, 10b.3): a v10-shaped 422 at once.

    The signature is broken on purpose: the refusal comes before any
    verification work, so the answer is still 422, not 401.
    """
    encoded = wire.encode_request(
        StreamDummy(dummy_input=3),
        signer=crypto.HotkeySigner(dev_key("alice").keypair),
        axon_hotkey=BOB,
        axon_ip="44.1.2.3",
        axon_port=8091,
        nonce=tw_clock.now_ns(),
        uuid="0f6e3a1c-0000-4000-8000-000000000002",
        timeout=12.0,
    )
    headers = [
        (k, "0x" + "00" * 64 if k == "bt_header_dendrite_signature" else v)
        for k, v in encoded.headers
    ]
    verified_before = tw_miner.metrics.registry.get_sample_value(
        "tw_auth_verify_duration_seconds_count"
    )
    r = await post(miner_app, "/StreamDummy", headers, encoded.body)
    assert r.status_code == 422, r.text
    assert r.headers["bt_header_axon_status_code"] == "422"
    assert "text/event-stream" not in r.headers.get("content-type", "")
    assert r.json().get("error", {}).get("code", "tw.invalid_request") == (
        "tw.invalid_request"
    )
    assert (
        tw_miner.metrics.registry.get_sample_value(
            "tw_auth_verify_duration_seconds_count"
        )
        == verified_before
    )
