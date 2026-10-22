"""Unit tests for the legacy v10 bridge: error paths and decisions (spec 8.11).

The captured-vector and real-v10 tests are in ``tests/migration``.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from collections.abc import Callable
from typing import Any, ClassVar

import httpx
import pytest
from pydantic import BaseModel

from legacy_v10_models import BOB, Dummy, LegacyFieldHash, NoHash, PlainDummy, TextOps
from tensorwire import crypto
from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import NeuronView
from tensorwire.errors import (
    LegacyAuthFailed,
    LegacyDisabled,
    RateLimited,
    ReplayStoreUnavailable,
)
from tensorwire.extensions.legacy_v10 import wire
from tensorwire.extensions.legacy_v10.client import LegacyClient, ProtocolSelector
from tensorwire.extensions.legacy_v10.server import REPLAY_NAMESPACE, LegacyServer

TODAY = dt.date(2026, 10, 22)
NOW = 1_792_672_891_000_000_000
ALICE_KEY = crypto.keypair_from_uri("//Alice")
ALICE = ALICE_KEY.ss58_address
UUID = "e85a70d0-ce15-11f1-a10f-847b57c7b217"


def alice() -> crypto.HotkeySigner:
    return crypto.HotkeySigner(ALICE_KEY)


def bob() -> crypto.HotkeySigner:
    return crypto.HotkeySigner(crypto.keypair_from_uri("//Bob"))


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> int:
        return self.now


def server(
    clock: Clock | None = None,
    *,
    store: Any = None,
    today: Callable[[], dt.date] = lambda: TODAY,
    until: dt.date = TODAY + dt.timedelta(days=30),
) -> LegacyServer:
    return LegacyServer(
        signer=bob(),
        store=MemoryNonceStore(60.0) if store is None else store,
        until=until,
        external_ip="203.0.113.7",
        external_port=8091,
        now_ns=clock or Clock(),
        today=today,
    )


def request(
    synapse: BaseModel,
    *,
    nonce: int = NOW,
    uuid: str = UUID,
    receiver: str = BOB,
    timeout: float = 12.0,
) -> wire.EncodedRequest:
    return wire.encode_request(
        synapse,
        signer=alice(),
        axon_hotkey=receiver,
        axon_ip="203.0.113.7",
        axon_port=8091,
        nonce=nonce,
        uuid=uuid,
        timeout=timeout,
    )


def verify(srv: LegacyServer, req: wire.EncodedRequest, cls: Any = Dummy) -> Any:
    return srv.verify_sync(req.headers, req.body, synapse_cls=cls, body_hash=None)


def replace(
    headers: list[tuple[str, str]], name: str, value: str | None
) -> list[tuple[str, str]]:
    out = [(k, v) for k, v in headers if k.lower() != name]
    return out if value is None else [*out, (name, value)]


# ------------------------------------------------------------------ wire


def test_hash_rules() -> None:
    assert wire.hash_fields(Dummy) == ("dummy_input",)
    assert wire.hash_fields(NoHash) == ()
    assert wire.hash_fields(LegacyFieldHash) == ("a_field", "b_field")
    assert wire.body_hash(NoHash(payload="x")) == wire.EMPTY_BODY_HASH
    expected = wire.hash_values([0])
    assert wire.body_hash(Dummy(dummy_input=0)) == expected


def test_check_synapse_class() -> None:
    wire.check_synapse_class(Dummy)

    class Bad(BaseModel):
        x: int
        required_hash_fields: ClassVar[tuple[str, ...]] = ("y",)

    with pytest.raises(ValueError, match="unknown"):
        wire.check_synapse_class(Bad)
    with pytest.raises(TypeError):
        wire.check_synapse_class(dict)  # type: ignore[arg-type]
    assert not wire.is_synapse_name("no-dash")
    assert not wire.is_synapse_name("x" * 200)


def test_detection_helpers() -> None:
    assert wire.is_legacy_request({"BT_HEADER_DENDRITE_SIGNATURE": "0x"})
    assert not wire.is_legacy_request(
        {"bt_header_dendrite_signature": "0x", "X-Bittensor-Signature": "0x"}
    )
    assert wire.is_v10_response(500, {"Bt_Header_Axon_Status_Code": "500"})
    assert not wire.is_v10_response(500, {})
    assert not wire.is_v10_response(401, {"bt_header_axon_status_code": "401"})


def test_encode_request_refuses_bad_inputs() -> None:
    ed = crypto.HotkeySigner(
        crypto.keypair_from_uri("//Alice", crypto_type=crypto.CRYPTO_ED25519)
    )
    kw: dict[str, Any] = {
        "axon_hotkey": BOB,
        "axon_ip": "1.2.3.4",
        "axon_port": 1,
        "nonce": 1,
        "uuid": UUID,
    }
    with pytest.raises(ValueError, match="sr25519"):
        wire.encode_request(Dummy(dummy_input=1), signer=ed, timeout=1, **kw)
    with pytest.raises(ValueError, match="timeout"):
        wire.encode_request(Dummy(dummy_input=1), signer=alice(), timeout=0, **kw)
    with pytest.raises(ValueError, match="uuid"):
        wire.encode_request(
            Dummy(dummy_input=1), signer=alice(), timeout=1, **{**kw, "uuid": "a.b"}
        )

    class Raw(BaseModel):
        blob: bytes  # bytes() is not JSON: v10 cannot announce it either

    with pytest.raises(ValueError, match="cannot announce"):
        wire.encode_request(Raw(blob=b"x"), signer=alice(), timeout=1, **kw)


def test_input_obj_headers_announce_defaults_not_values() -> None:
    req = request(TextOps(text="secret", op="upper", count=5))
    headers = dict(req.headers)
    assert json.loads(base64.b64decode(headers["bt_header_input_obj_text"])) == ""
    assert "bt_header_input_obj_count" not in headers  # has a default


@pytest.mark.parametrize(
    ("name", "value", "match"),
    [
        ("bt_header_dendrite_hotkey", None, "missing"),
        ("bt_header_dendrite_hotkey", "not-an-address", "prefix-42"),
        ("bt_header_dendrite_nonce", "+1", "decimal"),
        ("bt_header_dendrite_uuid", "a.b", "unexpected"),
        ("bt_header_dendrite_signature", "0x1234", "64-byte"),
        ("computed_body_hash", "A" * 64, "lowercase"),
        ("bt_header_dendrite_version", "v10", "decimal"),
        ("timeout", "abc", "not a number"),
        ("timeout", "nan", "out of range"),
        ("timeout", "-1", "out of range"),
        ("bt_header_input_obj_x-y", "MA==", "malformed"),
        ("bt_header_input_obj_x", "!!", "malformed"),
    ],
)
def test_header_shape_rules(name: str, value: str | None, match: str) -> None:
    headers = replace(request(Dummy(dummy_input=1)).headers, name, value)
    with pytest.raises(wire.WireError, match=match):
        wire.parse_request_headers(headers)


def test_duplicate_and_too_many_headers() -> None:
    headers = request(Dummy(dummy_input=1)).headers
    with pytest.raises(wire.WireError, match="duplicate"):
        wire.parse_request_headers([*headers, ("Computed_Body_Hash", "0" * 64)])
    many = [(f"bt_header_input_obj_f{i}", "MA==") for i in range(65)]
    with pytest.raises(wire.WireError, match="too many"):
        wire.parse_request_headers([*headers, *many])


@pytest.mark.parametrize(
    ("body", "match"),
    [(b"{", "not JSON"), (b"[1]", "not a JSON object"), (b"{}", "does not parse")],
)
def test_decode_request_body_errors(body: bytes, match: str) -> None:
    with pytest.raises(wire.WireError, match=match):
        wire.decode_request_body(Dummy, body)


def test_decode_response_edge_cases() -> None:
    decoded = wire.decode_response(
        Dummy, 503, {"bt_header_axon_status_message": "busy"}, b"x"
    )
    assert decoded.status_message == "busy"
    with pytest.raises(wire.WireError):
        wire.decode_response(Dummy, 200, {}, b"{}")


def test_encode_response_needs_signing_inputs() -> None:
    with pytest.raises(ValueError, match="signed answer"):
        wire.encode_response(
            None,
            status=200,
            status_message="Success",
            process_time_s=0,
            axon_ip="1.2.3.4",
            axon_port=1,
            axon_hotkey=BOB,
            name=None,
            signer=bob(),
        )


# ------------------------------------------------------------------ server


def test_server_construction_rules() -> None:
    with pytest.raises(ValueError, match="future"):
        server(until=TODAY)
    with pytest.raises(ValueError, match="180"):
        server(until=TODAY + dt.timedelta(days=181))
    server(until=TODAY + dt.timedelta(days=180))
    with pytest.raises(ValueError, match="retention"):
        server(store=MemoryNonceStore(5.0))
    with pytest.raises(ValueError, match="positive"):
        LegacyServer(
            signer=bob(),
            store=MemoryNonceStore(60.0),
            until=TODAY + dt.timedelta(days=1),
            external_ip="1.2.3.4",
            external_port=1,
            max_age=0,
            today=lambda: TODAY,
        )
    with pytest.raises(ValueError, match="external_port"):
        LegacyServer(
            signer=bob(),
            store=MemoryNonceStore(60.0),
            until=TODAY + dt.timedelta(days=1),
            external_ip="1.2.3.4",
            external_port=0,
            today=lambda: TODAY,
        )


def test_end_date_is_checked_on_every_request() -> None:
    day = [TODAY]
    srv = server(today=lambda: day[0], until=TODAY + dt.timedelta(days=2))
    assert srv.enabled()
    assert srv.days_remaining() == 2
    assert srv.until == TODAY + dt.timedelta(days=2)
    verify(srv, request(Dummy(dummy_input=1)))
    day[0] = TODAY + dt.timedelta(days=2)
    assert not srv.enabled()
    assert srv.days_remaining() == 0
    with pytest.raises(LegacyDisabled):
        verify(srv, request(Dummy(dummy_input=1), nonce=NOW + 1))


def test_freshness_rules() -> None:
    clock = Clock()
    srv = server(clock)
    with pytest.raises(LegacyAuthFailed, match="too old"):
        verify(srv, request(Dummy(dummy_input=1), nonce=NOW - 10_000_000_001))
    with pytest.raises(LegacyAuthFailed, match="future"):
        verify(srv, request(Dummy(dummy_input=1), nonce=NOW + 2_000_000_001))
    # v10 first-nonce window: 4 s + timeout (here 1 s) is tighter than 10 s.
    with pytest.raises(LegacyAuthFailed, match="too old"):
        verify(srv, request(Dummy(dummy_input=1), nonce=NOW - 5_000_000_000, timeout=1))
    verify(srv, request(Dummy(dummy_input=1), nonce=NOW - 1_000))
    # Later nonces for the same (sender, uuid) must increase strictly.
    with pytest.raises(LegacyAuthFailed, match="not newer"):
        verify(srv, request(Dummy(dummy_input=2), nonce=NOW - 2_000))
    verify(srv, request(Dummy(dummy_input=2), nonce=NOW - 2_000, uuid="other"))


def test_replay_store_namespace_and_failures() -> None:
    seen: list[tuple[str, int]] = []

    class Store:
        retention = 60.0
        down = False

        def check_and_store(self, hotkey: str, nonce: int) -> bool:
            if self.down:
                raise ReplayStoreUnavailable()
            seen.append((hotkey, nonce))
            return True

    store = Store()
    srv = server(store=store)
    verify(srv, request(Dummy(dummy_input=1)))
    assert seen == [(REPLAY_NAMESPACE + ALICE, NOW)]
    store.down = True
    with pytest.raises(ReplayStoreUnavailable):
        verify(srv, request(Dummy(dummy_input=1), nonce=NOW + 1))


def test_bad_signature_and_wrong_receiver() -> None:
    srv = server()
    with pytest.raises(LegacyAuthFailed, match="signature"):
        verify(srv, request(Dummy(dummy_input=1), receiver=ALICE))
    req = request(Dummy(dummy_input=1))
    forged = replace(req.headers, "bt_header_dendrite_signature", "0x" + "11" * 64)
    with pytest.raises(LegacyAuthFailed, match="signature"):
        srv.verify_sync(forged, req.body, synapse_cls=Dummy, body_hash=None)


def test_body_checks() -> None:
    srv = server()
    req = request(Dummy(dummy_input=1))
    with pytest.raises(LegacyAuthFailed, match="does not parse"):
        srv.verify_sync(req.headers, b"{}", synapse_cls=Dummy, body_hash=None)
    tampered = req.body.replace(b'"dummy_input": 1', b'"dummy_input": 2')
    with pytest.raises(LegacyAuthFailed, match="hash"):
        srv.verify_sync(req.headers, tampered, synapse_cls=Dummy, body_hash=None)
    # The envelope does not pass the model's own validation: still a 401.
    bad_envelope = req.body.replace(b'"timeout": 12.0', b'"dendrite": 5, "x": 1', 0)
    data = json.loads(req.body)
    data["dendrite"] = {"version": "x"}
    with pytest.raises(LegacyAuthFailed):
        srv.verify_sync(
            replace(req.headers, "bt_header_dendrite_version", "notdigits"),
            bad_envelope,
            synapse_cls=Dummy,
            body_hash=None,
        )


def test_native_body_hash_route_and_plain_model() -> None:
    srv = server()
    req = request(Dummy(dummy_input=1))
    ok = srv.verify_sync(
        req.headers,
        req.body,
        synapse_cls=None,
        body_hash=lambda _: req.computed_body_hash,
    )
    assert ok.synapse is None
    assert ok.caller.hotkey_ss58 == ALICE
    req2 = request(Dummy(dummy_input=1), nonce=NOW + 1)
    with pytest.raises(LegacyAuthFailed, match="hash"):
        srv.verify_sync(
            req2.headers, req2.body, synapse_cls=None, body_hash=lambda _: "0"
        )
    with pytest.raises(TypeError):
        srv.verify_sync(req2.headers, req2.body, synapse_cls=None, body_hash=None)
    plain = verify(srv, request(PlainDummy(dummy_input=3), nonce=NOW + 2), PlainDummy)
    assert plain.synapse == PlainDummy(dummy_input=3)


async def test_async_verify_and_lru_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    import tensorwire.extensions.legacy_v10.server as mod

    monkeypatch.setattr(mod, "_MAX_TRACKED_KEYS", 2)
    srv = server()
    for i, uuid in enumerate(("a", "b", "c")):
        await srv.verify(
            request(Dummy(dummy_input=i), uuid=uuid, nonce=NOW + i).headers,
            request(Dummy(dummy_input=i), uuid=uuid, nonce=NOW + i).body,
            synapse_cls=Dummy,
            body_hash=None,
        )
    assert list(srv._last) == [(ALICE, "b"), (ALICE, "c")]


def test_respond_shapes() -> None:
    srv = server()
    req = request(Dummy(dummy_input=1))
    # Rejected before verification: v10 shape, unsigned, kit headers kept.
    body, headers = srv.respond(
        req.headers,
        status=429,
        synapse=None,
        error=RateLimited(retry_after_s=2, layer="hotkey"),
        process_time_s=0.0,
    )
    names = dict(headers)
    assert json.loads(body) == {
        "message": RateLimited(retry_after_s=1, layer="ip").public_message
    }
    assert names["bt_header_axon_status_code"] == "429"
    assert names["Retry-After"] == "2"
    assert names["name"] == "Dummy"
    assert "bt_header_axon_signature" not in names
    # Unparseable headers: still v10 shape, no echo.
    body, headers = srv.respond(
        [("name", "not a name")],
        status=401,
        synapse=None,
        error=LegacyAuthFailed(),
        process_time_s=0.0,
    )
    names = dict(headers)
    assert "name" not in names
    assert "computed_body_hash" not in names
    body, headers = srv.respond(
        {}, status=401, synapse=None, error=LegacyAuthFailed(), process_time_s=0
    )
    assert "name" not in dict(headers)
    # Native route: raw Synapse-shaped body passes through on 200.
    verified = verify(srv, req)
    raw = b'{"dummy_output":2}'
    body, headers = srv.respond(
        req.headers,
        request=verified,
        status=200,
        synapse=None,
        error=None,
        process_time_s=0.0,
        raw_body=raw,
    )
    assert body == raw
    assert dict(headers)["bt_header_axon_signature"].startswith("0x")
    # A request object this server did not produce is not trusted: no signature.
    _, foreign = srv.respond(
        req.headers,
        request=object(),
        status=200,
        synapse=verified.synapse,
        error=None,
        process_time_s=0.0,
    )
    assert "bt_header_axon_signature" not in dict(foreign)
    # Axon nonces strictly increase across answers.
    _, h2 = srv.respond(
        req.headers,
        request=verified,
        status=200,
        synapse=verified.synapse,
        error=None,
        process_time_s=0.0,
    )
    assert int(dict(h2)["bt_header_axon_nonce"]) > int(
        dict(headers)["bt_header_axon_nonce"]
    )


# ------------------------------------------------------------------ client


def view(
    *, protocol: int | None = 0, hotkey: str = BOB, axon: bool = True
) -> NeuronView:
    return NeuronView(
        uid=3,
        hotkey=hotkey,
        coldkey=hotkey,
        validator_permit=False,
        active=True,
        total_stake_tao=0,
        alpha_stake=0,
        tao_stake=0,
        axon=Endpoint("203.0.113.7", 8091, False) if axon else None,
        last_update=0,
        incentive=0,
        dividends=0,
        axon_protocol=protocol,
    )


def test_client_requires_sr25519_and_has_increasing_nonces() -> None:
    ed = crypto.HotkeySigner(
        crypto.keypair_from_uri("//Alice", crypto_type=crypto.CRYPTO_ED25519)
    )
    with pytest.raises(ValueError, match="sr25519"):
        LegacyClient(ed)
    client = LegacyClient(alice(), now_ns=lambda: 5)
    assert client._nonce() == 5
    assert client._nonce() == 6
    assert len(client.uuid) == 36


async def run_query(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    limit: int = 1 << 20,
    **kw: Any,
) -> Any:
    client = LegacyClient(alice())
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        return await client.query(
            http,
            view(**kw),
            Dummy(dummy_input=4),
            timeout_s=1.0,
            max_response_bytes=limit,
        )


async def test_client_outcomes() -> None:
    seen: list[httpx.Request] = []

    def ok(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        data = json.loads(req.content)
        data["dummy_output"] = 8
        return httpx.Response(200, json=data)

    result = await run_query(ok)
    assert result.status == 200
    assert result.error_code is None
    assert result.synapse.dummy_output == 8
    assert str(seen[0].url) == "http://203.0.113.7:8091/Dummy"
    srv = server(Clock())
    srv._now_ns = lambda: int(seen[0].headers["bt_header_dendrite_nonce"])
    srv.verify_sync(
        list(seen[0].headers.items()),
        seen[0].content,
        synapse_cls=Dummy,
        body_hash=None,
    )

    err = await run_query(lambda _: httpx.Response(403, json={"message": "no"}))
    assert (err.status, err.error_code, err.status_message) == (
        403,
        "tw.http_403",
        "no",
    )
    big = await run_query(lambda _: httpx.Response(200, content=b"x" * 100), limit=10)
    assert big.error_code == "tw.response_too_large"
    bad = await run_query(lambda _: httpx.Response(200, content=b"{}"))
    assert bad.error_code == "tw.invalid_response"
    none = await run_query(ok, axon=False)
    assert none.error_code == "tw.no_axon"
    assert none.latency_ms is None

    def timeout(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    def refused(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    assert (await run_query(timeout)).error_code == "tw.timeout"
    assert (await run_query(refused)).error_code == "tw.connect_error"


def test_selector_rules() -> None:
    day = [TODAY]
    sel = ProtocolSelector(87, until=TODAY + dt.timedelta(days=3), today=lambda: day[0])
    marker = [("bt_header_axon_status_code", "500")]
    miner = view()
    assert sel.choose(miner) == "btauth/1"
    assert not sel.after_btauth(miner, status=502, headers=[], verified=False)
    assert sel.known(BOB) is None  # an unmarked failure proves nothing
    assert not sel.after_btauth(miner, status=None, headers=None, verified=False)
    assert sel.after_btauth(miner, status=500, headers=marker, verified=False)
    assert sel.choose(miner) == sel.known(BOB) == "v10"
    sel.reprobe()
    assert sel.choose(miner) == "btauth/1"
    # A verified btauth/1 answer: never downgraded afterwards.
    assert not sel.after_btauth(miner, status=200, headers=[], verified=True)
    assert not sel.after_btauth(miner, status=500, headers=marker, verified=False)
    assert sel.choose(miner) == "btauth/1"
    sel.reprobe()
    assert sel.known(BOB) == "btauth/1"
    sel.forget(BOB)
    assert sel.known(BOB) is None
    # The on-chain tag wins: no fallback for a miner that publishes it.
    tagged = view(protocol=87)
    assert not sel.after_btauth(tagged, status=500, headers=marker, verified=False)
    assert sel.choose(tagged) == "btauth/1"
    assert sel.days_remaining() == 3
    day[0] = TODAY + dt.timedelta(days=3)
    assert not sel.enabled()
    assert sel.days_remaining() == 0
    assert not sel.after_btauth(miner, status=500, headers=marker, verified=False)
    assert sel.choose(miner) == "btauth/1"


def test_selector_bounds() -> None:
    with pytest.raises(ValueError, match="0-255"):
        ProtocolSelector(256, until=TODAY)
    sel = ProtocolSelector(
        87, until=TODAY + dt.timedelta(days=1), today=lambda: TODAY, max_hotkeys=2
    )
    for hotkey in ("a", "b", "c"):
        sel.after_btauth(view(hotkey=hotkey), status=200, headers=[], verified=True)
    assert sel.known("a") is None
    assert sel.known("c") == "btauth/1"
