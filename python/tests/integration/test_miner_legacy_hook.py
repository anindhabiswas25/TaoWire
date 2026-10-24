"""The miner's side of the v10 bridge (spec 8.11.2), with a fake ``LegacyServer``.

The v10 wire format itself is Engineer B's (``extensions/legacy_v10``,
integration test 12). These tests check what the pipeline does around it:
which requests reach the bridge, that caller policy, rate limits and the
handler still apply, how answers are built, and that the verified request
is passed to ``respond`` only after verification passed.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

import httpx
import pytest
import structlog.testing
from pydantic import BaseModel, Field

from taowire.auth.verifier import Caller
from taowire.compat.synapse import Synapse
from taowire.crypto import CRYPTO_SR25519
from taowire.errors import HandlerError, LegacyAuthFailed, StartupError, TWError
from taowire.miner.app import Miner
from taowire.miner.routes import RouteContext
from taowire.testing.client import BASE_URL, SignedClient
from taowire.testing.clock import FakeClock
from taowire.testing.keys import dev_key

UNTIL = dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)


class Syn(Synapse):
    text: str
    result: str | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("text",)


class NativeSyn(Synapse):
    text: str
    result: str | None = None


class Req(BaseModel):
    text: str


class Resp(BaseModel):
    result: str


class Scores(BaseModel):
    """A native answer with a float field and values held under ``Any``."""

    score: float = 0.0
    meta: dict[str, Any] = Field(default_factory=dict)
    timeout: float = 0.0  # a Synapse envelope name: still checked here


@dataclass(frozen=True)
class FakeLegacyRequest:
    caller: Caller
    synapse: BaseModel | None


@dataclass
class FakeLegacyServer:
    kwargs: dict[str, Any]
    responses: list[dict[str, Any]] = field(default_factory=list)

    def is_legacy(self, headers: Mapping[str, str]) -> bool:
        return "bt_header_dendrite_signature" in headers

    async def verify(
        self,
        headers: Sequence[tuple[str, str]],
        body: bytes,
        *,
        synapse_cls: type[BaseModel] | None,
        body_hash: Callable[[bytes], str] | None,
    ) -> FakeLegacyRequest:
        h = dict(headers)
        if h["bt_header_dendrite_signature"] == "bad":
            raise LegacyAuthFailed()
        synapse = None if synapse_cls is None else synapse_cls.model_validate_json(body)
        if body_hash is not None:
            assert body_hash(body) == "h"
        caller = Caller(
            hotkey_ss58=h["bt_header_dendrite_hotkey"],
            nonce_ns=int(h["bt_header_dendrite_nonce"]),
            crypto_type=CRYPTO_SR25519,
        )
        return FakeLegacyRequest(caller, synapse)

    def respond(
        self,
        request_headers: Mapping[str, str],
        *,
        request: FakeLegacyRequest | None,
        status: int,
        synapse: BaseModel | None,
        error: TWError | None,
        process_time_s: float,
        raw_body: bytes | None = None,
    ) -> tuple[bytes, list[tuple[str, str]]]:
        self.responses.append(
            {"request": request, "status": status, "error": error, "raw": raw_body}
        )
        if status == 200 and getattr(synapse, "result", None) == "REFUSE":
            raise HandlerError()  # as B's encode_response does for a non-finite answer
        if synapse is not None:
            body = synapse.model_dump_json().encode()
        elif raw_body is not None:
            body = raw_body
        else:
            body = json.dumps(
                {"message": error.public_message if error else ""}
            ).encode()
        headers = [
            ("bt_header_axon_status_code", str(status)),
            ("content-type", "application/json"),
            ("content-length", "1"),  # dropped by the pipeline
        ]
        return body, headers


@pytest.fixture
def servers() -> list[FakeLegacyServer]:
    return []


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any], servers: list[FakeLegacyServer]) -> Miner:
    kwargs = dict(tw_miner_kwargs)
    kwargs["settings"] = kwargs["settings"].model_copy(
        update={"legacy_v10_until": UNTIL}
    )

    def factory(**kw: Any) -> FakeLegacyServer:
        server = FakeLegacyServer(kw)
        servers.append(server)
        return server

    miner = Miner(**kwargs, legacy_server=factory)

    @miner.route("/Syn", request=Syn, response=Syn, legacy_synapse=Syn)
    async def syn(s: Syn, ctx: RouteContext) -> Syn:
        s.result = s.text.upper()
        return s

    @miner.route("/v1/native", request=Req, response=Resp, legacy_synapse=NativeSyn)
    async def native(req: Req, ctx: RouteContext) -> Resp:
        return Resp(result=req.text[::-1])

    @miner.route("/v1/raw", legacy_body_hash=lambda body: "h")
    async def raw(body: bytes, ctx: RouteContext) -> bytes:
        return b'{"result":"raw"}'

    @miner.route("/v1/raw-model", legacy_body_hash=lambda body: "h")
    async def raw_model(body: bytes, ctx: RouteContext) -> BaseModel:
        return Scores.model_validate_json(body)

    @miner.route("/v1/plain", request=Req, response=Resp)
    async def plain(req: Req, ctx: RouteContext) -> Resp:
        return Resp(result=req.text)

    return miner


def v10_headers(key: str = "alice", signature: str = "0xsig") -> dict[str, str]:
    return {
        "bt_header_dendrite_signature": signature,
        "bt_header_dendrite_hotkey": dev_key(key).ss58,  # type: ignore[arg-type]
        "bt_header_dendrite_nonce": "123",
    }


async def post_v10(app: Any, path: str, body: bytes, **kw: Any) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE_URL
    ) as http:
        return await http.post(path, content=body, headers=v10_headers(**kw))


async def test_v10_request_on_a_synapse_route(
    miner_app: Any, servers: list[FakeLegacyServer], tw_miner: Miner
) -> None:
    r = await post_v10(miner_app, "/Syn", Syn(text="abc").model_dump_json().encode())
    assert r.status_code == 200
    assert r.json()["result"] == "ABC"
    assert r.headers["bt_header_axon_status_code"] == "200"
    assert "x-tw-resp-signature" not in r.headers  # v10 answers are not twresp-signed
    (server,) = servers
    assert server.kwargs["until"] == UNTIL
    assert server.kwargs["external_ip"] == "44.1.2.3"
    assert server.responses[-1]["request"] is not None
    text = tw_miner.metrics.render().decode()
    assert 'tw_legacy_v10_requests_total{direction="inbound",result="ok"} 1.0' in text
    assert 'tw_legacy_v10_days_remaining{direction="inbound"}' in text


async def test_answer_refused_by_respond_counts_once(
    miner_app: Any, tw_miner: Miner
) -> None:
    r = await post_v10(miner_app, "/Syn", Syn(text="refuse").model_dump_json().encode())
    assert r.status_code == 500
    assert r.headers["bt_header_axon_status_code"] == "500"
    text = tw_miner.metrics.render().decode()
    assert 'result="tw.handler_error"} 1.0' in text
    assert 'result="ok"' not in text


async def test_native_route_answers_through_its_synapse_alias(
    miner_app: Any, signed_client: SignedClient
) -> None:
    body = NativeSyn(text="abc").model_dump_json().encode()
    for path in ("/NativeSyn", "/v1/native"):
        r = await post_v10(miner_app, path, body)
        assert r.status_code == 200
        assert r.json()["result"] == "cba"  # response model merged into the Synapse
        assert r.json()["name"] == "NativeSyn"


async def test_native_alias_rejects_btauth(tw_miner_kwargs: dict[str, Any]) -> None:
    miner = Miner(**tw_miner_kwargs)

    @miner.route("/v1/native", request=Req, response=Resp, legacy_synapse=Syn)
    async def native(req: Req, ctx: RouteContext) -> Resp:
        return Resp(result=req.text)

    async with miner.running() as app:
        client = SignedClient(app, receiver_ss58=dev_key("bob").ss58)
        r = await client.post("/Syn", json={"text": "x"})
        await client.aclose()
    assert r.status_code == 404


async def test_body_hash_route_passes_raw_body(
    miner_app: Any, servers: list[FakeLegacyServer]
) -> None:
    r = await post_v10(miner_app, "/v1/raw", b"{}")
    assert r.status_code == 200
    assert r.json() == {"result": "raw"}
    assert servers[0].responses[-1]["raw"] == b'{"result":"raw"}'


@pytest.mark.parametrize(
    ("answer", "bad_field"),
    [
        ('{"score": Infinity}', "score"),
        ('{"meta": {"r": NaN}}', "meta.r"),
        ('{"meta": {"w": [1.0, -Infinity]}}', "meta.w[1]"),
        ('{"timeout": Infinity}', "timeout"),
    ],
)
async def test_native_body_hash_model_with_non_finite_values_is_refused(
    miner_app: Any,
    tw_miner: Miner,
    servers: list[FakeLegacyServer],
    answer: str,
    bad_field: str,
) -> None:
    """G4-4 (D11, 8.11.2): ``model_dump_json`` would write these as ``null``."""
    with structlog.testing.capture_logs() as logs:
        r = await post_v10(miner_app, "/v1/raw-model", answer.encode())
    assert r.status_code == 500
    assert servers[0].responses[-1]["error"].code == "tw.handler_error"
    assert servers[0].responses[-1]["raw"] is None
    [event] = [e for e in logs if e["event"] == "legacy_non_finite_answer"]
    assert (event["route"], event["field"]) == ("/v1/raw-model", bad_field)
    assert event["log_level"] == "error"
    text = tw_miner.metrics.render().decode()
    assert 'result="tw.handler_error"} 1.0' in text
    assert 'result="ok"' not in text


async def test_native_body_hash_model_with_finite_values_is_answered(
    miner_app: Any, servers: list[FakeLegacyServer]
) -> None:
    body = b'{"score": 1.5, "meta": {"r": 2.0, "w": [1, 2]}}'
    r = await post_v10(miner_app, "/v1/raw-model", body)
    assert r.status_code == 200
    assert r.json() == {"score": 1.5, "meta": {"r": 2.0, "w": [1, 2]}, "timeout": 0.0}


async def test_route_without_legacy_support(
    miner_app: Any, servers: list[FakeLegacyServer]
) -> None:
    r = await post_v10(miner_app, "/v1/plain", b"{}")
    assert r.status_code == 401
    last = servers[0].responses[-1]
    assert last["error"].code == "tw.legacy_auth_failed"
    assert last["request"] is None


async def test_failed_v10_verification_is_answered_unsigned(
    miner_app: Any, servers: list[FakeLegacyServer], tw_miner: Miner
) -> None:
    r = await post_v10(miner_app, "/Syn", b"{}", signature="bad")
    assert r.status_code == 401
    assert servers[0].responses[-1]["request"] is None
    text = tw_miner.metrics.render().decode()
    assert 'result="tw.legacy_auth_failed"' in text


@pytest.mark.parametrize(
    ("key", "status", "code"),
    [
        ("charlie", 403, "tw.forbidden_not_validator"),
        ("dave", 403, "tw.forbidden_not_registered"),
    ],
)
async def test_caller_policy_still_applies(
    miner_app: Any, servers: list[FakeLegacyServer], key: str, status: int, code: str
) -> None:
    body = Syn(text="abc").model_dump_json().encode()
    r = await post_v10(miner_app, "/Syn", body, key=key)
    assert r.status_code == status
    last = servers[0].responses[-1]
    assert last["error"].code == code
    assert last["request"] is not None  # after verification: the bridge signs it


async def test_handler_returning_the_wrong_type(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    kwargs = dict(tw_miner_kwargs)
    kwargs["settings"] = kwargs["settings"].model_copy(
        update={"legacy_v10_until": UNTIL}
    )
    miner = Miner(**kwargs, legacy_server=lambda **kw: FakeLegacyServer(kw))

    @miner.route("/Syn", request=Syn, legacy_synapse=Syn)
    async def syn(s: Syn, ctx: RouteContext) -> bytes:
        return b"not a synapse"

    async with miner.running() as app:
        r = await post_v10(app, "/Syn", Syn(text="a").model_dump_json().encode())
    assert r.status_code == 500


async def test_v10_request_without_the_bridge_is_btauth_malformed(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    miner = Miner(**tw_miner_kwargs)

    @miner.route("/Syn", request=Syn, response=Syn, legacy_synapse=Syn)
    async def syn(s: Syn, ctx: RouteContext) -> Syn:
        return s

    async with miner.running() as app:
        r = await post_v10(app, "/Syn", b"{}")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "tw.auth_malformed"


def _with_until(tw_miner_kwargs: dict[str, Any]) -> dict[str, Any]:
    kwargs = dict(tw_miner_kwargs)
    kwargs["settings"] = kwargs["settings"].model_copy(
        update={"legacy_v10_until": UNTIL}
    )
    return kwargs


async def test_until_builds_the_real_bridge_by_default(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    from taowire.extensions.legacy_v10.server import LegacyServer

    miner = Miner(**_with_until(tw_miner_kwargs))  # no legacy_server=
    async with miner.running():
        bridge = miner.lifecycle.runtime.legacy
        assert isinstance(bridge, LegacyServer)
        assert bridge.until == UNTIL


async def test_until_without_the_bridge_refuses_to_start(
    tw_miner_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A build without extensions/legacy_v10 (the import fails).
    monkeypatch.setitem(sys.modules, "taowire.extensions.legacy_v10.server", None)
    miner = Miner(**_with_until(tw_miner_kwargs))
    with pytest.raises(StartupError, match="not in this build"):
        async with miner.running():
            pass


def test_route_options_are_checked(tw_miner_kwargs: dict[str, Any]) -> None:
    miner = Miner(**tw_miner_kwargs)
    with pytest.raises(ValueError, match="not both"):
        miner.route("/a", legacy_synapse=Syn, legacy_body_hash=lambda b: "")(
            lambda b, c: b
        )
    with pytest.raises(ValueError, match="POST only"):
        miner.route("/b", method="GET", legacy_synapse=Syn)(lambda b, c: b)

    @miner.route("/Syn")
    async def taken(body: bytes, ctx: RouteContext) -> bytes:
        return body

    @miner.route("/v1/x", request=Req, legacy_synapse=Syn)
    async def clash(req: Req, ctx: RouteContext) -> bytes:
        return b""

    with pytest.raises(ValueError, match="v10 path"):
        _ = miner.app


async def test_inbound_days_remaining_is_current_at_every_scrape(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    # Spec 8.11.2 / G3-5: a long-running miner reports the real count.
    today = dt.datetime.fromtimestamp(tw_clock.time(), dt.timezone.utc).date()
    kwargs = dict(tw_miner_kwargs)
    kwargs["settings"] = kwargs["settings"].model_copy(
        update={"legacy_v10_until": today + dt.timedelta(days=15)}
    )
    miner = Miner(**kwargs, legacy_server=lambda **kw: FakeLegacyServer(kw))

    def days_left() -> float | None:
        return miner.metrics.registry.get_sample_value(
            "tw_legacy_v10_days_remaining", {"direction": "inbound"}
        )

    async with miner.running():
        assert days_left() == 15.0
        tw_clock.advance(86_400)
        assert days_left() == 14.0
        tw_clock.advance(86_400)
        assert days_left() == 13.0  # below the 14-day alert line, no restart
        tw_clock.advance(20 * 86_400)
        assert days_left() == 0.0
