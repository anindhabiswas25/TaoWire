"""The miner request path beyond tests 1-9: F2, limits, parsing, handlers, health."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import pytest
from bittensor import http_auth, sp_core
from pydantic import BaseModel

from tensorwire.errors import Forbidden, ReplayStoreUnavailable
from tensorwire.miner.app import Miner
from tensorwire.miner.routes import RouteContext
from tensorwire.policy.caller import CallerPolicy
from tensorwire.testing.client import BASE_URL, SignedClient
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.pytest_plugin import TEST_NETUID

pytestmark = pytest.mark.asyncio

BOB = dev_key("bob")
OPEN = "/v1/open"  # relaxed policy: any authenticated caller
STRICT = "/v1/strict"
SYNC = "/v1/sync"
RAW = "/v1/raw"
GET = "/v1/info"
BROKEN = "/v1/broken"
WRONG = "/v1/wrong"
KIT_ERROR = "/v1/kit-error"
OWN_TIMEOUT = "/v1/own-timeout"


class Ping(BaseModel):
    n: int


class Pong(BaseModel):
    n: int
    caller: str
    registered: bool


def pong(req: Ping, ctx: RouteContext) -> Pong:
    return Pong(
        n=req.n, caller=ctx.caller.hotkey_ss58, registered=ctx.caller_neuron is not None
    )


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any]) -> Miner:
    settings = tw_miner_kwargs["settings"].model_copy(
        update={
            "deny_hotkeys": frozenset({dev_key("dave").ss58}),
            "rate_hotkey_per_s": 0.001,
            "rate_hotkey_burst": 2,
        }
    )
    miner = Miner(**{**tw_miner_kwargs, "settings": settings})
    relaxed = CallerPolicy(require_registered=False, require_validator_permit=False)

    @miner.route(OPEN, request=Ping, response=Pong, policy=relaxed)
    async def open_route(req: Ping, ctx: RouteContext) -> Pong:
        return pong(req, ctx)

    @miner.route(STRICT, request=Ping, response=Pong)
    async def strict_route(req: Ping, ctx: RouteContext) -> Pong:
        return pong(req, ctx)

    @miner.route(SYNC, request=Ping, response=Pong, timeout_s=0.05)
    def sync_route(req: Ping, ctx: RouteContext) -> Pong:
        if req.n < 0:
            time.sleep(0.3)
        return pong(req, ctx)

    @miner.route(RAW)
    async def raw_route(body: bytes, ctx: RouteContext) -> bytes:
        return body[::-1]

    @miner.route(GET, method="GET", response=Pong)
    async def get_route(req: None, ctx: RouteContext) -> Pong:
        return Pong(n=0, caller=ctx.caller.hotkey_ss58, registered=True)

    @miner.route(BROKEN, request=Ping)
    async def broken(req: Ping, ctx: RouteContext) -> Pong:
        raise RuntimeError("secret internal detail /etc/passwd")

    @miner.route(WRONG, request=Ping, response=Pong)
    async def wrong(req: Ping, ctx: RouteContext) -> Any:
        return {"n": 1}

    @miner.route(KIT_ERROR, request=Ping)
    async def kit_error(req: Ping, ctx: RouteContext) -> Pong:
        raise Forbidden(code="tw.forbidden_blacklisted")

    @miner.route(OWN_TIMEOUT, request=Ping)
    async def own_timeout(req: Ping, ctx: RouteContext) -> Pong:
        raise TimeoutError

    return miner


def code_of(r: httpx.Response) -> str:
    return str(r.json()["error"]["code"])


def alt_headers(
    clock: FakeClock, key: str, path: str, body: bytes, prefix: int
) -> dict[str, str]:
    """btauth/1 headers signed by ``key`` under an alternate SS58 encoding."""
    kp = dev_key(key).keypair
    alt = str(sp_core.ss58_encode(bytes(sp_core.ss58_decode(kp.ss58_address)), prefix))
    nonce = clock.now_ns()
    payload = http_auth.build_payload(
        scheme="sr25519",
        method="POST",
        path=path,
        body=body,
        nonce_ns=nonce,
        sender_ss58=alt,
        receiver_ss58=BOB.ss58,
    )
    return {
        http_auth.HEADER_VERSION: "1",
        http_auth.HEADER_HOTKEY: alt,
        http_auth.HEADER_RECEIVER: BOB.ss58,
        http_auth.HEADER_NONCE: str(nonce),
        http_auth.HEADER_SIGNATURE: "0x" + bytes(kp.sign(payload)).hex(),
    }


# ---------------------------------------------------------------- F2 (spec A11)


async def test_f2_denied_hotkey_cannot_hide_behind_another_encoding(
    signed_client: SignedClient, tw_clock: FakeClock
) -> None:
    dave = signed_client.as_key("dave")
    r = await dave.post(OPEN, json={"n": 1})
    assert (r.status_code, code_of(r)) == (403, "tw.forbidden_denied")
    body = b'{"n":1}'
    for prefix in (0, 2, 7):
        headers = alt_headers(tw_clock, "dave", OPEN, body, prefix)
        r = await signed_client.send_raw("POST", OPEN, content=body, headers=headers)
        assert (r.status_code, code_of(r)) == (401, "tw.auth_malformed")


async def test_f2_rate_limited_hotkey_cannot_reset_its_bucket(
    signed_client: SignedClient, tw_clock: FakeClock
) -> None:
    eve = signed_client.as_key("eve")  # unregistered; the open route admits it
    for _ in range(2):
        assert (await eve.post(OPEN, json={"n": 1})).status_code == 200
    r = await eve.post(OPEN, json={"n": 1})
    assert (r.status_code, code_of(r)) == (429, "tw.rate_limited")
    assert int(r.headers["retry-after"]) >= 1
    body = b'{"n":1}'
    for prefix in (0, 5):
        headers = alt_headers(tw_clock, "eve", OPEN, body, prefix)
        r = await signed_client.send_raw("POST", OPEN, content=body, headers=headers)
        assert (r.status_code, code_of(r)) == (401, "tw.auth_malformed")


# ---------------------------------------------------------------- policy


async def test_relaxed_route_admits_unregistered_and_strict_route_does_not(
    signed_client: SignedClient,
) -> None:
    eve = signed_client.as_key("eve")
    r = await eve.post(OPEN, json={"n": 3})
    assert r.json() == {"n": 3, "caller": dev_key("eve").ss58, "registered": False}
    r = await eve.post(STRICT, json={"n": 3})
    assert (r.status_code, code_of(r)) == (403, "tw.forbidden_not_registered")


async def test_global_deny_list_applies_to_relaxed_routes(
    tw_miner: Miner,
) -> None:
    assert dev_key("dave").ss58 in tw_miner.routes.get(OPEN).policy.deny_hotkeys  # type: ignore[union-attr]


async def test_hotkey_buckets_are_per_route(signed_client: SignedClient) -> None:
    for _ in range(2):
        assert (await signed_client.post(OPEN, json={"n": 1})).status_code == 200
    assert (await signed_client.post(OPEN, json={"n": 1})).status_code == 429
    assert (await signed_client.post(STRICT, json={"n": 1})).status_code == 200


# ---------------------------------------------------------------- parsing & handlers


@pytest.mark.parametrize("body", [b"not json", b'{"n":"x"}', b"{}", b""])
async def test_invalid_body_is_422(signed_client: SignedClient, body: bytes) -> None:
    r = await signed_client.post(STRICT, content=body)
    assert (r.status_code, code_of(r)) == (422, "tw.invalid_request")
    assert "pydantic" not in r.text


async def test_sync_handler_runs_and_times_out(signed_client: SignedClient) -> None:
    r = await signed_client.post(SYNC, json={"n": 5})
    assert r.status_code == 200
    assert r.json()["n"] == 5
    r = await signed_client.post(SYNC, json={"n": -1})
    assert (r.status_code, code_of(r)) == (504, "tw.handler_timeout")


async def test_raw_route_gets_verified_bytes_and_returns_bytes(
    signed_client: SignedClient,
) -> None:
    r = await signed_client.post(RAW, content=b"abc")
    assert r.status_code == 200
    assert r.content == b"cba"
    assert r.headers["content-type"] == "application/octet-stream"


async def test_get_route_is_signed_and_takes_no_body(
    signed_client: SignedClient,
) -> None:
    r = await signed_client.get(GET)
    assert r.status_code == 200
    assert r.json()["caller"] == dev_key("alice").ss58
    r = await signed_client.request("GET", GET, content=b"x")
    assert (r.status_code, code_of(r)) == (422, "tw.invalid_request")
    unsigned = await signed_client.http.get(GET)
    assert (unsigned.status_code, code_of(unsigned)) == (401, "tw.auth_malformed")


async def test_wrong_method_is_405(signed_client: SignedClient) -> None:
    r = await signed_client.get(STRICT)
    assert r.status_code == 405


async def test_handler_exception_is_500_without_detail(
    signed_client: SignedClient,
) -> None:
    r = await signed_client.post(BROKEN, json={"n": 1})
    assert (r.status_code, code_of(r)) == (500, "tw.handler_error")
    assert "passwd" not in r.text
    assert "RuntimeError" not in r.text


async def test_handler_own_timeout_error_is_not_a_kit_timeout(
    signed_client: SignedClient,
) -> None:
    r = await signed_client.post(OWN_TIMEOUT, json={"n": 1})
    assert (r.status_code, code_of(r)) == (500, "tw.handler_error")


async def test_handler_wrong_return_type_is_500(signed_client: SignedClient) -> None:
    r = await signed_client.post(WRONG, json={"n": 1})
    assert (r.status_code, code_of(r)) == (500, "tw.handler_error")


async def test_handler_kit_error_passes_through(signed_client: SignedClient) -> None:
    r = await signed_client.post(KIT_ERROR, json={"n": 1})
    assert (r.status_code, code_of(r)) == (403, "tw.forbidden_blacklisted")


async def test_unknown_route_is_404(signed_client: SignedClient) -> None:
    r = await signed_client.post("/v1/nope", json={"n": 1})
    assert r.status_code == 404


async def test_error_bodies_carry_the_request_id(signed_client: SignedClient) -> None:
    r = await signed_client.as_key("charlie").post(STRICT, json={"n": 1})
    assert r.json()["error"]["request_id"] == r.headers["x-tw-request-id"]


# ---------------------------------------------------------------- pre-auth layers


async def test_ip_rate_limit_rejects_before_auth(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    settings = tw_miner_kwargs["settings"].model_copy(
        update={"rate_ip_per_s": 0.001, "rate_ip_burst": 1}
    )
    miner = Miner(**{**tw_miner_kwargs, "settings": settings})

    @miner.route(STRICT, request=Ping, response=Pong)
    async def strict_route(req: Ping, ctx: RouteContext) -> Pong:
        return pong(req, ctx)

    async with miner.running() as app:
        client = SignedClient(app, receiver_ss58=BOB.ss58, clock_ns=tw_clock.now_ns)
        assert (await client.post(STRICT, json={"n": 1})).status_code == 200
        r = await client.post(STRICT, json={"n": 1})
        assert (r.status_code, code_of(r)) == (429, "tw.rate_limited")
        assert "retry-after" in r.headers
        samples = miner.metrics.registry.get_sample_value(
            "tw_rate_limited_total", {"layer": "ip"}
        )
        assert samples == 1
        await client.aclose()


async def test_replay_store_outage_is_503_and_counted(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    class DownStore:
        retention = 60.0

        def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
            raise ReplayStoreUnavailable()

        def ping(self) -> bool:
            return False

    miner = Miner(**{**tw_miner_kwargs, "nonce_store": DownStore()})

    @miner.route(STRICT, request=Ping, response=Pong)
    async def strict_route(req: Ping, ctx: RouteContext) -> Pong:
        return pong(req, ctx)

    async with miner.running() as app:
        client = SignedClient(app, receiver_ss58=BOB.ss58, clock_ns=tw_clock.now_ns)
        r = await client.post(STRICT, json={"n": 1})
        assert (r.status_code, code_of(r)) == (503, "tw.replay_store_unavailable")
        value = miner.metrics.registry.get_sample_value(
            "tw_nonce_store_errors_total", {"backend": "redis"}
        )
        assert value == 1
        ready = await client.http.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["reasons"] == ["nonce_store_unreachable"]
        await client.aclose()


# ---------------------------------------------------------------- health & metrics


async def test_healthz_reveals_nothing(signed_client: SignedClient) -> None:
    r = await signed_client.http.get("/healthz")
    assert r.json() == {"status": "ok"}
    assert BOB.ss58 not in r.text


async def test_readyz_lifecycle(
    tw_miner: Miner, signed_client: SignedClient, fake_chain: FakeChain
) -> None:
    r = await signed_client.http.get("/readyz")
    assert r.json() == {"status": "ready", "degraded": []}
    fake_chain.deregister(TEST_NETUID, BOB.ss58)
    await tw_miner.lifecycle.runtime.metagraph.refresh_now()
    r = await signed_client.http.get("/readyz")
    assert (r.status_code, r.json()["reasons"]) == (503, ["not_registered"])
    await tw_miner.lifecycle.stop()
    r = await signed_client.http.get("/readyz")
    assert r.json()["reasons"] == ["stopping"]


async def test_readyz_before_start_says_starting(tw_miner: Miner) -> None:
    transport = httpx.ASGITransport(app=tw_miner.app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as http:
        r = await http.get("/readyz")
    assert (r.status_code, r.json()["reasons"]) == (503, ["starting"])


async def test_request_metrics_and_access_log(
    tw_miner: Miner, signed_client: SignedClient, capsys: pytest.CaptureFixture[str]
) -> None:
    await signed_client.post(STRICT, json={"n": 1})
    await signed_client.as_key("charlie").post(STRICT, json={"n": 1})
    await signed_client.http.post("/v1/nope")
    reg = tw_miner.metrics.registry
    ok = reg.get_sample_value(
        "tw_requests_total", {"route": STRICT, "status": "200", "code": "ok"}
    )
    denied = reg.get_sample_value(
        "tw_policy_denials_total", {"code": "tw.forbidden_not_validator"}
    )
    unmatched = reg.get_sample_value(
        "tw_requests_total", {"route": "unmatched", "status": "404", "code": "http_404"}
    )
    assert (ok, denied, unmatched) == (1, 1, 1)
    assert reg.get_sample_value("tw_auth_verify_duration_seconds_count") == 2
    out = capsys.readouterr().out
    assert "5GrwvaEF…" in out
    assert dev_key("alice").ss58 not in out


async def test_concurrent_requests(signed_client: SignedClient) -> None:
    clients = [signed_client.as_key(k) for k in ("alice", "charlie", "eve")]
    results = await asyncio.gather(*(c.post(OPEN, json={"n": 1}) for c in clients))
    assert [r.status_code for r in results] == [200, 200, 200]
