"""Integration tests 1-9 (spec 13.4): the real miner app, in process, on FakeChain.

Keys (testing.pytest_plugin): bob = miner, alice = validator (permit),
charlie = registered without permit, dave = unregistered.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import BaseModel

from taowire.chain.metagraph_cache import StalenessStage
from taowire.extensions.response_sig import verify_response
from taowire.miner.app import Miner
from taowire.miner.routes import RouteContext
from taowire.testing.client import SignedClient
from taowire.testing.clock import FakeClock
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.pytest_plugin import TEST_NETUID

pytestmark = pytest.mark.asyncio

ECHO = "/v1/echo"
SLOW = "/v1/slow"


class EchoRequest(BaseModel):
    text: str


class EchoResponse(BaseModel):
    text: str
    caller: str
    uid: int | None


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any]) -> Miner:
    miner = Miner(**tw_miner_kwargs)

    @miner.route(ECHO, request=EchoRequest, response=EchoResponse, max_body_bytes=1024)
    async def echo(req: EchoRequest, ctx: RouteContext) -> EchoResponse:
        uid = None if ctx.caller_neuron is None else ctx.caller_neuron.uid
        return EchoResponse(text=req.text, caller=ctx.caller.hotkey_ss58, uid=uid)

    @miner.route(SLOW, request=EchoRequest, response=EchoResponse, timeout_s=0.05)
    async def slow(req: EchoRequest, ctx: RouteContext) -> EchoResponse:
        await asyncio.sleep(5)
        raise AssertionError("not reached")

    return miner


def code_of(response: Any) -> str:
    return str(response.json()["error"]["code"])


def check_response_signature(response: Any, sender: str = "alice") -> None:
    """Raise unless ``response`` carries a valid twresp/1 signature from bob."""
    verify_response(
        response.headers,
        expected_responder=dev_key("bob").ss58,
        request_nonce=int(response.request.headers["x-bittensor-nonce"]),
        sender_ss58=dev_key(sender).ss58,
        status=response.status_code,
        body=response.content,
    )


# 1 ----------------------------------------------------------------------------
async def test_1_valid_validator_gets_200(signed_client: SignedClient) -> None:
    r = await signed_client.post(ECHO, json={"text": "hi"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"text": "hi", "caller": dev_key("alice").ss58, "uid": 1}
    assert len(r.headers["x-tw-request-id"]) == 26
    check_response_signature(r)
    assert r.headers["x-tw-resp-hotkey"] == dev_key("bob").ss58
    assert "x-tw-resp-crypto" not in r.headers  # sr25519: header omitted


# 2 ----------------------------------------------------------------------------
async def test_2_registered_non_validator_is_forbidden(
    signed_client: SignedClient,
) -> None:
    r = await signed_client.as_key("charlie").post(ECHO, json={"text": "hi"})
    assert r.status_code == 403
    assert code_of(r) == "tw.forbidden_not_validator"
    check_response_signature(r, sender="charlie")  # after auth: signed (Appendix A)


# 3 ----------------------------------------------------------------------------
async def test_3_unregistered_hotkey_is_forbidden(signed_client: SignedClient) -> None:
    r = await signed_client.as_key("dave").post(ECHO, json={"text": "hi"})
    assert r.status_code == 403
    assert code_of(r) == "tw.forbidden_not_registered"


# 4 ----------------------------------------------------------------------------
async def test_4_replayed_headers_are_rejected(signed_client: SignedClient) -> None:
    body = b'{"text":"hi"}'
    headers = signed_client.sign("POST", ECHO, body)
    first = await signed_client.send_raw("POST", ECHO, content=body, headers=headers)
    again = await signed_client.send_raw("POST", ECHO, content=body, headers=headers)
    assert first.status_code == 200
    assert again.status_code == 401
    assert code_of(again) == "tw.auth_replayed"


# 5 ----------------------------------------------------------------------------
async def test_5_request_for_another_miner_is_rejected(
    signed_client: SignedClient,
) -> None:
    other_miner = dev_key("eve").ss58
    r = await signed_client.post(ECHO, json={"text": "hi"}, receiver_ss58=other_miner)
    assert r.status_code == 401
    assert code_of(r) == "tw.auth_wrong_receiver"
    assert "x-tw-resp-signature" not in r.headers  # before auth: never signed


# 6 ----------------------------------------------------------------------------
async def test_6_old_nonce_is_stale(
    signed_client: SignedClient, tw_clock: FakeClock
) -> None:
    body = b'{"text":"hi"}'
    headers = signed_client.sign("POST", ECHO, body)
    tw_clock.advance(10.5)  # default TW_AUTH_MAX_AGE_S is 10
    r = await signed_client.send_raw("POST", ECHO, content=body, headers=headers)
    assert r.status_code == 401
    assert code_of(r) == "tw.auth_stale"


# 7 ----------------------------------------------------------------------------
async def test_7_staleness_stages(
    tw_miner: Miner,
    signed_client: SignedClient,
    tw_clock: FakeClock,
    fake_chain: FakeChain,
) -> None:
    source = tw_miner.lifecycle.runtime.metagraph
    soft, max_age = source.thresholds.soft_age_s, source.thresholds.max_age_s
    assert (soft, max_age) == (900, 8640)  # defaults at tempo 360
    fake_chain.register(TEST_NETUID, dev_key("dave").ss58, validator_permit=True)
    alice = signed_client
    dave = signed_client.as_key("dave")

    # fresh: alice calls and becomes a known caller; dave has no permit yet.
    assert (await alice.post(ECHO, json={"text": "a"})).status_code == 200

    # past the soft age: degraded, still served, /readyz says so.
    tw_clock.advance(soft + 1)
    assert source.stage() is StalenessStage.DEGRADED
    assert (await alice.post(ECHO, json={"text": "a"})).status_code == 200
    ready = await alice.http.get("/readyz")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready", "degraded": ["metagraph_stale"]}

    # past the max age: known callers only.
    tw_clock.advance(max_age)
    assert source.stage() is StalenessStage.KNOWN_CALLERS_ONLY
    r_alice = await alice.post(ECHO, json={"text": "a"})
    r_dave = await dave.post(ECHO, json={"text": "d"})
    assert r_alice.status_code == 200
    assert r_dave.status_code == 503
    assert code_of(r_dave) == "tw.metagraph_stale"
    ready = await alice.http.get("/readyz")
    assert ready.status_code == 503
    assert ready.json() == {"status": "not_ready", "reasons": ["metagraph_stale"]}

    # a fresh snapshot clears the known set and decides again: dave is now a
    # validator on chain (registered above), so he gets in; known set restarts.
    await source.refresh_now()
    assert len(tw_miner.lifecycle.runtime.gate.known) == 0
    assert (await dave.post(ECHO, json={"text": "d"})).status_code == 200
    assert (await alice.http.get("/readyz")).json()["status"] == "ready"


async def test_7_strict_mode_refuses_everyone_past_max_age(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    settings = tw_miner_kwargs["settings"].model_copy(update={"metagraph_strict": True})
    miner = Miner(**{**tw_miner_kwargs, "settings": settings})

    @miner.route(ECHO, request=EchoRequest, response=EchoResponse)
    async def echo(req: EchoRequest, ctx: RouteContext) -> EchoResponse:
        return EchoResponse(text=req.text, caller=ctx.caller.hotkey_ss58, uid=None)

    async with miner.running() as app:
        client = SignedClient(
            app, receiver_ss58=dev_key("bob").ss58, clock_ns=tw_clock.now_ns
        )
        assert (await client.post(ECHO, json={"text": "a"})).status_code == 200
        tw_clock.advance(miner.lifecycle.runtime.metagraph.thresholds.max_age_s + 1)
        verify_calls = 0
        verifier = miner.lifecycle.runtime.verifier
        original = verifier.verify

        async def counting(*args: Any, **kwargs: Any) -> Any:
            nonlocal verify_calls
            verify_calls += 1
            return await original(*args, **kwargs)

        verifier.verify = counting  # type: ignore[method-assign]
        r = await client.post(ECHO, json={"text": "a"})  # alice is a known caller
        assert r.status_code == 503
        assert code_of(r) == "tw.metagraph_stale"
        assert verify_calls == 0  # strict mode rejects at step 5, before verify
        await client.aclose()


# 8 ----------------------------------------------------------------------------
@pytest.mark.parametrize("chunked", [False, True])
async def test_8_oversized_body_rejected_before_verification(
    tw_miner: Miner, signed_client: SignedClient, chunked: bool
) -> None:
    calls = 0
    verifier = tw_miner.lifecycle.runtime.verifier
    original = verifier.verify

    async def counting(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return await original(*args, **kwargs)

    verifier.verify = counting  # type: ignore[method-assign]
    body = b'{"text":"' + b"x" * 2000 + b'"}'  # the route allows 1024 bytes
    headers = signed_client.sign("POST", ECHO, body)
    if chunked:

        async def stream() -> Any:
            for i in range(0, len(body), 100):
                yield body[i : i + 100]

        r = await signed_client.http.post(ECHO, content=stream(), headers=headers)
    else:
        r = await signed_client.send_raw("POST", ECHO, content=body, headers=headers)
    assert r.status_code == 413
    assert code_of(r) == "tw.payload_too_large"
    assert calls == 0


# 9 ----------------------------------------------------------------------------
async def test_9_handler_timeout(signed_client: SignedClient) -> None:
    r = await signed_client.post(SLOW, json={"text": "hi"})
    assert r.status_code == 504
    assert code_of(r) == "tw.handler_timeout"
    check_response_signature(r)


# twresp/1 switches -------------------------------------------------------------
async def test_responses_unsigned_when_sign_responses_off(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    kwargs = dict(tw_miner_kwargs)
    kwargs["settings"] = kwargs["settings"].model_copy(update={"sign_responses": False})
    miner = Miner(**kwargs)

    @miner.route(ECHO, request=EchoRequest, response=EchoResponse)
    async def echo(req: EchoRequest, ctx: RouteContext) -> EchoResponse:
        return EchoResponse(text=req.text, caller=ctx.caller.hotkey_ss58, uid=None)

    async with miner.running() as app:
        client = SignedClient(
            app, receiver_ss58=dev_key("bob").ss58, clock_ns=tw_clock.now_ns
        )
        r = await client.post(ECHO, json={"text": "hi"})
        await client.aclose()
    assert r.status_code == 200
    assert not any(k.startswith("x-tw-resp-") for k in r.headers)


async def test_invalid_request_is_signed(signed_client: SignedClient) -> None:
    r = await signed_client.post(ECHO, json={"nope": 1})
    assert r.status_code == 422
    check_response_signature(r)
