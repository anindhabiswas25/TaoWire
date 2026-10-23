"""ValidatorClient rules (spec 8.8) and v10 selector wiring (8.11.3), mocked."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from tensorwire.chain.axon import parse_axon
from tensorwire.chain.gateway import NeuronView
from tensorwire.crypto import HotkeySigner
from tensorwire.extensions.response_sig import sign_response
from tensorwire.observability.metrics import Metrics
from tensorwire.testing.keys import dev_key
from tensorwire.validator.client import ValidatorClient, check_scheme_policy

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
    axon_protocol=4,
)
V10_HEADERS = {"bt_header_axon_status_code": "500"}


class Syn(BaseModel):
    text: str
    result: str | None = None

    def user_fields(self) -> dict[str, Any]:
        return self.model_dump()


class Out(BaseModel):
    result: str


def signed_answer(
    request: httpx.Request, status: int = 200, body: bytes = b'{"result":"OK"}'
) -> httpx.Response:
    headers = sign_response(
        HotkeySigner(MINER.keypair),
        request_nonce=int(request.headers["x-bittensor-nonce"]),
        sender_ss58=request.headers["x-bittensor-hotkey"],
        status=status,
        body=body,
    )
    return httpx.Response(status, content=body, headers=headers)


def make(
    handler: Callable[[httpx.Request], httpx.Response], **kw: Any
) -> tuple[ValidatorClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    options: dict[str, Any] = {"transport": httpx.MockTransport(record)}
    options.update(kw)
    return ValidatorClient(dev_key("alice").signer(), **options), seen


async def test_each_attempt_is_signed_afresh_and_bound_to_the_miner() -> None:
    answers = iter([503, 200])

    def handler(request: httpx.Request) -> httpx.Response:
        status = next(answers)
        return signed_answer(request) if status == 200 else httpx.Response(status)

    vc, seen = make(handler)
    r = await vc.query(NEURON, "/v1/x", b"{}")
    assert r.ok
    assert r.attempts == 2
    nonces = [q.headers["x-bittensor-nonce"] for q in seen]
    assert nonces[0] != nonces[1]
    assert {q.headers["x-bittensor-receiver"] for q in seen} == {MINER.ss58}
    assert str(seen[0].url) == "http://44.0.0.1:8091/v1/x"
    assert seen[0].headers["content-type"] == "application/json"
    await vc.aclose()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500])
async def test_other_statuses_are_not_retried(status: int) -> None:
    vc, seen = make(lambda r: httpx.Response(status))
    r = await vc.query(NEURON, "/v1/x", b"{}")
    assert r.error_code == f"tw.http_{status}"
    assert len(seen) == 1


async def test_redirects_are_not_followed() -> None:
    """Spec 16.1 row 16: a redirect would send the signed request elsewhere."""
    vc, seen = make(
        lambda r: httpx.Response(307, headers={"location": "http://203.0.113.9/x"})
    )
    r = await vc.query(NEURON, "/v1/x", b"{}")
    assert (r.ok, r.error_code, len(seen)) == (False, "tw.http_307", 1)
    await vc.aclose()


async def test_the_default_transport_never_retries() -> None:
    """Spec 16.1 row 6: retries happen in the kit, re-signed; httpx/httpcore
    must not resend a signed request (no public accessor for the setting)."""
    vc = ValidatorClient(dev_key("alice").signer())
    transport: Any = vc._http._transport
    assert isinstance(transport, httpx.AsyncHTTPTransport)
    assert transport._pool._retries == 0
    await vc.aclose()


async def test_retry_statuses_stop_at_max_attempts() -> None:
    vc, seen = make(lambda r: httpx.Response(502), max_attempts=3)
    r = await vc.query(NEURON, "/v1/x", b"{}")
    assert (r.error_code, r.attempts, len(seen)) == ("tw.http_502", 3, 3)


async def test_unsigned_200_is_a_bad_signature() -> None:
    vc, _ = make(lambda r: httpx.Response(200, content=b"{}"))
    r = await vc.query(NEURON, "/v1/x", b"{}")
    assert r.error_code == "tw.bad_response_signature"


async def test_unknown_error_code_in_body_is_not_trusted() -> None:
    body = b'{"error":{"code":"tw.made_up"}}'
    vc, _ = make(lambda r: httpx.Response(403, content=body))
    assert (await vc.query(NEURON, "/v1/x", b"{}")).error_code == "tw.http_403"


async def test_protocol_error_is_invalid_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("peer closed", request=request)

    vc, seen = make(handler)
    r = await vc.query(NEURON, "/v1/x", b"{}")
    assert r.error_code == "tw.invalid_response"
    assert len(seen) == 1


async def test_declared_length_over_cap_is_refused() -> None:
    big = httpx.Response(200, headers={"content-length": "99"}, content=b"x" * 99)
    vc, _ = make(lambda r: big, max_response_bytes=10)
    r = await vc.query(NEURON, "/v1/x", b"{}")
    assert r.error_code == "tw.response_too_large"


async def test_a_bug_never_breaks_the_round() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise ZeroDivisionError

    metrics = Metrics()
    vc, _ = make(handler, metrics=metrics)
    results = await vc.query_many([NEURON], "/v1/x", b"{}")
    assert results[3].error_code == "tw.internal"


async def test_route_must_be_absolute() -> None:
    vc, _ = make(lambda r: httpx.Response(200))
    r = await vc.query(NEURON, "v1/x", b"{}")
    assert r.error_code == "tw.internal"


async def test_https_policy() -> None:
    vc, seen = make(signed_answer, scheme_policy="https")
    await vc.query(NEURON, "/v1/x", b"{}")
    assert seen[0].url.scheme == "https"


async def test_https_if_tls_published_without_a_key_is_plain_http() -> None:
    vc, seen = make(signed_answer, scheme_policy="https-if-tls-published")
    await vc.query(NEURON, "/v1/x", b"{}")
    assert seen[0].url.scheme == "http"


def test_scheme_policies() -> None:
    for policy in ("http", "https", "https-if-tls-published"):
        check_scheme_policy(policy)
    with pytest.raises(ValueError, match="unknown scheme policy"):
        check_scheme_policy("ftp")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_s": 0},
        {"max_concurrency": 0},
        {"max_attempts": 0},
        {"max_response_bytes": 0},
    ],
)
def test_bad_settings(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must be"):
        ValidatorClient(dev_key("alice").signer(), **kwargs)


def test_legacy_needs_both_parts() -> None:
    with pytest.raises(ValueError, match="both"):
        ValidatorClient(dev_key("alice").signer(), legacy=FakeLegacy())


# ---------------------------------------------------------------- v10 wiring


@dataclasses.dataclass
class FakeResult:
    status: int | None
    synapse: BaseModel | None
    error_code: str | None
    latency_ms: float | None = 1.0
    status_message: str | None = None


class FakeLegacy:
    def __init__(self, result: FakeResult | None = None) -> None:
        self.calls: list[BaseModel] = []
        self.result = result or FakeResult(200, Syn(text="a", result="A"), None)

    async def query(
        self,
        http: httpx.AsyncClient,
        neuron: NeuronView,
        synapse: BaseModel,
        *,
        timeout_s: float,
        max_response_bytes: int,
    ) -> FakeResult:
        self.calls.append(synapse)
        return self.result


class FakeSelector:
    def __init__(self, choice: str = "btauth/1", switch: bool = False) -> None:
        self.choice = choice
        self.switch = switch
        self.after: list[dict[str, Any]] = []
        self.reprobed = 0
        self.forgotten: list[str] = []

    def choose(self, neuron: NeuronView) -> Any:
        return self.choice

    def after_btauth(self, neuron: NeuronView, **kw: Any) -> bool:
        self.after.append(kw)
        return self.switch

    def reprobe(self) -> None:
        self.reprobed += 1

    def forget(self, hotkey: str) -> None:
        self.forgotten.append(hotkey)


async def test_remembered_v10_goes_straight_to_v10() -> None:
    legacy, selector = FakeLegacy(), FakeSelector("v10")
    vc, seen = make(signed_answer, legacy=legacy, selector=selector, metrics=Metrics())
    r = await vc.query(NEURON, "/Syn", b"{}", legacy_synapse=Syn(text="a"))
    assert seen == []
    assert r.protocol == "v10"
    assert not r.response_verified
    assert r.ok
    assert r.data == Syn(text="a", result="A")
    assert r.attempts == 1


async def test_v10_marker_switches_once_and_converts_to_response_model() -> None:
    legacy, selector = FakeLegacy(), FakeSelector(switch=True)
    vc, seen = make(
        lambda r: httpx.Response(500, headers=V10_HEADERS),
        legacy=legacy,
        selector=selector,
    )
    r = await vc.query(
        NEURON, "/Syn", b"{}", legacy_synapse=Syn(text="a"), response_model=Out
    )
    assert len(seen) == 1
    assert selector.after[0]["status"] == 500
    assert selector.after[0]["verified"] is False
    assert r.protocol == "v10"
    assert r.data == Out(result="A")
    assert r.attempts == 2


async def test_verified_btauth_answer_is_reported_to_the_selector() -> None:
    legacy, selector = FakeLegacy(), FakeSelector()
    vc, _ = make(signed_answer, legacy=legacy, selector=selector)
    r = await vc.query(NEURON, "/Syn", b"{}", legacy_synapse=Syn(text="a"))
    assert r.protocol == "btauth/1"
    assert selector.after[0]["verified"] is True
    assert legacy.calls == []


async def test_without_a_synapse_the_selector_is_not_used() -> None:
    legacy, selector = FakeLegacy(), FakeSelector("v10")
    vc, seen = make(signed_answer, legacy=legacy, selector=selector)
    r = await vc.query(NEURON, "/x", b"{}")
    assert r.protocol == "btauth/1"
    assert len(seen) == 1
    assert selector.after == []


async def test_no_answer_is_reported_without_status() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    selector = FakeSelector()
    vc, _ = make(refuse, legacy=FakeLegacy(), selector=selector)
    await vc.query(NEURON, "/Syn", b"{}", legacy_synapse=Syn(text="a"))
    assert selector.after[0]["status"] is None
    assert selector.after[0]["headers"] is None


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (FakeResult(None, None, "tw.timeout"), "tw.timeout"),
        (FakeResult(403, None, None), "tw.http_403"),
        (FakeResult(None, None, None), "tw.invalid_response"),
    ],
)
async def test_v10_failures(result: FakeResult, code: str) -> None:
    vc, _ = make(
        signed_answer,
        legacy=FakeLegacy(result),
        selector=FakeSelector("v10"),
        metrics=Metrics(),
    )
    r = await vc.query(NEURON, "/Syn", b"{}", legacy_synapse=Syn(text="a"))
    assert (r.ok, r.error_code, r.data) == (False, code, None)


async def test_v10_answer_not_matching_the_response_model() -> None:
    class Strict(BaseModel):
        number: int

    vc, _ = make(signed_answer, legacy=FakeLegacy(), selector=FakeSelector("v10"))
    r = await vc.query(
        NEURON, "/Syn", b"{}", legacy_synapse=Syn(text="a"), response_model=Strict
    )
    assert r.error_code == "tw.invalid_response"


async def test_reprobe_and_forget_reach_the_selector() -> None:
    selector = FakeSelector()
    vc, _ = make(signed_answer, legacy=FakeLegacy(), selector=selector)
    assert vc.legacy_enabled
    vc.reprobe()
    vc.forget("hk")
    assert (selector.reprobed, selector.forgotten) == (1, ["hk"])
    plain, _ = make(signed_answer)
    assert not plain.legacy_enabled
    plain.reprobe()
    plain.forget("hk")
