"""Property tests for the sidecar's request parsers (spec 11.6, 13.3).

1. ``parse_serve_axon`` on arbitrary bytes and JSON: either the documented
   tuple (and only for a body that really is the contract) or
   ``InvalidRequest``, never anything else.
2. The bearer check accepts exactly ``Bearer <token>``.
3. Through the app: an arbitrary ``netuid`` parameter, hotkey path segment or
   ``Authorization`` header never reaches a decision, a snapshot or a chain
   write unless it is exactly right (422 / 401 otherwise).
"""

from __future__ import annotations

import asyncio
import json
import string
from typing import Any

import httpx
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tensorwire.config import SidecarSettings
from tensorwire.errors import InvalidRequest
from tensorwire.policy.caller import CallerGate, CallerPolicy
from tensorwire.sidecar import create_app, parse_serve_axon, token_matches
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource

TOKEN = "k" * 43
BOB = dev_key("bob").ss58
ALICE = dev_key("alice").ss58
_SETTINGS = settings(
    max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=20),
    lambda inner: (
        st.lists(inner, max_size=4)
        | st.dictionaries(st.text(max_size=12), inner, max_size=5)
    ),
    max_leaves=12,
)
contract_like = st.fixed_dictionaries(
    {
        "netuid": st.one_of(st.just(1), json_values),
        "ip": st.one_of(st.just("203.0.113.7"), json_values),
        "port": st.one_of(st.integers(-5, 70_000), json_values),
    },
    optional={
        "tls_cert_hex": st.one_of(st.none(), st.just("0x01ab"), json_values),
        "x": json_values,
    },
)


@_SETTINGS
@given(
    st.one_of(
        st.binary(max_size=200),
        json_values.map(lambda v: json.dumps(v).encode()),
        contract_like.map(lambda v: json.dumps(v).encode()),
    )
)
def test_serve_axon_body_is_the_contract_or_refused(body: bytes) -> None:
    try:
        ip, port, cert = parse_serve_axon(body, 1)
    except InvalidRequest:
        return
    value = json.loads(body)
    assert isinstance(value, dict)
    assert set(value) <= {"netuid", "ip", "port", "tls_cert_hex"}
    assert value["netuid"] == 1
    assert type(value["netuid"]) is int
    assert (ip, port) == (value["ip"], value["port"])
    assert type(port) is int
    assert 1 <= port <= 65535
    assert cert is None or (cert.startswith("0x") and len(cert) % 2 == 0)


@_SETTINGS
@given(
    st.text(max_size=80), st.text(alphabet=string.printable, min_size=16, max_size=64)
)
def test_bearer_check_is_exact(header: str, token: str) -> None:
    assert token_matches(header, token) == (header == f"Bearer {token}")
    assert token_matches(f"Bearer {token}", token)


def _app() -> tuple[Any, FakeChain]:
    chain = FakeChain(signer_hotkey=BOB)
    chain.add_subnet(1)
    chain.register(1, BOB)
    chain.register(1, ALICE, validator_permit=True, stake_tao=1000)
    source = FakeMetagraphSource(chain, 1)

    async def connect() -> None:
        await chain.connect()
        await source.start()

    asyncio.run(connect())
    s = SidecarSettings(netuid=1, wallet_name="x")
    app = create_app(
        settings=s,
        gateway=chain,
        metagraph=source,
        gate=CallerGate(source),
        policy=CallerPolicy.from_settings(s),
        hotkey_ss58=BOB,
        token=TOKEN,
    )
    return app, chain


APP, CHAIN = _app()


async def _get(path: str, headers: dict[str, str] | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=APP)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
        return await http.get(
            path,
            headers={"Authorization": f"Bearer {TOKEN}"}
            if headers is None
            else headers,
        )


@_SETTINGS
@given(st.text(alphabet=string.ascii_letters + string.digits + "-+. %&=", max_size=12))
def test_arbitrary_netuid_parameter(netuid: str) -> None:
    q = httpx.QueryParams({"netuid": netuid})
    r = asyncio.run(_get(f"/v1/metagraph?{q}"))
    if netuid == "1" or (
        netuid.lstrip("0") == "1" and netuid.isdigit() and len(netuid) <= 5
    ):
        assert r.status_code == 200
    else:
        assert r.status_code == 422
        assert r.json()["error"]["code"] == "tw.invalid_request"


@_SETTINGS
@given(
    st.one_of(
        st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=60),
        st.just(ALICE),
        st.just(ALICE[:-1] + "x"),
    )
)
def test_arbitrary_hotkey_segment(hotkey: str) -> None:
    r = asyncio.run(_get(f"/v1/caller/{hotkey}?netuid=1"))
    if hotkey == ALICE:
        assert r.json() == {"allowed": True}
    elif (
        r.status_code == 200
    ):  # some other valid SS58 address: never allowed (not registered)
        assert r.json()["allowed"] is False
    else:
        assert r.status_code == 422


@_SETTINGS
@given(
    st.text(alphabet=string.printable.replace("\n", "").replace("\r", ""), max_size=70)
)
def test_arbitrary_authorization_header(value: str) -> None:
    r = asyncio.run(_get("/v1/metagraph?netuid=1", headers={"Authorization": value}))
    if value.strip() == f"Bearer {TOKEN}" and value == value.strip():
        assert r.status_code == 200
    elif r.status_code != 200:
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "tw.sidecar_unauthorized"
    assert CHAIN.calls["serve_axon"] == 0
