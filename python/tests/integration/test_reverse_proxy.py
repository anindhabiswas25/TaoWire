"""A miner behind a reverse proxy (spec 16.3, docs/security.md).

A proxy must pass the request target and body unchanged. Three ASGI proxies
sit in front of a real miner app on FakeChain: one that passes everything
through (as ``deploy/proxy/`` does; checked against real Caddy and nginx in
``reports/phase-4/wp6/proxy-check.txt``), one that normalises the path, and
one that re-encodes the JSON body. The last two make every request fail
verification with the documented 401 ``tw.auth_bad_signature``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, MutableMapping
from typing import Any
from urllib.parse import unquote

import pytest
from pydantic import BaseModel

from tensorwire.chain.gateway import NeuronView
from tensorwire.miner.app import Miner
from tensorwire.miner.routes import RouteContext
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.pytest_plugin import MINER_KEY, TEST_NETUID
from tensorwire.testing.transport import AppRouter
from tensorwire.validator.client import ValidatorClient

pytestmark = pytest.mark.asyncio

ADDRESS = "44.1.2.3:8091"
PROXY_IP = "10.0.0.5"
BODY = b'{"n":  2}'  # two spaces: re-encoding changes the bytes, not the value

Proxy = Callable[[Any], Any]


class Gen(BaseModel):
    n: int


def proxy(
    app: Any,
    *,
    path: Callable[[str], str] | None = None,
    reencode: bool = False,
    client: str = "203.0.113.9",
) -> Any:
    """An ASGI reverse proxy at PROXY_IP; ``client`` is the caller's address."""

    async def proxied(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        headers = [(k, v) for k, v in scope["headers"] if k != b"x-forwarded-for"]
        forwarded = dict(scope["headers"]).get(b"x-forwarded-for")
        chain = (forwarded + b", " if forwarded else b"") + client.encode()
        scope = {**scope, "client": (PROXY_IP, 4000), "headers": headers}
        scope["headers"].append((b"x-forwarded-for", chain))
        if path is not None:
            scope["path"] = path(scope["path"])
            scope["raw_path"] = scope["path"].encode()
        if not reencode:
            await app(scope, receive, send)
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        body = json.dumps(json.loads(body)).encode()
        scope["headers"] = [
            (k, str(len(body)).encode() if k == b"content-length" else v)
            for k, v in scope["headers"]
        ]

        async def replay() -> dict[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        await app(scope, replay, send)

    return proxied


def merge_slashes(path: str) -> str:
    """A proxy that merges slashes (nginx's location matching does by default)."""
    return re.sub("/+", "/", path)


@pytest.fixture
def miner(tw_miner_kwargs: dict[str, Any]) -> tuple[Miner, list[str]]:
    settings = tw_miner_kwargs["settings"].model_copy(
        update={
            "trusted_proxies": (ipaddress.ip_network("10.0.0.0/8"),),
            "rate_ip_per_s": 0.001,  # one request per client address
            "rate_ip_burst": 1,
        }
    )
    m = Miner(**{**tw_miner_kwargs, "settings": settings})
    seen: list[str] = []

    @m.route("/v1/gen", request=Gen, response=Gen)
    async def gen(req: Gen, ctx: RouteContext) -> Gen:
        seen.append(ctx.route)
        return req

    return m, seen


async def neuron(chain: FakeChain) -> NeuronView:
    chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
    found = (await chain.metagraph(TEST_NETUID)).by_hotkey(dev_key(MINER_KEY).ss58)
    assert found is not None
    return found


async def query(app: Any, chain: FakeChain, clock: FakeClock, route: str) -> Any:
    signer = dev_key("alice").signer(clock_ns=clock.now_ns)
    async with ValidatorClient(
        signer, transport=AppRouter({ADDRESS: app}), max_attempts=1
    ) as client:
        return await client.query(await neuron(chain), route, BODY)


async def test_a_pass_through_proxy_works_and_forwards_the_client_ip(
    miner: tuple[Miner, list[str]], fake_chain: FakeChain, tw_clock: FakeClock
) -> None:
    m, seen = miner
    async with m.running() as app:
        first = await query(proxy(app), fake_chain, tw_clock, "/v1/gen")
        tw_clock.advance(1)  # a new nonce
        # Rate limits are per client address, not per proxy address:
        other = await query(
            proxy(app, client="198.51.100.7"), fake_chain, tw_clock, "/v1/gen"
        )
        tw_clock.advance(1)
        again = await query(proxy(app), fake_chain, tw_clock, "/v1/gen")
    assert first.ok, first
    assert first.response_verified
    assert other.ok, other
    assert (again.status, again.error_code) == (429, "tw.rate_limited")
    assert seen == ["/v1/gen", "/v1/gen"]


@pytest.mark.parametrize(
    ("route", "rewrite"),
    [
        ("/v1//gen", merge_slashes),
        ("/v1/%67en", unquote),  # decodes percent-encoded characters
    ],
)
async def test_a_path_normalising_proxy_breaks_verification(
    miner: tuple[Miner, list[str]],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    route: str,
    rewrite: Callable[[str], str],
) -> None:
    m, seen = miner
    assert rewrite(route) == "/v1/gen"  # (httpx itself removes "." and "..")
    async with m.running() as app:
        result = await query(proxy(app, path=rewrite), fake_chain, tw_clock, route)
    assert (result.status, result.error_code) == (401, "tw.auth_bad_signature")
    assert seen == []


async def test_a_body_re_encoding_proxy_breaks_verification(
    miner: tuple[Miner, list[str]], fake_chain: FakeChain, tw_clock: FakeClock
) -> None:
    m, seen = miner
    async with m.running() as app:
        result = await query(proxy(app, reencode=True), fake_chain, tw_clock, "/v1/gen")
    assert (result.status, result.error_code) == (401, "tw.auth_bad_signature")
    assert seen == []
