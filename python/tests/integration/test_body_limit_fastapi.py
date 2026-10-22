"""BodySizeLimit in front of a real FastAPI app, over httpx's ASGI transport."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI, Request

from tensorwire.limits.body import BodySizeLimit

LIMIT = 1024


def make_app() -> tuple[BodySizeLimit, list[int]]:
    seen: list[int] = []
    api = FastAPI()

    @api.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        body = await request.body()
        seen.append(len(body))
        return {"len": len(body)}

    return BodySizeLimit(api, LIMIT), seen


@pytest.fixture
async def client() -> AsyncIterator[tuple[httpx.AsyncClient, list[int]]]:
    app, seen = make_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://miner") as c:
        yield c, seen


async def test_within_limit(client: tuple[httpx.AsyncClient, list[int]]) -> None:
    c, seen = client
    r = await c.post("/echo", content=b"x" * LIMIT)
    assert r.status_code == 200
    assert r.json() == {"len": LIMIT}
    assert seen == [LIMIT]


async def test_declared_too_large(client: tuple[httpx.AsyncClient, list[int]]) -> None:
    c, seen = client
    r = await c.post("/echo", content=b"x" * (LIMIT + 1))
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "tw.payload_too_large"
    assert seen == []  # the handler never ran


async def test_streamed_too_large(client: tuple[httpx.AsyncClient, list[int]]) -> None:
    c, seen = client

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(8):
            yield b"x" * 300

    r = await c.post("/echo", content=chunks())  # chunked: no Content-Length
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "tw.payload_too_large"
    assert seen == []
