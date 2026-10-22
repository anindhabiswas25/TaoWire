"""A btauth/1-signing HTTP client for in-process miner tests (spec 8.13).

:class:`SignedClient` sends requests to an ASGI app through
``httpx.ASGITransport`` (no network) and signs each one with a development
key, bound to the miner's hotkey. Every call signs afresh, with a strictly
increasing nonce from the given clock::

    client = SignedClient(miner.app, receiver_ss58=miner_hotkey, clock_ns=clock.now_ns)
    r = await client.post("/v1/transform", json={"text": "hi"})
    r = await client.as_key("charlie").post("/v1/transform", json={"text": "hi"})
"""

from __future__ import annotations

import json as jsonlib
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from tensorwire.testing.keys import DevKey, dev_key

__all__ = ["SignedClient"]

BASE_URL = "http://miner.test"


class SignedClient:
    """Signs and sends requests to one in-process app."""

    def __init__(
        self,
        app: Any,
        *,
        receiver_ss58: str,
        key: DevKey | str = "alice",
        clock_ns: Callable[[], int] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.key = dev_key(key) if isinstance(key, str) else key
        self.receiver_ss58 = receiver_ss58
        self._clock_ns = clock_ns
        self._signer = self.key.signer(clock_ns=clock_ns)
        self._app = app
        self.http = (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
            if client is None
            else client
        )

    def as_key(self, key: DevKey | str) -> SignedClient:
        """The same client (same connection) signing as another key."""
        return SignedClient(
            self._app,
            receiver_ss58=self.receiver_ss58,
            key=key,
            clock_ns=self._clock_ns,
            client=self.http,
        )

    def sign(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        receiver_ss58: str | None = None,
    ) -> dict[str, str]:
        """btauth/1 headers for ``method path`` with ``body``, as httpx will send it."""
        target = httpx.URL(BASE_URL + path).raw_path.decode("ascii")
        return self._signer.sign(
            method=method,
            target=target,
            body=body,
            receiver_ss58=self.receiver_ss58
            if receiver_ss58 is None
            else receiver_ss58,
        )

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        content: bytes = b"",
        headers: Mapping[str, str] | None = None,
        receiver_ss58: str | None = None,
    ) -> httpx.Response:
        """Sign and send one request. ``headers`` are added after signing."""
        body = jsonlib.dumps(json).encode() if json is not None else content
        signed = self.sign(method, path, body, receiver_ss58=receiver_ss58)
        if json is not None:
            signed["content-type"] = "application/json"
        signed.update(headers or {})
        return await self.http.request(method, path, content=body, headers=signed)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        """Signed ``POST``."""
        return await self.request("POST", path, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        """Signed ``GET`` (empty body)."""
        return await self.request("GET", path, **kwargs)

    async def send_raw(
        self, method: str, path: str, *, content: bytes, headers: Mapping[str, str]
    ) -> httpx.Response:
        """Send exactly ``content`` and ``headers`` (for replays and tampering)."""
        return await self.http.request(
            method, path, content=content, headers=dict(headers)
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self.http.aclose()
