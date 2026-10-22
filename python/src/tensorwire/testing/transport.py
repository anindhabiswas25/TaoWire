"""An httpx transport that routes requests to in-process ASGI apps by ``host:port``.

Lets a :class:`~tensorwire.validator.client.ValidatorClient` talk to several
in-process miners at the addresses published on a ``FakeChain``, with no
network::

    transport = AppRouter({"44.0.0.1:8091": miner_a.app, "44.0.0.2:8091": miner_b.app})
    client = ValidatorClient(signer, transport=transport)

A request to an address with no app fails like a refused connection
(``httpx.ConnectError``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

__all__ = ["AppRouter"]


class AppRouter(httpx.AsyncBaseTransport):
    """Dispatches each request to the ASGI app registered for its ``host:port``."""

    def __init__(self, apps: Mapping[str, Any] | None = None) -> None:
        self._transports: dict[str, httpx.ASGITransport] = {}
        for address, app in (apps or {}).items():
            self.add(address, app)

    def add(self, address: str, app: Any) -> None:
        """Serve ``app`` at ``address`` (``"ip:port"`` or ``"[v6]:port"``)."""
        self._transports[address] = httpx.ASGITransport(app=app)

    def remove(self, address: str) -> None:
        """Stop serving ``address`` (later requests fail to connect)."""
        self._transports.pop(address, None)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Route ``request`` by its URL's host and port."""
        host = request.url.host
        if ":" in host:
            host = f"[{host}]"
        address = f"{host}:{request.url.port}"
        transport = self._transports.get(address)
        if transport is None:
            raise httpx.ConnectError(f"connection refused: {address}", request=request)
        return await transport.handle_async_request(request)

    async def aclose(self) -> None:
        """Close every app transport."""
        for transport in self._transports.values():
            await transport.aclose()
