"""Request body size cap as a pure ASGI middleware (spec 8.6.1).

Installed outermost, so oversized requests are rejected before anything
expensive (signature verification) runs:

1. A declared ``Content-Length`` over the limit gets 413 at once; the body is
   never read.
2. Otherwise the body is counted as it streams in (chunked uploads, or a
   client that sends more than it declared). The moment the running total
   passes the limit, the client gets 413 and the app's ``receive()`` raises
   :class:`PayloadTooLarge`, so a handler never sees a truncated body.

Anything the app tries to send after the 413 is dropped, so frameworks that
turn exceptions into 500 responses (Starlette's ``ServerErrorMiddleware``)
cannot overwrite it.

Error bodies use the kit format; the request ID is taken from
``scope["state"]["request_id"]`` when an outer middleware has set it, and the
error code is recorded in ``scope["state"]["tw_code"]`` for it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from tensorwire.errors import PayloadTooLarge, TWError

__all__ = ["BodySizeLimit", "send_error"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def _content_length(headers: list[tuple[bytes, bytes]]) -> int | None:
    """The declared length, or ``None`` if absent or not a plain decimal.

    Conflicting duplicate headers count as absent here; the streaming cap
    still applies (and the miner's HTTP parser rejects them before they reach
    the app).
    """
    values = {v.strip() for k, v in headers if k.lower() == b"content-length"}
    if len(values) != 1:
        return None
    (value,) = values
    return int(value) if value.isdigit() else None


def _request_id(scope: Scope) -> str | None:
    state = scope.get("state")
    if isinstance(state, MutableMapping):
        rid = state.get("request_id")
        if isinstance(rid, str):
            return rid
    return None


def _record(scope: Scope | None, error: TWError) -> None:
    if scope is None:
        return
    state = scope.setdefault("state", {})
    if isinstance(state, MutableMapping):
        state["tw_code"] = error.code


async def send_error(
    send: Send,
    error: TWError,
    *,
    request_id: str | None = None,
    scope: Scope | None = None,
) -> None:
    """Send ``error`` as a complete kit-format JSON response.

    With ``scope``, the code is also recorded in ``scope["state"]["tw_code"]``.
    """
    _record(scope, error)
    body = error.response_body(request_id)
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        *(
            (k.lower().encode(), v.encode())
            for k, v in error.response_headers().items()
        ),
    ]
    if request_id is not None:
        headers.append((b"x-tw-request-id", request_id.encode()))
    await send(
        {"type": "http.response.start", "status": error.http_status, "headers": headers}
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class BodySizeLimit:
    """Reject HTTP requests whose body is larger than ``max_bytes`` with 413."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = _request_id(scope)
        declared = _content_length(scope.get("headers", []))
        if declared is not None and declared > self.max_bytes:
            await send_error(
                send, PayloadTooLarge(), request_id=request_id, scope=scope
            )
            return

        received = 0
        response_started = False
        rejected = False

        async def limited_receive() -> Message:
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    if not response_started and not rejected:
                        rejected = True
                        await send_error(
                            send, PayloadTooLarge(), request_id=request_id, scope=scope
                        )
                    raise PayloadTooLarge()
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if rejected:
                return  # the 413 already went out
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except PayloadTooLarge:
            if not rejected:
                raise  # the app had already started its response; nothing safe to send
