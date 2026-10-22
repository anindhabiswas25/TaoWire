"""limits/body.py: Content-Length rejection and mid-stream cap (13.2)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tensorwire.errors import PayloadTooLarge, RateLimited
from tensorwire.limits.body import BodySizeLimit, Message, Receive, Scope, Send, send_error


def http_scope(headers: list[tuple[bytes, bytes]] | None = None, **extra: Any) -> Scope:
    return {"type": "http", "method": "POST", "path": "/x", "headers": headers or [], **extra}


class Client:
    """Feeds body chunks to an ASGI app and records what it sends."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.sent: list[Message] = []

    async def receive(self) -> Message:
        if not self.chunks:
            return {"type": "http.disconnect"}
        chunk = self.chunks.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(self.chunks)}

    async def send(self, message: Message) -> None:
        self.sent.append(message)

    @property
    def status(self) -> int:
        return int(next(m for m in self.sent if m["type"] == "http.response.start")["status"])

    @property
    def json(self) -> Any:
        return json.loads(
            b"".join(m.get("body", b"") for m in self.sent if m["type"] == "http.response.body")
        )

    def header(self, name: bytes) -> bytes | None:
        start = next(m for m in self.sent if m["type"] == "http.response.start")
        return dict(start["headers"]).get(name)


class EchoApp:
    """Reads the whole body, answers 200 with its length."""

    def __init__(self) -> None:
        self.called = False
        self.body = b""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.called = True
        more = True
        while more:
            msg = await receive()
            self.body += msg.get("body", b"")
            more = msg.get("more_body", False)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": str(len(self.body)).encode()})


async def test_content_length_over_limit_rejected_without_reading() -> None:
    app = EchoApp()
    client = Client([b"x" * 11])
    await BodySizeLimit(app, 10)(
        http_scope([(b"content-length", b"11")]), client.receive, client.send
    )
    assert not app.called
    assert client.status == 413
    assert client.json["error"]["code"] == "tw.payload_too_large"
    assert client.chunks == [b"x" * 11]  # body never consumed


async def test_content_length_at_limit_passes() -> None:
    app = EchoApp()
    client = Client([b"x" * 10])
    await BodySizeLimit(app, 10)(
        http_scope([(b"Content-Length", b"10")]), client.receive, client.send
    )
    assert client.status == 200
    assert app.body == b"x" * 10


async def test_chunked_body_exceeding_cap_mid_stream() -> None:
    app = EchoApp()
    client = Client([b"x" * 4, b"x" * 4, b"x" * 4, b"x" * 4])
    await BodySizeLimit(app, 10)(http_scope(), client.receive, client.send)
    assert client.status == 413
    assert len([m for m in client.sent if m["type"] == "http.response.start"]) == 1
    assert app.body == b"x" * 8  # the app never saw the chunk that crossed the limit
    assert client.chunks == [b"x" * 4]  # stopped reading right there


async def test_body_longer_than_declared_is_capped() -> None:
    app = EchoApp()
    client = Client([b"x" * 6, b"x" * 6])
    await BodySizeLimit(app, 10)(
        http_scope([(b"content-length", b"5")]), client.receive, client.send
    )
    assert client.status == 413


async def test_app_output_after_rejection_is_dropped() -> None:
    """Frameworks that turn the exception into a 500 cannot overwrite the 413."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await receive()
        except PayloadTooLarge:
            await send({"type": "http.response.start", "status": 500, "headers": []})
            await send({"type": "http.response.body", "body": b"boom"})
            raise

    client = Client([b"x" * 11])
    await BodySizeLimit(app, 10)(http_scope(), client.receive, client.send)
    assert client.status == 413
    assert len(client.sent) == 2


async def test_overflow_after_response_started_reraises() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await receive()

    client = Client([b"x" * 11])
    with pytest.raises(PayloadTooLarge):
        await BodySizeLimit(app, 10)(http_scope(), client.receive, client.send)
    assert client.status == 200


async def test_other_app_errors_propagate() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("bug")

    client = Client([b""])
    with pytest.raises(RuntimeError, match="bug"):
        await BodySizeLimit(app, 10)(http_scope(), client.receive, client.send)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"abc")],
        [(b"content-length", b"-1")],
        [(b"content-length", b"5"), (b"content-length", b"500")],
    ],
)
async def test_unusable_content_length_falls_back_to_streaming_cap(
    headers: list[tuple[bytes, bytes]],
) -> None:
    app = EchoApp()
    client = Client([b"x" * 3])
    await BodySizeLimit(app, 10)(http_scope(headers), client.receive, client.send)
    assert client.status == 200


async def test_duplicate_identical_content_length_is_honoured() -> None:
    client = Client([b""])
    headers = [(b"content-length", b"50"), (b"content-length", b"50")]
    await BodySizeLimit(EchoApp(), 10)(http_scope(headers), client.receive, client.send)
    assert client.status == 413


async def test_non_http_scopes_pass_through() -> None:
    seen: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])

    client = Client([])
    await BodySizeLimit(app, 1)({"type": "lifespan"}, client.receive, client.send)
    assert seen == ["lifespan"]


async def test_request_id_from_scope_state() -> None:
    client = Client([b""])
    scope = http_scope([(b"content-length", b"99")], state={"request_id": "01JREQ"})
    await BodySizeLimit(EchoApp(), 10)(scope, client.receive, client.send)
    assert client.json["error"]["request_id"] == "01JREQ"
    assert client.header(b"x-tw-request-id") == b"01JREQ"


@pytest.mark.parametrize("state", [None, "nope", {"request_id": 5}])
async def test_request_id_absent(state: object) -> None:
    client = Client([b""])
    await BodySizeLimit(EchoApp(), 10)(
        http_scope([(b"content-length", b"99")], state=state), client.receive, client.send
    )
    assert client.json["error"]["request_id"] is None
    assert client.header(b"x-tw-request-id") is None


def test_max_bytes_must_be_positive() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        BodySizeLimit(EchoApp(), 0)


async def test_send_error_includes_extra_headers() -> None:
    client = Client([])
    await send_error(client.send, RateLimited(retry_after_s=2.5, layer="ip"))
    assert client.status == 429
    assert client.header(b"retry-after") == b"3"
    assert client.header(b"content-type") == b"application/json"
    assert int(client.header(b"content-length") or 0) == len(client.sent[1]["body"])


async def test_disconnect_messages_pass_through() -> None:
    got: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        got.append((await receive())["type"])
        got.append((await receive())["type"])

    client = Client([b"abc"])
    await BodySizeLimit(app, 10)(http_scope(), client.receive, client.send)
    assert got == ["http.request", "http.disconnect"]
