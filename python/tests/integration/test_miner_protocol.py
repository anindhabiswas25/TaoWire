"""miner/protocol.py: httptools with a request-read deadline and header limits
(spec 8.6.1, 13.6), over real sockets."""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import AsyncIterator, MutableMapping
from typing import Any

import anyio
import pytest
import uvicorn
from uvicorn.server import ServerState

from tensorwire.miner.app import NoSignalServer
from tensorwire.miner.protocol import (
    MAX_HEADER_BYTES,
    MAX_HEADERS,
    GuardedHttpToolsProtocol,
    guarded_protocol,
)

READ_TIMEOUT_S = 0.5


async def app(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
    """Echoes the body length; ``/slow`` takes longer than the read deadline."""
    assert scope["type"] == "http"
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break
    if scope["path"] == "/slow":
        await asyncio.sleep(READ_TIMEOUT_S * 3)
    content = str(len(body)).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", str(len(content)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": content})


@pytest.fixture
async def port() -> AsyncIterator[int]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = NoSignalServer(
        uvicorn.Config(
            app,
            lifespan="off",
            log_config=None,
            access_log=False,
            http=guarded_protocol(READ_TIMEOUT_S),
            timeout_keep_alive=5,
        )
    )
    task = asyncio.get_running_loop().create_task(server.serve([sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    yield sock.getsockname()[1]
    server.should_exit = True
    await task
    sock.close()


async def exchange(
    port: int, *chunks: bytes, pause: float = 0.0, read_s: float = 3.0
) -> tuple[bytes, float]:
    """Send ``chunks`` (``pause`` apart); return everything read until the
    server closes (or ``read_s`` passes), and the seconds it took."""
    started = time.monotonic()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        for chunk in chunks:
            writer.write(chunk)
            await writer.drain()
            if pause:
                await asyncio.sleep(pause)
        data = b""
        with anyio.move_on_after(read_s):  # asyncio.timeout is 3.11+
            while chunk := await reader.read(65536):
                data += chunk
    except ConnectionError:
        data = b""
    finally:
        writer.close()
    return data, time.monotonic() - started


def post(path: str = "/", body: bytes = b"abc", **headers: str) -> bytes:
    head = [f"POST {path} HTTP/1.1", "Host: m", f"Content-Length: {len(body)}"]
    head += [f"{k.replace('_', '-')}: {v}" for k, v in headers.items()]
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


async def test_requests_keep_alive_and_pipelining(port: int) -> None:
    data, _ = await exchange(port, post() + post(body=b"12345"), read_s=1)
    assert data.count(b"HTTP/1.1 200") == 2
    assert data.endswith(b"5")
    data, _ = await exchange(port, post(), post(body=b"xy"), pause=0.2, read_s=1)
    assert data.count(b"HTTP/1.1 200") == 2


async def test_a_slow_handler_is_not_cut_off(port: int) -> None:
    data, took = await exchange(port, post("/slow"), read_s=5)
    assert data.startswith(b"HTTP/1.1 200")
    assert took >= READ_TIMEOUT_S * 3


@pytest.mark.parametrize(
    "request_bytes",
    [
        post(X_Pad="a" * (MAX_HEADER_BYTES + 1)),  # one header, one read
        post(**{f"X_H{i}": "v" for i in range(MAX_HEADERS + 1)}),  # too many fields
        post("/" + "a" * (MAX_HEADER_BYTES + 1)),  # request line
        post(**{f"X_H{i}": "v" * 200 for i in range(90)}),  # many medium fields
    ],
    ids=["one-huge-header", "too-many-headers", "huge-url", "many-medium-headers"],
)
async def test_oversized_heads_get_400_and_close(
    port: int, request_bytes: bytes
) -> None:
    data, took = await exchange(port, request_bytes)
    assert data.startswith(b"HTTP/1.1 400"), data[:60]
    assert b"connection: close" in data.lower()
    assert took < 2  # closed by the server, not by our read timeout


async def test_a_head_just_under_the_limit_is_served(port: int) -> None:
    pad = MAX_HEADER_BYTES - 200
    data, _ = await exchange(port, post(X_Pad="a" * pad), read_s=1)
    assert data.startswith(b"HTTP/1.1 200")


async def test_an_incomplete_header_value_is_bounded(port: int) -> None:
    head = b"POST / HTTP/1.1\r\nHost: m\r\nX-Pad: "
    data, took = await exchange(
        port, head, *[b"a" * 8192] * 4, pause=0.01
    )  # never ends the value
    assert data.startswith(b"HTTP/1.1 400"), data[:60]
    assert took < READ_TIMEOUT_S  # refused on size, before the deadline


@pytest.mark.parametrize(
    ("chunks", "pause"),
    [
        ([b""], 0.0),  # connects and says nothing
        ([b"POST / HTTP/1.1\r\n", b"Host: m\r\n", b"X-A: 1\r\n", b"X-B: 2\r\n"], 0.2),
        (
            [b"POST / HTTP/1.1\r\nHost: m\r\nContent-Length: 10\r\n\r\n", b"1", b"2"],
            0.2,
        ),
    ],
    ids=["idle", "slow-headers", "slow-body"],
)
async def test_slow_requests_are_closed_at_the_deadline(
    port: int, chunks: list[bytes], pause: float
) -> None:
    data, took = await exchange(port, *chunks, pause=pause, read_s=5)
    assert data == b""
    assert READ_TIMEOUT_S * 0.8 <= took < READ_TIMEOUT_S + 1.5


async def test_deadline_restarts_for_each_kept_alive_request(port: int) -> None:
    # Three requests, each well within the deadline, over 1.5 deadlines in total.
    data, _ = await exchange(port, post(), post(), post(), pause=0.3, read_s=1)
    assert data.count(b"HTTP/1.1 200") == 3


@pytest.mark.parametrize(
    "smuggled",
    [
        b"POST / HTTP/1.1\r\nHost: m\r\nContent-Length: 3\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: m\r\nContent-Length: 3\r\n"
        b"Content-Length: 5\r\n\r\nabcde",
        b"POST / HTTP/1.1\r\nHost: m\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: m\r\nX-Bad\x00: v\r\nContent-Length: 0\r\n\r\n",
    ],
    ids=["cl-and-te", "two-content-lengths", "te-not-chunked-last", "nul-in-name"],
)
async def test_ambiguous_framing_is_refused(port: int, smuggled: bytes) -> None:
    data, _ = await exchange(port, smuggled)
    assert data.startswith(b"HTTP/1.1 400"), data[:80]


async def test_limits_must_be_positive() -> None:
    for bad in (
        {"read_timeout_s": 0},
        {"read_timeout_s": 1, "max_header_bytes": 0},
        {"read_timeout_s": 1, "max_headers": 0},
    ):
        with pytest.raises(ValueError, match="must be > 0"):
            GuardedHttpToolsProtocol(
                config=uvicorn.Config(app),
                server_state=ServerState(),
                app_state={},
                **bad,
            )
