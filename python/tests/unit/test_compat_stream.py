"""``compat.stream`` pieces on their own (spec 10b.2.1)."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from typing import Any

import pytest
from pydantic import ValidationError

from taowire.compat.stream import Frame, StreamContent, StreamResponse, frames

pytestmark = pytest.mark.asyncio


async def test_frames_carry_the_exact_bytes() -> None:
    async def streamer(send: Any) -> None:
        await send({"type": "http.response.start", "status": 200})  # ignored
        await send({"type": "http.response.body", "body": b"a\xffb", "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": True})
        await send({"type": "http.response.body", "body": b"c", "more_body": False})

    out = [f async for f in frames(streamer)]
    assert out == [{"b": base64.b64encode(b"a\xffb").decode()}, {"b": "Yw=="}]
    assert [Frame.model_validate(f).b for f in out] == [b"a\xffb", b"c"]


async def test_a_streamer_error_reaches_the_kit() -> None:
    async def streamer(send: Any) -> None:
        await send({"type": "http.response.body", "body": b"x"})
        raise RuntimeError("model crashed")

    gen = frames(streamer)
    assert await anext(gen) == {"b": "eA=="}
    with pytest.raises(RuntimeError, match="model crashed"):
        await anext(gen)


async def test_closing_the_frames_cancels_the_streamer() -> None:
    cancelled = asyncio.Event()

    async def streamer(send: Any) -> None:
        try:
            while True:
                await send({"type": "http.response.body", "body": b"x"})
        except asyncio.CancelledError:
            cancelled.set()
            raise

    gen = frames(streamer)
    await anext(gen)
    await gen.aclose()
    await asyncio.wait_for(cancelled.wait(), 1)


@pytest.mark.parametrize("value", [5, "not base64!", "YQ"])
async def test_bad_frames_are_refused(value: Any) -> None:
    with pytest.raises(ValidationError):
        Frame.model_validate({"b": value})


async def pieces(*items: bytes) -> AsyncIterator[bytes]:
    for item in items:
        yield item


async def test_content_readers() -> None:
    chunked = StreamContent(pieces(b"abcde", b"fg"))
    assert [c async for c in chunked.iter_chunked(2)] == [b"ab", b"cd", b"e", b"fg"]
    assert await StreamContent(pieces(b"ab", b"c")).read() == b"abc"
    with pytest.raises(ValueError, match="at least 1"):
        await anext(StreamContent(pieces(b"a")).iter_chunked(0))


async def test_the_response_has_the_headers_template_code_reads() -> None:
    response = StreamResponse(pieces(), name="StreamPrompting", timeout=12.0)
    headers = {k.decode(): v.decode() for k, v in response.__dict__["_raw_headers"]}
    assert headers["name"] == "StreamPrompting"
    assert float(headers["timeout"]) == 12.0
    assert response.status == 200


async def test_a_cancelled_inner_task_ends_the_frames_at_once() -> None:
    async def streamer(send: Any) -> None:
        await send({"type": "http.response.body", "body": b"x"})
        inner = asyncio.create_task(asyncio.sleep(10))
        inner.cancel()
        await inner  # CancelledError escapes the streamer (not our cancel)

    gen = frames(streamer)
    assert await anext(gen) == {"b": "eA=="}
    with pytest.raises(RuntimeError, match="cancelled"):
        await asyncio.wait_for(anext(gen), 1)  # no wait for the idle limit
