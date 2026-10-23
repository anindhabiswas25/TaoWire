"""v10-shaped ``StreamingSynapse`` over the kit's streaming (spec 10b.2.1, 9.2).

A drop-in for ``bittensor.StreamingSynapse`` (v10) in template-style code::

    from tensorwire.compat import StreamingSynapse

    class StreamPrompting(StreamingSynapse):
        messages: list[str]
        completion: str = ""

        async def process_streaming_response(self, response):
            async for chunk in response.content.iter_any():   # bytes, as in v10
                self.completion += chunk.decode()
                yield chunk

        def extract_response_json(self, response) -> dict: ...
        def deserialize(self) -> str:
            return self.completion

Miner side, ``forward`` returns ``synapse.create_streaming_response(streamer)``
where ``streamer(send)`` sends ASGI body frames, exactly as in v10;
``compat.Axon`` serves it as a kit streaming route (every frame becomes one
chunk; the kit signs the stream with a ``tw-end`` trailer). Validator side,
``compat.Dendrite(..., streaming=True)`` returns one async generator per
axon that yields what ``process_streaming_response`` yields and then the
final ``deserialize()`` value or Synapse.

**Unverified until the end.** The bytes ``process_streaming_response`` reads
have not been verified yet. The final item is the filled Synapse only when
the trailer verified; otherwise it is a fresh copy of the request (none of
the streamed values) with ``dendrite.status_code`` set (408 timeout, 500 bad
signature, ...). Score from the final item.

Streaming works TensorWire to TensorWire only (D33): a v10 Dendrite gets the
v10-shaped ``tw.invalid_request`` answer from a streaming route.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, field_validator

from tensorwire.compat.synapse import Synapse

__all__ = [
    "BTStreamingResponse",
    "BTStreamingResponseModel",
    "StreamingSynapse",
    "TokenStreamer",
]

#: v10's token streamer: ``async def streamer(send)``.
TokenStreamer = Callable[
    [Callable[[Mapping[str, Any]], Awaitable[None]]], Awaitable[None]
]

#: Frames the miner buffers between the streamer and the kit's stream.
_QUEUE = 16


class BTStreamingResponseModel(BaseModel):
    """v10's wrapper of the token streamer (kept for code that names it)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    token_streamer: Callable[..., Awaitable[None]]


class BTStreamingResponse:
    """What ``create_streaming_response`` returns: the token streamer to run.

    In v10 this was a Starlette response; here ``compat.Axon`` runs the
    streamer and turns its frames into a signed kit stream.
    """

    def __init__(
        self,
        model: BTStreamingResponseModel,
        *,
        synapse: StreamingSynapse | None = None,
    ) -> None:
        self.token_streamer = model.token_streamer
        self.synapse = synapse


_Response = BTStreamingResponse  # the name inside StreamingSynapse is the ClassVar


class StreamingSynapse(Synapse, ABC):
    """The v10 ``StreamingSynapse`` shape; see the module docstring."""

    model_config = ConfigDict(validate_assignment=True)

    #: v10 code names it through the class (``self.BTStreamingResponse(...)``).
    BTStreamingResponse: ClassVar[type[_Response]]

    @abstractmethod
    def process_streaming_response(self, response: Any) -> AsyncIterator[Any]:
        """Read ``response.content`` (``iter_any()``, ...); yield what callers see."""

    @abstractmethod
    def extract_response_json(self, response: Any) -> dict[str, Any]:
        """Called after the stream; ``response`` has ``status`` and the headers."""

    def create_streaming_response(self, token_streamer: TokenStreamer) -> _Response:
        """Wrap ``token_streamer(send)`` as the answer of ``forward``."""
        return _Response(
            BTStreamingResponseModel(token_streamer=token_streamer), synapse=self
        )


StreamingSynapse.BTStreamingResponse = BTStreamingResponse


# ------------------------------------------------------------ miner side


class Frame(BaseModel):
    """One streamed body frame on the wire: ``{"b": "<base64>"}`` (an object, 9.2)."""

    b: bytes

    @field_validator("b", mode="before")
    @classmethod
    def _decode(cls, value: Any) -> bytes:
        if not isinstance(value, str):
            raise ValueError("b must be base64 text")
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("b is not valid base64") from None


async def frames(streamer: TokenStreamer) -> AsyncIterator[dict[str, str]]:
    """Run a v10 token streamer; yield each body frame as a kit chunk.

    The streamer runs as a task feeding a bounded queue, so a slow reader
    slows it down. Its exception is raised to the kit (which ends the stream
    without a trailer); closing this generator cancels the streamer.
    """
    queue: asyncio.Queue[bytes | BaseException | None] = asyncio.Queue(_QUEUE)

    async def send(message: Mapping[str, Any]) -> None:
        if message.get("type") == "http.response.body" and message.get("body"):
            await queue.put(bytes(message["body"]))

    closing = False

    async def run() -> None:
        try:
            await streamer(send)
        except Exception as exc:  # noqa: BLE001 - handed to the kit, which logs it
            await queue.put(exc)
        except BaseException:
            if closing:
                raise  # our own cancel (the stream ended): nobody is reading
            # e.g. a CancelledError from a task the streamer awaited: end now,
            # do not leave the kit waiting for the idle limit.
            await queue.put(RuntimeError("the token streamer was cancelled"))
        else:
            await queue.put(None)

    task = asyncio.create_task(run())
    try:
        while (item := await queue.get()) is not None:
            if isinstance(item, BaseException):
                raise item
            yield {"b": base64.b64encode(item).decode("ascii")}
    finally:
        closing = True
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


# ------------------------------------------------------------ validator side


class StreamContent:
    """``response.content`` as v10 user code reads it (aiohttp's ``StreamReader``)."""

    def __init__(self, source: AsyncIterator[bytes]) -> None:
        self._source = source

    async def iter_any(self) -> AsyncIterator[bytes]:
        """Each piece of bytes as it arrives."""
        async for piece in self._source:
            yield piece

    async def iter_chunked(self, n: int) -> AsyncIterator[bytes]:
        """Pieces of at most ``n`` bytes."""
        if n < 1:
            raise ValueError("n must be at least 1")
        async for piece in self._source:
            for i in range(0, len(piece), n):
                yield piece[i : i + n]

    async def read(self) -> bytes:
        """Everything left, at once."""
        return b"".join([piece async for piece in self._source])


class StreamResponse:
    """The ``response`` that ``process_streaming_response`` and co. receive.

    ``status`` and ``headers`` as aiohttp has them; ``_raw_headers`` (read by
    the template's ``extract_response_json``) holds ``name`` and ``timeout``.
    """

    def __init__(
        self, source: AsyncIterator[bytes], *, name: str, timeout: float
    ) -> None:
        self.content = StreamContent(source)
        self.status = 200
        self.headers = {
            "content-type": "text/event-stream",
            "name": name,
            "timeout": str(timeout),
        }
        self._raw_headers = tuple(
            (k.encode(), v.encode()) for k, v in self.headers.items()
        )
