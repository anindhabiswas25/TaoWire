"""The subnet's wire contract: one route, one request, one response.

Validators send ``{"text": ..., "op": "upper" | "reverse" | "sha256"}`` to
``POST /v1/transform``; miners answer ``{"result": ...}``. The same request to
``POST /v1/transform/stream`` is answered as a stream (spec 9.2) of
``{"i": n, "piece": ...}`` chunks: the result in pieces of 32 characters.
Everything is deterministic, so a validator can check every answer exactly.
"""

from __future__ import annotations

import hashlib
import random
import string
from typing import Literal

from pydantic import BaseModel, Field

ROUTE = "/v1/transform"
STREAM_ROUTE = "/v1/transform/stream"
#: Characters per streamed piece.
PIECE_CHARS = 32
OPS: tuple[str, ...] = ("upper", "reverse", "sha256")
#: ASCII only, so miners in any language produce byte-identical results.
ALPHABET = string.ascii_letters + string.digits + " "


class TransformRequest(BaseModel):
    """What the validator asks."""

    text: str = Field(min_length=1, max_length=4096)
    op: Literal["upper", "reverse", "sha256"]


class TransformResponse(BaseModel):
    """What the miner answers."""

    result: str


class TransformPiece(BaseModel):
    """One streamed chunk: piece ``i`` of the result."""

    i: int
    piece: str


def expected(req: TransformRequest) -> str:
    """The one correct answer."""
    if req.op == "upper":
        return req.text.upper()
    if req.op == "reverse":
        return req.text[::-1]
    return hashlib.sha256(req.text.encode()).hexdigest()


def pieces(req: TransformRequest) -> list[TransformPiece]:
    """The streamed answer: the expected result in pieces of ``PIECE_CHARS``."""
    result = expected(req)
    return [
        TransformPiece(i=n, piece=result[start : start + PIECE_CHARS])
        for n, start in enumerate(range(0, len(result), PIECE_CHARS))
    ]


def random_request(rng: random.Random) -> TransformRequest:
    """A task: 64-512 ASCII characters and a random operation."""
    length = rng.randint(64, 512)
    text = "".join(rng.choice(ALPHABET) for _ in range(length))
    return TransformRequest(text=text, op=rng.choice(OPS))  # type: ignore[arg-type]
