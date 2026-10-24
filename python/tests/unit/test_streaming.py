"""Unit tests for the shared streaming pieces (spec 9.2, 11.7 S1, 12.1)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from taowire.extensions import streaming as sse

VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors"
DIGEST = "ab" * 32


def test_digest_matches_the_s1_vector() -> None:
    vectors = json.loads((VECTORS / "twresp.json").read_text())["vectors"]
    s1 = next(v for v in vectors if v["id"] == "S1")
    digest = sse.StreamDigest()
    for chunk in s1["inputs"]["chunks_base64"]:
        digest.update(base64.b64decode(chunk))
    assert digest.count == s1["expected"]["count"] == 3
    assert digest.hexdigest() == s1["expected"]["digest"]


def test_empty_stream_digest() -> None:
    digest = sse.StreamDigest()
    assert digest.count == 0
    assert digest.hexdigest() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_event_framing() -> None:
    assert sse.encode_event("chunk", b'{"a":1}') == b'event: chunk\ndata: {"a":1}\n\n'
    for name, data in (("a\nb", b"{}"), ("chunk", b"{\n}"), ("chunk", b"\r")):
        with pytest.raises(ValueError, match="line breaks"):
            sse.encode_event(name, data)


class Token(BaseModel):
    token: str


@pytest.mark.parametrize(
    ("item", "data"),
    [
        (Token(token="hé"), '{"token":"hé"}'.encode()),
        ({"a": [1, 2]}, b'{"a":[1,2]}'),
        ([1, "x"], b'[1,"x"]'),
        (b' {"raw": true}', b' {"raw": true}'),
    ],
)
def test_encode_chunk(item: object, data: bytes) -> None:
    assert sse.encode_chunk(item) == data


@pytest.mark.parametrize(
    "item",
    [
        1,
        "text",
        None,
        b"12",
        b'"s"',
        b"{bad",
        b'{"a":\n1}',
        {"x": float("nan")},
        {"x": object()},
        object(),
    ],
)
def test_encode_chunk_refuses(item: object) -> None:
    with pytest.raises(sse.ChunkError):
        sse.encode_chunk(item)


@pytest.mark.parametrize(
    "data", [b"1", b"null", b'"s"', b"NaN", b'{"a":NaN}', b"\xff", b"{", b"[" * 100_000]
)
def test_decode_chunk_refuses(data: bytes) -> None:
    with pytest.raises(sse.ChunkError):
        sse.decode_chunk(data)


def _nested(depth: int) -> bytes:
    return b"[" * depth + b"]" * depth


def test_chunk_depth_limit_is_128_both_ways() -> None:
    # D43: [] is depth 1; arrays and objects count together.
    assert sse.MAX_CHUNK_DEPTH == 128
    assert sse.decode_chunk(_nested(128)) is not None
    mixed = b'{"a":' * 64 + b"[" * 64 + b"]" * 64 + b"}" * 64
    assert sse.decode_chunk(mixed) is not None
    assert sse.encode_chunk(_nested(128)) == _nested(128)
    for deep in (_nested(129), b'{"a":' * 65 + b"[" * 64 + b"]" * 64 + b"}" * 65):
        with pytest.raises(sse.ChunkError, match="too deeply"):
            sse.decode_chunk(deep)
        with pytest.raises(sse.ChunkError, match="too deeply"):
            sse.encode_chunk(deep)
        with pytest.raises(sse.ChunkError, match="too deeply"):
            sse.encode_chunk(json.loads(deep))


class Deep(BaseModel):
    child: Deep | None = None


def test_encode_chunk_refuses_deep_values_without_recursing() -> None:
    value: list[Any] = []
    inner = value
    for _ in range(100_000):  # far past the interpreter's recursion limit
        inner.append([])
        inner = inner[0]
    with pytest.raises(sse.ChunkError, match="too deeply"):
        sse.encode_chunk(value)
    loop: list[Any] = []
    loop.append(loop)
    with pytest.raises(sse.ChunkError):
        sse.encode_chunk(loop)
    model = Deep()
    for _ in range(128):  # 129 objects: one level too deep
        model = Deep(child=model)
    with pytest.raises(sse.ChunkError, match="too deeply"):
        sse.encode_chunk(model)
    assert sse.encode_chunk(Deep(child=Deep())) == b'{"child":{"child":null}}'


def test_trailer_round_trip() -> None:
    trailer = sse.Trailer(digest=DIGEST, count=3, signature="0x" + "1" * 128)
    assert sse.parse_trailer(sse.encode_trailer(trailer)) == trailer
    unsigned = sse.Trailer(digest=DIGEST, count=0, signature=None)
    assert sse.encode_trailer(unsigned) == f'{{"digest":"{DIGEST}","count":0}}'.encode()
    assert sse.parse_trailer(sse.encode_trailer(unsigned)) == unsigned


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"[]",
        b"\xff",
        b'{"digest": "%s"}' % DIGEST.encode(),
        b'{"count": 1}',
        b'{"digest": "%s", "count": 1, "extra": 1}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 1, "count": 2}' % DIGEST.encode(),
        b'{"digest": "%s", "count": -1}' % DIGEST.encode(),
        b'{"digest": "%s", "count": true}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 1.0}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 1}' % DIGEST.upper().encode(),
        b'{"digest": "abc", "count": 1}',
        b'{"digest": "%s", "count": 1, "signature": 5}' % DIGEST.encode(),
        b'{"digest": "%s", "count": NaN}' % DIGEST.encode(),
        # D43: a plain non-negative integer literal that fits a u64 ...
        b'{"digest": "%s", "count": -0}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 1e2}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 1E0}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 0.5}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 18446744073709551616}' % DIGEST.encode(),
        b'{"digest": "%s", "count": %s}' % (DIGEST.encode(), b"9" * 5000),
        b'{"digest": "%s", "count": 01}' % DIGEST.encode(),
        # ... and no lone surrogate escape in any string
        b'{"digest": "%s", "count": 1, "signature": "0x\\ud800"}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 1, "signature": "\\udfff0x"}' % DIGEST.encode(),
        b'{"digest": "%s", "count": 1, "\\ud800": "x"}' % DIGEST.encode(),
    ],
)
def test_parse_trailer_refuses(data: bytes) -> None:
    with pytest.raises(sse.TrailerError):
        sse.parse_trailer(data)


def test_parse_trailer_count_edges_and_surrogate_pairs() -> None:
    top = b'{"digest": "%s", "count": 18446744073709551615}' % DIGEST.encode()
    assert sse.parse_trailer(top).count == 2**64 - 1
    zero = b'{"digest": "%s", "count": 0}' % DIGEST.encode()
    assert sse.parse_trailer(zero).count == 0
    # A valid escaped pair is one code point, not a lone surrogate.
    pair = b'{"digest": "%s", "count": 1, "signature": "\\ud83d\\ude00"}'
    assert sse.parse_trailer(pair % DIGEST.encode()).signature == "\U0001f600"


def test_limits_defaults_and_ranges() -> None:
    limits = sse.StreamLimits()
    assert (limits.max_s, limits.max_bytes, limits.idle_s) == (60.0, 4194304, 10.0)
    assert limits.override(max_s=5).max_s == 5
    assert limits.override(idle_s=2).max_bytes == limits.max_bytes
    for bad in (
        {"max_s": 0.5},
        {"max_s": 601},
        {"max_bytes": 1023},
        {"max_bytes": 64 * 1024 * 1024 + 1},
        {"idle_s": 121},
        {"idle_s": float("nan")},
        {"max_bytes": 2048.5},
        {"max_s": True},
    ):
        with pytest.raises(ValueError, match="must be"):
            sse.StreamLimits(**bad)  # type: ignore[arg-type]


def test_parser_dispatch_rules() -> None:
    parser = sse.SSEParser()
    raw = (
        b": keep-alive\n"
        b"event: chunk\ndata: a\ndata: b\n\n"  # multi-line data joined with LF
        b"event: x\n\n"  # no data: not dispatched
        b"data\n\n"  # field without a colon: empty data
        b"event:\ndata: y\n\n"  # empty type: "message"
        b"event: tw-end\ndata: partial"  # incomplete at the end: dropped
    )
    assert parser.feed(raw) + parser.finish() == [
        sse.SSEEvent("chunk", b"a\nb"),
        sse.SSEEvent("message", b""),
        sse.SSEEvent("message", b"y"),
    ]


def test_bom_only_at_the_start() -> None:
    parser = sse.SSEParser()
    assert parser.feed(b"\xef\xbb") == []
    assert parser.feed(b"\xbfdata: 1\n\n\xef\xbb\xbfdata: 2\n\n") == [
        sse.SSEEvent("message", b"1")
    ]  # the second BOM is part of a field name, not data


def test_the_trailer_reserve_covers_the_largest_trailer() -> None:
    largest = sse.encode_event(
        sse.EVENT_END,
        sse.encode_trailer(
            sse.Trailer("f" * 64, count=2**64 - 1, signature="0x" + "f" * 128)
        ),
    )
    assert len(largest) <= sse.TRAILER_RESERVE
    assert sse.TRAILER_RESERVE > 256  # the first guess was too small (review)
