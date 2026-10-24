"""Property tests for the streaming parser and encoding (spec 9.2, 13.3, D29).

The SSE parser reads untrusted bytes from miners. These tests check:

1. ``SSEParser`` never raises on arbitrary bytes fed in arbitrary pieces, and
   gives the same events as a whole-input reference parser written
   independently from the WHATWG rules.
2. Any split of a stream into pieces gives the same events (CRLF split across
   pieces included), whatever mix of CRLF / LF / CR ends the lines.
3. Comments, ``id`` / ``retry`` / unknown fields and unknown event names pass
   through without changing the events; a BOM at the start is ignored.
4. Encoded events round-trip; a long line in small pieces stays linear.
5. ``decode_chunk`` / ``parse_trailer`` raise only their own errors on any
   bytes; ``encode_chunk`` round-trips JSON objects and arrays and refuses
   everything else.
6. Chunk boundaries are unambiguous: no other split of the signed bytes into
   the same number of valid chunks exists (why chunks are objects/arrays).
7. D43: a chunk is accepted (both ways) exactly when it nests at most 128
   levels; ``tw-end`` ``count`` is accepted exactly when it is a plain
   non-negative integer literal that fits a u64; a lone surrogate escape in
   any trailer string is refused, an escaped pair is not.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from taowire.extensions import streaming as sse

BOM = b"\xef\xbb\xbf"
LINE_ENDS = [b"\r\n", b"\n", b"\r"]


def reference(raw: bytes) -> list[sse.SSEEvent]:
    """Whole-input WHATWG event-stream parsing (no incremental state)."""
    if raw.startswith(BOM):
        raw = raw[len(BOM) :]
    lines = re.split(rb"\r\n|\r|\n", raw)[:-1]  # the last piece has no line end
    events: list[sse.SSEEvent] = []
    name, data = "", None
    for line in lines:
        if line == b"":
            if data is not None:
                events.append(sse.SSEEvent(name or "message", b"\n".join(data)))
            name, data = "", None
            continue
        if line[:1] == b":":
            continue
        if b":" in line:
            field, value = line.split(b":", 1)
            if value[:1] == b" ":
                value = value[1:]
        else:
            field, value = line, b""
        if field == b"data":
            data = [*(data or []), value]
        elif field == b"event":
            name = value.decode("utf-8", errors="replace")
    return events


def parse_in_pieces(raw: bytes, cuts: list[int]) -> list[sse.SSEEvent]:
    parser = sse.SSEParser()
    events: list[sse.SSEEvent] = []
    last = 0
    for cut in sorted({c % (len(raw) + 1) for c in cuts}):
        events += parser.feed(raw[last:cut])
        last = cut
    events += parser.feed(raw[last:])
    return events + parser.finish()


# Bytes that look like SSE often enough to reach every branch.
sse_tokens = st.sampled_from(
    [
        b"event: chunk",
        b"event: tw-end",
        b"event:",
        b"data: {}",
        b"data:x",
        b"data",
        b": comment",
        b":",
        b"id: 7",
        b"retry: 10",
        b"foo: bar",
        b"\r\n",
        b"\n",
        b"\r",
        b" ",
        BOM,
        b"\xff\xfe",
        "☃".encode(),
    ]
)
sse_like = st.lists(st.one_of(sse_tokens, st.binary(max_size=8)), max_size=40).map(
    b"".join
)
cuts = st.lists(st.integers(min_value=0, max_value=10_000), max_size=12)


@settings(max_examples=400)
@given(raw=st.one_of(st.binary(max_size=512), sse_like), cuts=cuts)
def test_parser_never_raises_and_matches_the_reference(
    raw: bytes, cuts: list[int]
) -> None:
    assert parse_in_pieces(raw, cuts) == reference(raw)


ascii_value = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=20
)
event = st.tuples(st.sampled_from(["chunk", "tw-end", "message", "x"]), ascii_value)


@settings(max_examples=300)
@given(
    events=st.lists(event, max_size=8),
    ends=st.lists(st.sampled_from(LINE_ENDS), min_size=1, max_size=5),
    noise=st.lists(
        st.sampled_from([b": keep-alive", b"id: 1", b"retry: 5", b"x-unknown: 1"]),
        max_size=4,
    ),
    bom=st.booleans(),
    cuts=cuts,
)
def test_line_endings_noise_and_splits_do_not_change_events(
    events: list[tuple[str, str]],
    ends: list[bytes],
    noise: list[bytes],
    bom: bool,
    cuts: list[int],
) -> None:
    out = [BOM] if bom else []
    for i, (name, value) in enumerate(events):
        end = ends[i % len(ends)]
        lines = [*noise, b"event: " + name.encode(), b"data: " + value.encode()]
        out.append(b"".join(line + end for line in lines) + end)
    raw = b"".join(out)
    expected = [sse.SSEEvent(name, value.encode()) for name, value in events]
    assert parse_in_pieces(raw, cuts) == expected


@given(events=st.lists(event, max_size=10), cuts=cuts)
def test_encoded_events_round_trip(
    events: list[tuple[str, str]], cuts: list[int]
) -> None:
    raw = b"".join(sse.encode_event(n, v.encode()) for n, v in events)
    assert parse_in_pieces(raw, cuts) == [
        sse.SSEEvent(n, v.encode()) for n, v in events
    ]


def test_a_long_line_in_small_pieces_is_linear() -> None:
    parser = sse.SSEParser()
    started = time.perf_counter()
    parser.feed(b"event: chunk\ndata: ")
    for _ in range(4096):  # 4 MiB in 1 KiB pieces
        assert parser.feed(b"a" * 1024) == []
    (got,) = parser.feed(b"\n\n")
    assert len(got.data) == 4 * 1024 * 1024
    assert time.perf_counter() - started < 2.0  # quadratic rescanning takes minutes


def test_a_crlf_split_across_pieces_is_one_line_end() -> None:
    parser = sse.SSEParser()
    assert parser.feed(b"data: a\r") == []
    assert parser.feed(b"\n\r") == []
    assert parser.feed(b"\n") == [sse.SSEEvent("message", b"a")]


# ------------------------------------------------------------ chunks and trailer

json_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=8),
)
json_value = st.recursive(
    json_leaf,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(st.text(max_size=6), inner, max_size=4),
    ),
    max_leaves=12,
)
json_container = st.one_of(
    st.lists(json_value, max_size=4),
    st.dictionaries(st.text(max_size=6), json_value, max_size=4),
)


@settings(max_examples=300)
@given(
    raw=st.one_of(
        st.binary(max_size=64), json_value.map(lambda v: json.dumps(v).encode())
    )
)
def test_decode_chunk_and_parse_trailer_raise_only_their_errors(raw: bytes) -> None:
    try:
        value = sse.decode_chunk(raw)
    except sse.ChunkError:
        pass
    else:
        assert isinstance(value, (dict, list))
    try:
        trailer = sse.parse_trailer(raw)
    except sse.TrailerError:
        pass
    else:
        assert re.fullmatch("[0-9a-f]{64}", trailer.digest)


@given(value=json_container)
def test_encode_chunk_round_trips_objects_and_arrays(value: Any) -> None:
    data = sse.encode_chunk(value)
    assert b"\n" not in data
    assert b"\r" not in data
    assert sse.decode_chunk(data) == json.loads(json.dumps(value))
    assert sse.encode_chunk(data) == data  # bytes are sent as they are


@given(value=json_leaf)
def test_scalars_are_refused_both_ways(value: Any) -> None:
    raw = json.dumps(value).encode()
    for call in (sse.encode_chunk, sse.decode_chunk):
        try:
            call(raw)
        except sse.ChunkError:
            continue
        raise AssertionError(f"{call.__name__} accepted {raw!r}")


def _splits(raw: bytes, parts: int) -> list[list[bytes]]:
    if parts == 1:
        return [[raw]]
    out = []
    for i in range(1, len(raw)):
        out += [[raw[:i], *rest] for rest in _splits(raw[i:], parts - 1)]
    return out


@settings(max_examples=150)
@given(values=st.lists(json_container, min_size=2, max_size=3))
def test_no_other_split_of_the_signed_bytes_is_valid(values: list[Any]) -> None:
    chunks = [sse.encode_chunk(v) for v in values]
    joined = b"".join(chunks)
    if len(joined) > 120:
        return  # the enumeration is quadratic or cubic in the length
    for split in _splits(joined, len(chunks)):
        try:
            for part in split:
                sse.decode_chunk(part)
        except sse.ChunkError:
            continue
        assert split == chunks


# ---------------------------------------------------------------- D43


@st.composite
def nested_chunk(draw: st.DrawFn) -> tuple[int, bytes]:
    """A chunk of a random depth, each level an array or an object."""
    depth = draw(st.integers(min_value=1, max_value=300))
    kinds = draw(st.lists(st.booleans(), min_size=depth, max_size=depth))
    opens = b"".join(b'{"k":' if obj else b"[" for obj in kinds)
    closes = b"".join(b"}" if obj else b"]" for obj in reversed(kinds))
    # An object's value cannot be empty: the innermost object gets a 0.
    middle = b"0" if kinds[-1] else b""
    return depth, opens + middle + closes


@settings(max_examples=300)
@given(chunk=nested_chunk())
def test_chunk_depth_is_accepted_up_to_128_exactly(chunk: tuple[int, bytes]) -> None:
    depth, raw = chunk
    for call in (sse.decode_chunk, sse.encode_chunk):
        try:
            call(raw)
        except sse.ChunkError:
            assert depth > sse.MAX_CHUNK_DEPTH, (call.__name__, depth)
        else:
            assert depth <= sse.MAX_CHUNK_DEPTH, (call.__name__, depth)
    if depth <= sse.MAX_CHUNK_DEPTH:
        assert sse.encode_chunk(json.loads(raw)) == raw.replace(b" ", b"")


_DIGEST = "ab" * 32


def _trailer(count: str, signature: str = '"0x00"') -> bytes:
    return f'{{"digest":"{_DIGEST}","count":{count},"signature":{signature}}}'.encode()


@given(n=st.integers(min_value=-(2**70), max_value=2**70))
def test_count_accepts_exactly_the_u64_range(n: int) -> None:
    try:
        trailer = sse.parse_trailer(_trailer(str(n)))
    except sse.TrailerError:
        assert not 0 <= n <= 2**64 - 1
    else:
        assert 0 <= n <= 2**64 - 1
        assert trailer.count == n


@given(
    literal=st.one_of(
        st.just("-0"),
        st.integers(min_value=0, max_value=10**6).map(lambda n: f"{n}.0"),
        st.integers(min_value=0, max_value=10**6).map(lambda n: f"{n}e0"),
        st.integers(min_value=0, max_value=10**6).map(lambda n: f"{n}E+1"),
        st.floats(allow_nan=False, allow_infinity=False).map(repr),
    )
)
def test_count_refuses_sign_fraction_and_exponent(literal: str) -> None:
    try:
        sse.parse_trailer(_trailer(literal))
    except sse.TrailerError:
        return
    raise AssertionError(f"accepted count {literal}")


surrogate = st.integers(min_value=0xD800, max_value=0xDFFF)


@given(unit=surrogate, before=st.text(max_size=4), after=st.text(max_size=4))
def test_a_lone_surrogate_escape_is_refused(unit: int, before: str, after: str) -> None:
    text = json.dumps(before)[1:-1] + f"\\u{unit:04x}" + json.dumps(after)[1:-1]
    # st.text draws no surrogates and json.dumps escapes an astral character
    # as a high + low pair, so the inserted unit can never complete a pair.
    try:
        sse.parse_trailer(_trailer("1", f'"{text}"'))
    except sse.TrailerError:
        return
    raise AssertionError(f"accepted a lone surrogate {text!r}")


@given(char=st.characters(min_codepoint=0x10000, max_codepoint=0x10FFFF))
def test_an_escaped_surrogate_pair_is_accepted(char: str) -> None:
    escaped = json.dumps(char)  # ensure_ascii: an escaped UTF-16 pair
    assert escaped.count("\\u") == 2
    assert sse.parse_trailer(_trailer("1", escaped)).signature == char
