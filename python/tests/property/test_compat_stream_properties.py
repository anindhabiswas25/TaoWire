"""Property tests for the compat stream frame parser (spec 10b.2.1, 13.3).

``compat.stream.Frame`` parses every chunk a (possibly hostile) miner sends to
a compat validator. It must accept exactly ``{"b": <canonical base64>}`` and
give back the exact bytes, and raise nothing but ``ValidationError``.
"""

from __future__ import annotations

import base64
import contextlib
import json
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from taowire.compat.stream import Frame

json_value = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=12)),
    lambda inner: st.one_of(
        st.lists(inner, max_size=3),
        st.dictionaries(st.text(max_size=4), inner, max_size=3),
    ),
    max_leaves=8,
)


@given(data=st.binary(max_size=256))
def test_frames_round_trip_exact_bytes(data: bytes) -> None:
    frame = {"b": base64.b64encode(data).decode("ascii")}
    assert Frame.model_validate(frame).b == data
    assert Frame.model_validate_json(json.dumps(frame)).b == data


@settings(max_examples=400)
@given(
    value=st.one_of(
        json_value,
        st.dictionaries(st.just("b"), json_value, min_size=1, max_size=1),
        st.dictionaries(st.just("b"), st.text(max_size=40), min_size=1, max_size=1),
    )
)
def test_any_input_parses_or_raises_validation_error(value: Any) -> None:
    try:
        frame = Frame.model_validate(value)
    except ValidationError:
        return
    assert isinstance(frame.b, bytes)
    assert isinstance(value, dict)
    # Only canonical base64 text gets through (validate=True).
    assert base64.b64encode(frame.b).decode("ascii") == value["b"].rstrip("\n")


@given(raw=st.binary(max_size=128))
def test_arbitrary_json_bytes(raw: bytes) -> None:
    with contextlib.suppress(ValidationError):  # nothing else may escape
        Frame.model_validate_json(raw)
