"""Property tests for the timelock parsers of untrusted input (spec 8.10, 13.3).

A miner's sealed answer and a validator's sealed challenge come from peers.

1. ``BittensorGateway.timelock_parse`` / ``timelock_decrypt`` raise nothing
   but ``TimelockMalformed`` for any text, including envelopes whose trailer
   names a round too large for a date (no network: decryption of junk is
   local and fails first).
2. ``parse_reveal_in`` raises only ``ValueError`` and returns a positive,
   finite number of seconds.
3. ``Timelock.open_results`` never raises for any miner data, and every
   result it changes is ``ok=False`` with ``tw.invalid_response`` or
   ``tw.timelock_unavailable`` (FakeChain backend).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import struct
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from taowire.chain.gateway import BittensorGateway, TimelockMalformed
from taowire.extensions.timelock import Timelock, parse_reveal_in
from taowire.testing.fake_chain import FakeChain
from taowire.validator.client import MinerResult

GATEWAY = BittensorGateway("local")

envelopes = st.builds(
    lambda body, round_: (body + b"AES_GCM_" + struct.pack("<Q", round_)).hex(),
    st.binary(max_size=64),
    st.integers(min_value=0, max_value=2**64 - 1),
)
texts = st.one_of(
    st.text(max_size=80),
    st.binary(max_size=80).map(bytes.hex),
    envelopes,
    envelopes.map(lambda h: "0x" + h),
)


@settings(max_examples=300)
@given(sealed=texts)
def test_gateway_parsing_raises_only_malformed(sealed: str) -> None:
    try:
        parsed = GATEWAY.timelock_parse(sealed)
    except TimelockMalformed:
        return
    assert math.isfinite(parsed.reveal_at_s)
    assert parsed.reveal_round >= 0
    with contextlib.suppress(TimelockMalformed):  # nothing else may escape
        GATEWAY.timelock_decrypt(sealed, "ab" * 48)


@given(
    value=st.one_of(
        st.text(max_size=12),
        st.floats(allow_nan=True, allow_infinity=True),
        st.integers(),
        st.booleans(),
        st.none(),
    )
)
def test_parse_reveal_in_raises_only_value_error(value: Any) -> None:
    try:
        seconds = parse_reveal_in(value)
    except ValueError:
        return
    assert math.isfinite(seconds)
    assert seconds > 0


class Answer(BaseModel):
    value: int


miner_data = st.one_of(
    st.binary(max_size=200),
    st.dictionaries(
        st.sampled_from(["sealed", "ciphertext", "reveal_round", "x"]),
        st.one_of(st.booleans(), st.integers(), st.text(max_size=40), envelopes),
        max_size=4,
    ).map(lambda d: json.dumps(d).encode()),
    st.none(),
)


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(data=miner_data)
def test_open_results_never_raises(data: Any) -> None:
    chain = FakeChain()
    timelock = Timelock(chain, retries=0, timeout_s=1)
    result = MinerResult(
        uid=1,
        hotkey="5H",
        ok=True,
        status=200,
        latency_ms=1.0,
        data=data,
        error_code=None,
        attempts=1,
    )
    opened = asyncio.run(timelock.open_results({1: result}, Answer, timeout_s=1))[1]
    if opened is not result:
        assert not opened.ok
        assert opened.error_code in ("tw.invalid_response", "tw.timelock_unavailable")
