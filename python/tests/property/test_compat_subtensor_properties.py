"""Property tests for the chain values behind compat.Subtensor (spec 10b.2.6, D34).

Commitments, block info and storage values are written or decoded from data
others chose (any registered hotkey can commit anything).

1. ``BittensorGateway.commitment`` / ``block_hash`` give a non-empty ``str``
   or ``None`` for any value the SDK could return; they never raise.
2. ``Subtensor.get_commitment`` gives a ``str`` for any ``Keys`` value and any
   commitment, and for any UID.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from taowire.chain.gateway import REQUIRED_CLIENT_READS, BittensorGateway
from taowire.compat import Subtensor
from taowire.testing.fake_chain import FakeChain

values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text() | st.binary(),
    lambda inner: (
        st.lists(inner, max_size=3)
        | st.dictionaries(st.text(max_size=5), inner, max_size=3)
    ),
    max_leaves=8,
)
sdk_objects = st.one_of(
    values,
    st.builds(lambda v: SimpleNamespace(data=v), values),
    st.builds(lambda v: SimpleNamespace(hash=v), values),
)


def _unused(*_args: Any, **_kwargs: Any) -> None:
    raise AssertionError("not part of this test")


class _Client:
    """Only the reads under test are real; the rest satisfies the surface check."""

    def __init__(self, value: Any) -> None:
        self.value = value
        self.identity = SimpleNamespace(commitment=self._commitment)
        for path in REQUIRED_CLIENT_READS:
            head, _, tail = path.partition(".")
            if not hasattr(self, head):
                setattr(
                    self, head, SimpleNamespace(**{tail: _unused}) if tail else _unused
                )

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def _commitment(self, netuid: int, hotkey: str) -> Any:
        return self.value

    async def block_info(self, block: int) -> Any:
        return self.value


@settings(max_examples=200, deadline=None)
@given(value=sdk_objects)
def test_gateway_reads_never_trust_the_sdk_value(value: Any) -> None:
    async def run() -> tuple[Any, Any]:
        gw = BittensorGateway(
            "ws://x:9944", client_factory=lambda net, fb: _Client(value)
        )
        await gw.connect()
        try:
            return await gw.commitment(2, "5Hk"), await gw.block_hash(1)
        finally:
            await gw.close()

    commitment, block_hash = asyncio.run(run())
    for got in (commitment, block_hash):
        assert got is None or (isinstance(got, str) and got)


@settings(max_examples=100, deadline=None)
@given(key=values, data=st.text(min_size=1, max_size=40), uid=st.integers())
def test_get_commitment_is_always_a_string(key: Any, data: str, uid: int) -> None:
    chain = FakeChain(block=10)
    chain.add_subnet(2)
    chain.set_storage("Keys", [2, uid], key)
    if isinstance(key, str):
        chain._state.commitments[2, key] = data  # any hotkey may commit anything
    with Subtensor("x", gateway_factory=lambda hk: chain) as s:
        got = s.get_commitment(2, uid)
    assert isinstance(got, str)
    assert got in ("", data)
