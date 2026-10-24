"""pytest fixtures shipped with TaoWire (spec 8.13).

Registered through the ``pytest11`` entry point. Kept import-light: pytest
loads this module in every project that has ``taowire`` installed, so the
kit is only imported inside fixtures.

The fake world every fixture shares (all keys are public dev keys):

=========  =========================================================
``bob``    the miner (``FakeChain`` signer), registered on netuid 1
``alice``  a validator: permit, 1,000 TAO stake
``charlie`` registered, no permit
``dave``   not registered
=========  =========================================================

Fixtures:

- ``tw_env``: a clean ``TW_*`` environment.
- ``tw_clock``: a :class:`~taowire.testing.clock.FakeClock` driving
  nonces, freshness, snapshot ages and rate limits.
- ``fake_chain``: the ``FakeChain`` above.
- ``tw_miner_kwargs`` / ``tw_miner``: a ``Miner`` on the fake chain, not
  started. Override ``tw_miner`` in your ``conftest.py`` to add your routes.
- ``miner_app``: ``tw_miner`` started; yields its ASGI app.
- ``signed_client``: a :class:`~taowire.testing.client.SignedClient`
  signing as ``alice`` for ``bob``, against ``miner_app``.

Async fixtures need ``pytest-asyncio``.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from taowire.miner.app import Miner
    from taowire.testing.client import SignedClient
    from taowire.testing.clock import FakeClock
    from taowire.testing.fake_chain import FakeChain

__all__ = [
    "MINER_KEY",
    "NON_VALIDATOR_KEY",
    "TEST_NETUID",
    "UNREGISTERED_KEY",
    "VALIDATOR_KEY",
    "TWEnv",
    "fake_chain",
    "tw_clock",
    "tw_env",
    "tw_miner",
    "tw_miner_kwargs",
]

TEST_NETUID = 1
MINER_KEY = "bob"
VALIDATOR_KEY = "alice"
NON_VALIDATOR_KEY = "charlie"
UNREGISTERED_KEY = "dave"


class TWEnv:
    """Sets ``TW_*`` variables for one test; everything is undone afterwards."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._mp = monkeypatch

    def set(self, **values: object) -> None:
        """Set ``TW_<NAME>`` for each keyword; booleans become ``1``/``0``.

        ``set(netuid=1, metagraph_strict=True)`` sets ``TW_NETUID=1`` and
        ``TW_METAGRAPH_STRICT=1``.
        """
        for name, value in values.items():
            text = ("1" if value else "0") if isinstance(value, bool) else str(value)
            self._mp.setenv(f"TW_{name.upper()}", text)

    def unset(self, *names: str) -> None:
        """Remove ``TW_<NAME>`` for each name, if set."""
        for name in names:
            self._mp.delenv(f"TW_{name.upper()}", raising=False)


@pytest.fixture
def tw_env(monkeypatch: pytest.MonkeyPatch) -> TWEnv:
    """A clean ``TW_*`` environment: every inherited ``TW_*`` variable is removed."""
    for name in list(os.environ):
        if name.upper().startswith("TW_"):
            monkeypatch.delenv(name)
    return TWEnv(monkeypatch)


@pytest.fixture
def tw_clock() -> FakeClock:
    """Frozen time; move it with ``tw_clock.advance(seconds)``."""
    from taowire.testing.clock import FakeClock  # noqa: PLC0415 - keep plugin light

    return FakeClock()


@pytest.fixture
def fake_chain(tw_clock: FakeClock) -> FakeChain:
    """Netuid 1 with the miner, a validator and a non-validator registered."""
    from taowire.testing.fake_chain import FakeChain  # noqa: PLC0415
    from taowire.testing.keys import dev_key  # noqa: PLC0415

    chain = FakeChain(
        signer_hotkey=dev_key(MINER_KEY).ss58, monotonic=tw_clock.monotonic
    )
    chain.add_subnet(TEST_NETUID)
    chain.register(TEST_NETUID, dev_key(MINER_KEY).ss58)
    chain.register(
        TEST_NETUID, dev_key(VALIDATOR_KEY).ss58, validator_permit=True, stake_tao=1000
    )
    chain.register(TEST_NETUID, dev_key(NON_VALIDATOR_KEY).ss58)
    return chain


@pytest.fixture
def tw_miner_kwargs(
    tw_env: TWEnv,  # noqa: ARG001 - requested so inherited TW_* variables cannot leak in
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
) -> dict[str, Any]:
    """Keyword arguments for a ``Miner`` on ``fake_chain`` (no NTP, no SDK check).

    ``settings`` uses an empty wallet directory under ``tmp_path``; the hotkey
    is passed directly.
    """
    from taowire.config import MinerSettings  # noqa: PLC0415
    from taowire.testing.keys import dev_key  # noqa: PLC0415
    from taowire.testing.metagraph import FakeMetagraphSource  # noqa: PLC0415

    settings = MinerSettings(
        netuid=TEST_NETUID,
        wallet_name="miner",
        wallet_path=tmp_path / "wallets",
        external_ip="44.1.2.3",
        ntp_servers=(),
    )
    return {
        "settings": settings,
        "gateway": fake_chain,
        "metagraph": FakeMetagraphSource(
            fake_chain, TEST_NETUID, clock=tw_clock.monotonic
        ),
        "hotkey": dev_key(MINER_KEY).keypair,
        "clock_ns": tw_clock.now_ns,
        "monotonic": tw_clock.monotonic,
        "check_sdk": False,
    }


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any]) -> Miner:
    """A ``Miner`` on the fake chain with no routes; override it to add yours."""
    from taowire.miner.app import Miner  # noqa: PLC0415

    return Miner(**tw_miner_kwargs)


try:
    import pytest_asyncio
except ImportError:  # pragma: no cover - async fixtures need pytest-asyncio
    pass
else:

    @pytest_asyncio.fixture
    async def miner_app(tw_miner: Miner) -> AsyncIterator[Any]:
        """``tw_miner`` started (lifecycle run against the fake chain)."""
        async with tw_miner.running() as app:
            yield app

    @pytest_asyncio.fixture
    async def signed_client(
        miner_app: Any, tw_clock: FakeClock
    ) -> AsyncIterator[SignedClient]:
        """Signs as ``alice`` (the validator) for ``bob`` (the miner)."""
        from taowire.testing.client import SignedClient  # noqa: PLC0415
        from taowire.testing.keys import dev_key  # noqa: PLC0415

        client = SignedClient(
            miner_app,
            receiver_ss58=dev_key(MINER_KEY).ss58,
            key=VALIDATOR_KEY,
            clock_ns=tw_clock.now_ns,
        )
        try:
            yield client
        finally:
            await client.aclose()

    __all__ += ["miner_app", "signed_client"]
