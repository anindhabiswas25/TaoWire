"""The v10 template's neuron surface on the kit (spec 10b.2.4, D18).

A template-derived subnet customises the template's ``BaseNeuron``,
``BaseMinerNeuron`` and ``BaseValidatorNeuron``. Its own methods read
``self.wallet.hotkey``, ``self.subtensor``, ``self.metagraph``, ``self.uid``
and ``self.block``, and call ``self.sync()``, ``self.check_registered()``
or ``self.serve_axon()``. The template adapters
(:class:`~taowire.compat.TemplateMinerAdapter`,
:class:`~taowire.compat.TemplateValidatorAdapter`) give that surface on
the kit, so ``taowire migrate apply`` can swap a customised base onto an
adapter and keep the subnet's methods as they are:

- ``self.wallet`` is :class:`HotkeyWallet`: the hotkey only. The coldkey is
  never loaded (spec 16.1 row 13); touching it raises.
- ``self.subtensor`` is :class:`SubtensorView`: the reads template code makes
  (``block``, ``get_current_block()``, ``metagraph()``,
  ``is_hotkey_registered()``, ``chain_endpoint``), answered from the kit's
  metagraph cache. Writes (``serve_axon``, ``set_weights``) are the kit's
  job, and any other call raises with a pointer to v11's ``bt.Subtensor``.
- ``sync()`` keeps the template's order: ``check_registered()``,
  ``resync_metagraph()`` if ``should_sync_metagraph()``, ``set_weights()``
  if ``should_set_weights()``, ``save_state()``. The defaults: registration
  was checked at startup (exit 3), the metagraph resyncs every time (the
  kit's cache refreshes it in the background), and the kit sets weights on
  its own schedule (``should_set_weights()`` is ``False``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from taowire.chain.gateway import MetagraphView

if TYPE_CHECKING:
    from taowire.compat.metagraph import Metagraph
    from taowire.config import CommonSettings

__all__ = ["HotkeyWallet", "SubtensorView", "TemplateNeuronSurface", "interrupt"]


def interrupt(_signum: int, _frame: Any) -> None:
    """SIGTERM handler: raise ``KeyboardInterrupt`` like Ctrl-C (v10 ``with`` form)."""
    raise KeyboardInterrupt


class _Hotkey:
    """v10's ``wallet.hotkey``: address, public key and ``sign``."""

    def __init__(self, signer: Any) -> None:
        self._signer = signer

    @property
    def ss58_address(self) -> str:
        """The hotkey's SS58 address."""
        return str(self._signer.ss58_address)

    @property
    def public_key(self) -> bytes:
        """The 32-byte public key."""
        return bytes(self._signer.public_key)

    def sign(self, data: bytes | str) -> bytes:
        """Sign ``data`` (a ``str`` is UTF-8 encoded, as v10's ``Keypair.sign``)."""
        payload = data.encode() if isinstance(data, str) else bytes(data)
        return bytes(self._signer.sign(payload))

    def __repr__(self) -> str:
        return f"Keypair ({self.ss58_address})"


class HotkeyWallet:
    """v10's ``bt.wallet`` with the hotkey only (spec 16.1 row 13).

    ``signer`` is anything with ``ss58_address``, ``public_key`` and
    ``sign(bytes)`` (a ``Keypair`` or the kit's ``HotkeySigner``).
    ``coldkey`` and ``coldkeypub`` raise: the kit never loads the coldkey.
    """

    def __init__(self, signer: Any, *, name: str, hotkey_name: str, path: str) -> None:
        self.hotkey = _Hotkey(signer)
        self.name = name
        self.hotkey_str = hotkey_name
        self.path = path

    @property
    def coldkey(self) -> Any:
        """Refused: TaoWire never loads the coldkey."""
        raise AttributeError(
            "TaoWire never loads the coldkey (spec 16.1 row 13): validators "
            "and miners need the hotkey only"
        )

    @property
    def coldkeypub(self) -> Any:
        """Refused: TaoWire never loads the coldkey."""
        return self.coldkey

    def __str__(self) -> str:
        return f"wallet({self.name}, {self.hotkey_str}, {self.path})"

    __repr__ = __str__


class SubtensorView:
    """The chain reads template code makes, from the kit's metagraph cache.

    ``snapshot`` returns the current ``MetagraphView`` (``RuntimeError``
    before the first one); ``metagraph`` builds the compat view.
    """

    def __init__(
        self,
        settings: CommonSettings,
        snapshot: Callable[[], MetagraphView],
        metagraph: Callable[[], Metagraph],
    ) -> None:
        self._settings = settings
        self._snapshot = snapshot
        self._metagraph = metagraph

    @property
    def network(self) -> str:
        """``TW_NETWORK``."""
        return self._settings.network

    @property
    def chain_endpoint(self) -> str:
        """``TW_NETWORK`` (a network name or a ``ws(s)://`` endpoint)."""
        return self._settings.network

    @property
    def block(self) -> int:
        """The block of the latest metagraph snapshot."""
        return self._snapshot().block

    def get_current_block(self) -> int:
        """The block of the latest metagraph snapshot (no chain round trip)."""
        return self.block

    def metagraph(
        self, netuid: int | None = None, *_args: Any, **_kw: Any
    ) -> Metagraph:
        """The kit's metagraph (``TW_NETUID`` only)."""
        self._check_netuid(netuid)
        return self._metagraph()

    def is_hotkey_registered(
        self,
        hotkey_ss58: str | None = None,
        netuid: int | None = None,
        *_args: Any,
        **_kw: Any,
    ) -> bool:
        """Whether ``hotkey_ss58`` holds a UID on ``TW_NETUID``."""
        self._check_netuid(netuid)
        if hotkey_ss58 is None:
            raise TypeError("is_hotkey_registered() needs hotkey_ss58")
        return self._snapshot().by_hotkey(hotkey_ss58) is not None

    def _check_netuid(self, netuid: int | None) -> None:
        if netuid is not None and netuid != self._settings.netuid:
            raise ValueError(
                f"the kit follows TW_NETUID={self._settings.netuid}, not {netuid}"
            )

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        raise AttributeError(
            f"subtensor.{name} is not available on TaoWire: the kit serves the "
            "axon and sets weights itself; for other chain reads use v11's "
            "bt.Subtensor (spec 3) or the kit's gateway (self.gateway)"
        )

    def __repr__(self) -> str:
        return f"subtensor({self.network})"


class TemplateNeuronSurface:
    """What the template's ``BaseNeuron`` offered, for the adapters.

    Subclasses provide ``metagraph``, ``wallet``, ``subtensor``, ``uid`` and
    ``block``; everything here is overridable by the subnet's own methods.
    """

    config: Any

    def check_registered(self) -> None:
        """Nothing to do: the kit refuses to start unregistered (exit 3)."""

    def serve_axon(self) -> None:
        """Nothing to do: the kit publishes the axon at startup (``TW_EXTERNAL_IP``)."""

    def should_sync_metagraph(self) -> bool:
        """``True``: the kit's cache refreshes in the background; reading is cheap."""
        return True

    def should_set_weights(self) -> bool:
        """``False``: the kit sets weights on its own schedule."""
        return False

    def resync_metagraph(self) -> None:
        """Nothing to do here: the kit's metagraph cache refreshes itself."""

    def set_weights(self) -> None:
        """Nothing to do here: the kit sets weights on its own schedule."""

    def save_state(self) -> None:
        """Nothing to save by default."""

    def load_state(self) -> None:
        """Nothing to load by default."""

    def sync(self) -> None:
        """The template's ``sync()``: registration, metagraph, weights, state."""
        self.check_registered()
        if self.should_sync_metagraph():
            self.resync_metagraph()
        if self.should_set_weights():
            self.set_weights()
        self.save_state()
