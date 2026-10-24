"""``compat.Subtensor``: v10 ``bt.subtensor`` calls on the kit gateway (10b.2.6, D34).

Subnets that are not template-derived (data-universe, for one) call
``bt.subtensor`` directly for chain reads and commitments. This facade keeps
those calls, with v10 names and keywords, and sends every one through the
kit's chain gateway (ADR-0001)::

    subtensor = Subtensor(config=config)          # was: bt.subtensor(config=config)
    mg = subtensor.metagraph(netuid)               # compat.Metagraph
    uid = subtensor.get_uid_for_hotkey_on_subnet(hotkey_ss58=hk, netuid=netuid)
    sha = subtensor.get_commitment(netuid=netuid, uid=uid)
    subtensor.set_commitment(wallet=wallet, netuid=netuid, data=sha)

Like v10's, it is synchronous: calls block until the chain answers (the
gateway runs on a private event loop thread). Reads: ``metagraph``,
``block``, ``get_current_block``, ``get_block_hash``,
``get_uid_for_hotkey_on_subnet``, ``is_hotkey_registered``,
``get_commitment``, ``query_subtensor``. Writes are signed by the wallet's
**hotkey** only; the coldkey is never read: ``commit`` / ``set_commitment``,
``set_weights`` (submitted as-is: the kit's weight scheduler re-plans expired
timelocked commits, this does not) and ``serve_axon`` (a no-op: the kit's
lifecycle publishes the axon). Every other v10 write raises
``NotImplementedError`` naming its v11 replacement; any other attribute is an
``AttributeError``. Historical reads (``block=`` other than ``None``) are not
supported. An instance used in a ``fork``-ed child process opens its own
connections there.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import threading
from collections.abc import Callable, Coroutine
from typing import Any, NoReturn, TypeVar

import structlog

from tensorwire.chain.gateway import BittensorGateway, ChainGateway
from tensorwire.compat.metagraph import Metagraph
from tensorwire.compat.weights import to_mapping
from tensorwire.migrate.rules import V10_SUBTENSOR_WRITES as V10_WRITES

__all__ = ["V10_WRITES", "Subtensor"]

_T = TypeVar("_T")
_log = structlog.stdlib.get_logger("tensorwire.compat")


_DEFAULT_TIMEOUT_S = 60.0


def _hotkey_of(wallet: Any) -> Any:
    """``wallet.hotkey`` (v10 wallet, ``HotkeyWallet``) or a keypair itself."""
    hotkey = getattr(wallet, "hotkey", wallet)
    if not isinstance(getattr(hotkey, "ss58_address", None), str):
        raise TypeError("pass a wallet with a hotkey (or a hotkey keypair)")
    return hotkey


def _no_history(block: int | None) -> None:
    if block is not None:
        raise NotImplementedError(
            "compat.Subtensor reads the latest block only; use bt.Subtensor "
            "(v11) for historical reads"
        )


def _network_from(network: str | None, config: Any) -> str:
    if network:
        return network
    group = getattr(config, "subtensor", None)
    for name in ("chain_endpoint", "network"):
        value = getattr(group, name, None)
        if isinstance(value, str) and value:
            return value
    return os.environ.get("TW_NETWORK", "finney")


class Subtensor:
    """v10 ``bt.subtensor`` reads and commitments on the kit's gateway.

    ``network`` (or ``config.subtensor.chain_endpoint`` / ``.network``, else
    ``TW_NETWORK``, else ``finney``) is the chain. ``gateway_factory(hotkey)``
    builds a gateway, ``hotkey=None`` for reads (tests pass a ``FakeChain``
    factory); the default is :class:`BittensorGateway` with
    ``TW_ALLOW_PRIVATE_AXONS``. ``timeout_s`` bounds every call.
    """

    def __init__(
        self,
        network: Any = None,  # a name or endpoint; a v10 config object works too
        config: Any = None,
        *,
        gateway_factory: Callable[[Any], ChainGateway] | None = None,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        **_v10_options: Any,
    ) -> None:
        if network is not None and not isinstance(network, str):
            network, config = None, network  # v10's bt.subtensor(config)
        self.network = _network_from(network, config)
        self.chain_endpoint = self.network
        allow_private = os.environ.get("TW_ALLOW_PRIVATE_AXONS", "0") == "1"
        self._factory = gateway_factory or (
            lambda hotkey: BittensorGateway(
                self.network, hotkey=hotkey, allow_private_axons=allow_private
            )
        )
        self._timeout_s = timeout_s
        self._closed = False
        self._start()

    # ------------------------------------------------------------ plumbing

    def _start(self) -> None:
        """A loop thread and no connections, owned by this process."""
        self._pid = os.getpid()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, name="tensorwire-subtensor", daemon=True
        )
        self._thread.start()
        self._reader: ChainGateway | None = None
        self._writers: dict[str, ChainGateway] = {}
        self._lock = threading.Lock()

    def _after_fork(self) -> None:
        """In a forked child (v10 code runs chain calls in ``fork`` workers):
        the loop thread did not survive the fork and the connections belong
        to the parent, so start afresh instead of hanging until the timeout."""
        if self._pid != os.getpid() and not self._closed:
            self._start()

    def _run(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        self._after_fork()
        if threading.current_thread() is self._thread:
            coroutine.close()
            raise RuntimeError("compat.Subtensor called from its own loop thread")
        if self._closed:
            coroutine.close()
            raise RuntimeError("compat.Subtensor is closed")
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout=self._timeout_s)
        except concurrent.futures.TimeoutError:
            future.cancel()  # a cancelled write's fate is unknown: never resent
            raise TimeoutError(
                f"chain call took longer than {self._timeout_s:g} s"
            ) from None

    def _gateway(self, hotkey: Any = None) -> ChainGateway:
        self._after_fork()
        with self._lock:
            if hotkey is None:
                if self._reader is None:
                    self._reader = self._connect(None)
                return self._reader
            ss58 = hotkey.ss58_address
            if ss58 not in self._writers:
                self._writers[ss58] = self._connect(hotkey)
            return self._writers[ss58]

    def _connect(self, hotkey: Any) -> ChainGateway:
        gateway = self._factory(hotkey)
        self._run(gateway.connect())
        return gateway

    def close(self) -> None:
        """Close the chain connections and stop the loop thread (idempotent)."""
        self._after_fork()
        with self._lock:
            gateways = [g for g in (self._reader, *self._writers.values()) if g]
            self._reader, self._writers = None, {}
        for gateway in gateways:
            try:
                self._run(gateway.close())
            except Exception:  # noqa: BLE001 - closing anyway
                _log.warning("subtensor_close_failed", exc_info=True)
        self._closed = True
        if self._loop.is_closed():
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        if not self._thread.is_alive():
            self._loop.close()

    def __enter__(self) -> Subtensor:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"compat.Subtensor({self.network})"

    # ------------------------------------------------------------ reads

    def metagraph(
        self,
        netuid: int,
        lite: bool = True,  # noqa: ARG002 - v10 signature
        block: int | None = None,
    ) -> Metagraph:
        """The subnet as a compat ``Metagraph`` (``lite`` is ignored)."""
        _no_history(block)
        return Metagraph(self._run(self._gateway().metagraph(netuid)))

    @property
    def block(self) -> int:
        """The current block."""
        return self.get_current_block()

    def get_current_block(self) -> int:
        """The current block."""
        return self._run(self._gateway().block())

    def get_block_hash(self, block: int | None = None) -> str | None:
        """The ``0x`` hash of ``block`` (the current one when ``None``)."""
        if block is None:
            block = self.get_current_block()
        return self._run(self._gateway().block_hash(block))

    def get_uid_for_hotkey_on_subnet(
        self, hotkey_ss58: str, netuid: int, block: int | None = None
    ) -> int | None:
        """``hotkey_ss58``'s UID on ``netuid``, or ``None``."""
        _no_history(block)
        return self._run(self._gateway().uid_for_hotkey(netuid, hotkey_ss58))

    def is_hotkey_registered(
        self,
        hotkey_ss58: str,
        netuid: int | None = None,
        block: int | None = None,
    ) -> bool:
        """Whether ``hotkey_ss58`` holds a UID on ``netuid`` (required here)."""
        if netuid is None:
            raise NotImplementedError(
                "is_hotkey_registered() needs netuid on TensorWire (v10's "
                "any-subnet scan is not offered)"
            )
        return self.get_uid_for_hotkey_on_subnet(hotkey_ss58, netuid, block) is not None

    def get_commitment(self, netuid: int, uid: int, block: int | None = None) -> str:
        """The commitment of ``uid``'s hotkey on ``netuid``; ``""`` if none (as v10)."""
        _no_history(block)
        if uid < 0:
            return ""
        gateway = self._gateway()
        hotkey = self._run(gateway.storage("Keys", [netuid, uid]))
        if not isinstance(hotkey, str):
            return ""  # no such UID (or a value that is not a hotkey)
        return self._run(gateway.commitment(netuid, hotkey)) or ""

    def query_subtensor(
        self, name: str, block: int | None = None, params: list[Any] | None = None
    ) -> Any:
        """A ``SubtensorModule`` storage value as plain Python data.

        v10 returned an SDK object; this returns its value (untrusted chain data).
        """
        _no_history(block)
        return self._run(self._gateway().storage(name, params or []))

    # ------------------------------------------------------------ writes

    def commit(self, wallet: Any, netuid: int, data: str) -> bool:
        """Publish ``data`` as the wallet's hotkey's commitment; True if included."""
        gateway = self._gateway(_hotkey_of(wallet))
        outcome = self._run(gateway.commit(netuid, data))
        if not outcome.ok:
            _log.warning(
                "commitment_failed", code=outcome.code, remediation=outcome.remediation
            )
        return outcome.ok

    def set_commitment(self, wallet: Any, netuid: int, data: str) -> bool:
        """v10's other name for :meth:`commit`."""
        return self.commit(wallet, netuid, data)

    def set_weights(
        self,
        wallet: Any,
        netuid: int,
        uids: Any,
        weights: Any,
        version_key: int = 0,
        **_v10_options: Any,
    ) -> tuple[bool, str]:
        """Submit weights signed by the wallet's hotkey; v10's ``(ok, message)``.

        v10's ``wait_for_*`` / ``max_retries`` options are ignored: the gateway
        waits for inclusion and never resends a write blindly.
        """
        gateway = self._gateway(_hotkey_of(wallet))
        outcome = self._run(
            gateway.set_weights(
                netuid, to_mapping(uids, weights), mechid=0, version_key=version_key
            )
        )
        if outcome.ok:
            return True, "Successfully set weights."
        return False, outcome.remediation or outcome.code or "weights not set"

    def serve_axon(self, *_args: Any, **_kwargs: Any) -> bool:
        """A no-op: the kit's lifecycle publishes the axon (spec 8.7.3)."""
        _log.info("serve_axon_ignored", hint="the kit publishes the axon at startup")
        return True

    def __getattr__(self, name: str) -> Any:
        replacement = V10_WRITES.get(name)
        if replacement is None:
            raise AttributeError(
                f"compat.Subtensor has no {name!r}; use bt.Subtensor (v11) "
                "for other chain calls"
            )

        def unsupported(*_args: Any, **_kwargs: Any) -> NoReturn:
            raise NotImplementedError(
                f"subtensor.{name}() is not offered on TensorWire (spec 10b.2.6); "
                f"v11: {replacement}"
            )

        return unsupported
