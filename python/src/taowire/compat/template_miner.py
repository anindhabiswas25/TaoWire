"""``TemplateMinerAdapter``: the v10 template's miner base on the kit (10b.2.4, D18).

The template's ``BaseMinerNeuron`` built a wallet, a subtensor, a metagraph
and an axon, and ran a loop that called ``sync()`` once per epoch. On
TaoWire a :class:`~taowire.Miner` does the networking (btauth/1, the
v10 bridge, caller policy, rate limits, axon publishing); this adapter keeps
the template's surface around it:

- ``self.axon`` is a :class:`~taowire.compat.Axon` on the kit's miner.
  The subnet's ``__init__`` attaches its ``forward`` / ``blacklist`` /
  ``priority`` to it, as in v10.
- ``self.config`` has ``netuid`` (``TW_NETUID``), ``neuron.full_path``
  (``TW_STATE_DIR``), the subnet's own options (its ``add_args``) and v10's
  ``wallet.*`` / ``subtensor.*`` / ``logging.*`` / ``axon.*`` groups, filled
  from the kit's settings.
- ``self.metagraph``, ``self.wallet`` (hotkey only), ``self.subtensor``
  (reads only), ``self.uid``, ``self.block``, ``self.step``, ``sync()``
  (:mod:`taowire.compat.neuron`). Before the miner serves, the first
  read fetches one metagraph snapshot from the chain (v10's
  ``BaseNeuron.__init__`` connected, so subnet code checks registration
  there); once it serves, reads come from the miner's own cache.
- ``run()`` serves until SIGINT/SIGTERM; ``with Miner() as miner:`` serves in
  the background, as v10's did. Either way ``sync()`` runs once per
  ``neuron.epoch_length`` blocks, so a subnet's ``resync_metagraph()`` (or
  its own ``sync()``) keeps its per-epoch work.

``taowire migrate apply`` puts this adapter under a customised template
miner base (TWM031). Tests pass a :class:`~taowire.Miner` built on
``FakeChain`` (``miner=``).
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import threading
import time
from typing import Any

import structlog

from taowire.auth.keys import load_hotkey
from taowire.chain.gateway import BittensorGateway, MetagraphView
from taowire.compat.axon import Axon
from taowire.compat.config import config as v10_config
from taowire.compat.config import fill_defaults, fill_v10_groups
from taowire.compat.metagraph import Metagraph
from taowire.compat.neuron import (
    HotkeyWallet,
    SubtensorView,
    TemplateNeuronSurface,
    interrupt,
)
from taowire.config import MinerSettings
from taowire.miner.app import BackgroundServer, Miner
from taowire.observability.logging import configure_logging

__all__ = ["EPOCH_POLL_S", "TemplateMinerAdapter"]

#: How often the epoch thread looks at the block (v10 slept 1 s per check).
EPOCH_POLL_S = 12.0

_log = structlog.stdlib.get_logger("taowire.compat.template")


class TemplateMinerAdapter(TemplateNeuronSurface):
    """The v10 template's ``BaseMinerNeuron``, served by a ``taowire.Miner``."""

    neuron_type: str = "MinerNeuron"

    def __init__(self, config: Any = None, *, miner: Miner | None = None) -> None:
        self.axon = Axon(miner=Miner.from_env() if miner is None else miner)
        self.settings: MinerSettings = self.axon.miner.settings
        self.config = self.config_from(self.settings, config)
        self.step = 0
        self.should_exit = False
        self.is_running = False
        self.thread: threading.Thread | None = None
        self._server: BackgroundServer | None = None
        self._epochs: threading.Thread | None = None
        self._last_sync_block: int | None = None
        self._restore_sigterm = False
        self._preflight: MetagraphView | None = None
        self._metagraph: Metagraph | None = None

    # ------------------------------------------------------------ config

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        """The template's miner options the kit does not own.

        Override (and call ``super().add_args(parser)``) to add the subnet's
        own options. Wallet, chain and axon settings are ``TW_*`` variables.
        """
        parser.add_argument("--neuron.name", type=str, default="miner")
        parser.add_argument("--neuron.device", type=str, default="cpu")
        parser.add_argument("--neuron.epoch_length", type=int, default=100)
        parser.add_argument(
            "--blacklist.force_validator_permit", action="store_true", default=False
        )
        parser.add_argument(
            "--blacklist.allow_non_registered", action="store_true", default=False
        )

    @classmethod
    def config_from(cls, settings: MinerSettings, config: Any = None) -> Any:
        """``config`` (or the command-line options) plus the kit's values."""
        if config is None:
            parser = argparse.ArgumentParser(conflict_handler="resolve")
            cls.add_args(parser)
            config = v10_config(parser)
        parser = argparse.ArgumentParser()
        TemplateMinerAdapter.add_args(parser)
        fill_defaults(config, v10_config(parser, []))
        config.netuid = settings.netuid
        config.neuron.full_path = str(settings.state_dir)
        fill_v10_groups(config, settings)
        return config

    # ------------------------------------------------------------ template surface

    @property
    def metagraph(self) -> Metagraph:
        """The miner's metagraph with v10 attribute names (pinned: it moves on
        ``metagraph.sync()``, which ``resync_metagraph()`` calls each epoch)."""
        if self._metagraph is None:
            self._metagraph = Metagraph(_Snapshots(self), pinned=True)
        return self._metagraph

    def snapshot(self) -> MetagraphView:
        """The miner's current snapshot, or the pre-flight one before it serves."""
        lifecycle = self.axon.miner.lifecycle
        if lifecycle.ready:
            current = lifecycle.runtime.metagraph.snapshot()
            if current is not None:
                return current
        if self._preflight is None:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                self._preflight = asyncio.run(self._fetch_once())
            else:
                raise RuntimeError("no metagraph yet: the miner has not started")
        return self._preflight

    async def _fetch_once(self) -> MetagraphView:
        """One metagraph read before the miner serves (as v10's ``__init__`` did)."""
        miner = self.axon.miner
        parts = miner.lifecycle.parts
        s = self.settings
        if parts.gateway is not None:  # tests: FakeChain, shared with the miner
            await parts.gateway.connect()
            return await parts.gateway.metagraph(s.netuid)
        gateway = BittensorGateway.from_settings(s, self.wallet.hotkey)
        await gateway.connect()
        try:
            return await gateway.metagraph(s.netuid)
        finally:
            await gateway.close()

    @property
    def wallet(self) -> HotkeyWallet:
        """v10's wallet with the hotkey only (the kit never loads the coldkey)."""
        miner = self.axon.miner
        s = self.settings
        if miner.lifecycle.ready:
            signer: Any = miner.lifecycle.runtime.signer
        elif miner.lifecycle.parts.hotkey is not None:
            signer = miner.lifecycle.parts.hotkey
        else:
            signer = load_hotkey(s.wallet_path, s.wallet_name, s.wallet_hotkey)
        return HotkeyWallet(
            signer,
            name=s.wallet_name,
            hotkey_name=s.wallet_hotkey,
            path=str(s.wallet_path),
        )

    @property
    def subtensor(self) -> SubtensorView:
        """The chain reads template code makes, from the miner's metagraph."""
        return SubtensorView(self.settings, self.snapshot, lambda: self.metagraph)

    @property
    def uid(self) -> int:
        """This miner's UID (once it serves)."""
        return self.metagraph.hotkeys.index(self.wallet.hotkey.ss58_address)

    @property
    def block(self) -> int:
        """The block of the latest snapshot (the pre-flight one before serving)."""
        return self.snapshot().block

    def resync_metagraph(self) -> None:
        """The template's miner resync: ``metagraph.sync()``."""
        self.metagraph.sync()

    # ------------------------------------------------------------ epochs

    def _epoch_due(self) -> bool:
        if not self.axon.miner.lifecycle.ready:
            return False
        block = self.block
        if self._last_sync_block is None:
            self._last_sync_block = block
            return False
        return block - self._last_sync_block >= int(self.config.neuron.epoch_length)

    def epoch_tick(self) -> bool:
        """Run ``sync()`` if an epoch passed since the last one; whether it ran."""
        if not self._epoch_due():
            return False
        self._last_sync_block = self.block
        self.sync()
        self.step += 1
        return True

    def _epoch_loop(self) -> None:
        while not self.should_exit:
            try:
                self.epoch_tick()
            except Exception:  # noqa: BLE001 - a failing sync must not stop the miner
                _log.exception("template_sync_failed", step=self.step)
            deadline = time.monotonic() + EPOCH_POLL_S
            while not self.should_exit and time.monotonic() < deadline:
                time.sleep(0.2)

    def _start_epochs(self) -> None:
        self.should_exit = False
        self._epochs = threading.Thread(
            target=self._epoch_loop, name="taowire-template-epochs", daemon=True
        )
        self._epochs.start()

    def _stop_epochs(self) -> None:
        self.should_exit = True
        if self._epochs is not None:
            self._epochs.join(timeout=EPOCH_POLL_S + 5)
            self._epochs = None

    # ------------------------------------------------------------ running

    def run(self) -> None:
        """Serve until SIGINT/SIGTERM (blocks), with ``sync()`` once per epoch.

        Exit codes as :meth:`taowire.Miner.run` (3 = not registered).
        """
        self._start_epochs()
        try:
            self.axon.start()
        finally:
            self._stop_epochs()

    def run_in_background_thread(self) -> None:
        """v10's background mode: serve from a daemon thread."""
        if self.is_running:
            return
        configure_logging(self.settings.log_level)
        self._server = self.axon.miner.serve_in_background()
        self._start_epochs()
        self.is_running = True

    def stop_run_thread(self) -> None:
        """Stop serving (drains in-flight requests, ``TW_DRAIN_S``)."""
        if not self.is_running:
            return
        self._stop_epochs()
        if self._server is not None:
            self._server.stop(timeout_s=self.settings.drain_s + 30)
            self._server = None
        self.is_running = False

    def __enter__(self) -> TemplateMinerAdapter:
        """Serve in the background (v10's ``with Miner() as miner:`` form).

        In the main thread, SIGTERM (when not handled already) raises
        ``KeyboardInterrupt`` like Ctrl-C, so the ``with`` block exits and
        the miner stops cleanly.
        """
        if (
            threading.current_thread() is threading.main_thread()
            and signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
        ):
            signal.signal(signal.SIGTERM, interrupt)
            self._restore_sigterm = True
        self.run_in_background_thread()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop_run_thread()
        if self._restore_sigterm:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            self._restore_sigterm = False


class _Snapshots:
    """The adapter's snapshots for ``compat.Metagraph`` (pre-flight, then live)."""

    def __init__(self, adapter: TemplateMinerAdapter) -> None:
        self._adapter = adapter

    def snapshot(self) -> MetagraphView:
        return self._adapter.snapshot()
