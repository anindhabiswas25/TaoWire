"""``TemplateValidatorAdapter``: the v10 template's validator base on the kit (10b.2.4).

A template-derived validator keeps its ``forward()`` and ``reward()`` code
and changes one import (``tensorwire migrate apply`` does it)::

    from template.base.validator import BaseValidatorNeuron
    # becomes
    from tensorwire.compat import TemplateValidatorAdapter as BaseValidatorNeuron

The kit then runs everything the template's ``BaseValidatorNeuron`` did by
hand, through :class:`~tensorwire.validator.loop.ValidatorRunner`: the
hotkey (never the coldkey), the chain connection and metagraph cache, the
``compat.Dendrite`` (with the v10 fallback when ``TW_LEGACY_V10_CLIENT=auto``),
the EMA score store (``TW_STATE_DIR/scores.db``), weight setting with
``TW_WEIGHTS_VERSION_KEY`` on the chain's rate limit, and ``/healthz``,
``/readyz``, ``/metrics`` on ``TW_METRICS_BIND``. Settings come from
``TW_*`` variables (spec Section 12).

What the team's code sees is the template's surface: ``self.config``
(``netuid`` and the ``neuron.*`` options), ``self.metagraph``
(``compat.Metagraph``), ``self.dendrite``, ``self.step``, ``self.scores``,
``self.hotkeys``, ``self.uid``, ``self.block``, ``update_scores()``,
``set_weights()``, ``run()``, and ``with Validator() as v:``.

Differences from the v10 template (also in ``docs/migration-from-v10.md``):

- One step runs ``neuron.num_concurrent_forwards`` ``forward()`` calls, then
  submits weights if due; steps start at most every ``TW_ROUND_INTERVAL_S``.
- ``update_scores`` folds rewards into the kit's EMA (alpha
  ``TW_SCORE_ALPHA``). Rewards are clamped to [0, 1] and NaN counts as 0.
  Miners not queried in a step keep their score (the template decayed them).
- Scores and the step count persist in ``TW_STATE_DIR``; ``save_state`` and
  ``load_state`` have nothing left to do.
- ``self.wallet`` and ``self.subtensor`` do not exist: the kit never loads
  the coldkey, and chain calls go through the gateway (``self.gateway``).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import math
import signal
import sys
import threading
import time
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any

import structlog
import uvicorn

from tensorwire.chain.gateway import ChainGateway, MetagraphView
from tensorwire.compat.dendrite import Dendrite
from tensorwire.compat.metagraph import Metagraph
from tensorwire.config import ValidatorSettings
from tensorwire.errors import ConfigError, StartupError
from tensorwire.miner.app import NoSignalServer
from tensorwire.observability.logging import configure_logging
from tensorwire.validator.client import MinerResult
from tensorwire.validator.loop import (
    RoundReport,
    SubnetValidator,
    Task,
    ValidatorRunner,
)

__all__ = ["TemplateValidatorAdapter"]

_log = structlog.stdlib.get_logger("tensorwire.compat.template")


class _TemplateRounds(SubnetValidator):
    """Placeholder for the runner: the template's ``forward()`` drives rounds."""

    async def make_task(self, round_id: int) -> Task:
        raise NotImplementedError("TemplateValidatorAdapter rounds call forward()")

    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        raise NotImplementedError("TemplateValidatorAdapter rounds call forward()")


def _interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def _namespace(args: argparse.Namespace) -> SimpleNamespace:
    """``{"neuron.sample_size": 5}`` -> ``config.neuron.sample_size == 5``."""
    config = SimpleNamespace()
    for key, value in vars(args).items():
        *parents, leaf = key.split(".")
        node = config
        for part in parents:
            node = node.__dict__.setdefault(part, SimpleNamespace())
        setattr(node, leaf, value)
    return config


def _fill(config: Any, defaults: SimpleNamespace) -> None:
    """Set every attribute of ``defaults`` that ``config`` lacks (recursively)."""
    for name, value in vars(defaults).items():
        current = getattr(config, name, None)
        if current is None:
            setattr(config, name, value)
        elif isinstance(value, SimpleNamespace):
            _fill(current, value)


class TemplateValidatorAdapter:
    """The v10 template's ``BaseValidatorNeuron``, run by the kit.

    Subclass it and implement ``async def forward(self)``. Everything after
    ``config`` is optional: tests pass ``FakeChain`` (``gateway``), a test
    metagraph source, a dev keypair (``hotkey``) and an in-process
    ``transport``; otherwise all of it comes from ``TW_*`` variables.
    """

    neuron_type: str = "ValidatorNeuron"

    def __init__(
        self,
        config: Any = None,
        *,
        settings: ValidatorSettings | None = None,
        hotkey: Any = None,
        gateway: ChainGateway | None = None,
        metagraph_source: Any = None,
        transport: Any = None,
        **runner_options: Any,
    ) -> None:
        self.settings = ValidatorSettings.from_env() if settings is None else settings
        self.config = self.config_from(self.settings, config)
        self.runner = ValidatorRunner(
            _TemplateRounds(),
            self.settings,
            gateway=gateway,
            metagraph=metagraph_source,
            hotkey=hotkey,
            transport=transport,
            **runner_options,
        )
        self.step = 0
        self.should_exit = False
        self.is_running = False
        self.thread: threading.Thread | None = None
        self._dendrite: Dendrite | None = None
        self._round_results: dict[int, MinerResult] = {}
        self._round_scores: dict[int, float] = {}
        self._warned_clamp = False
        self._restore_sigterm = False

    # ------------------------------------------------------------ config

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        """The template's validator options the kit does not own.

        Override (and call ``super().add_args(parser)``) to add the
        subnet's own options. Wallet, chain, timeout, sample size and EMA
        settings are ``TW_*`` variables.
        """
        parser.add_argument("--neuron.name", type=str, default="validator")
        parser.add_argument("--neuron.device", type=str, default="cpu")
        parser.add_argument("--neuron.num_concurrent_forwards", type=int, default=1)
        parser.add_argument("--neuron.vpermit_tao_limit", type=int, default=4096)
        parser.add_argument(
            "--neuron.disable_set_weights", action="store_true", default=False
        )

    @classmethod
    def config_from(cls, settings: ValidatorSettings, config: Any = None) -> Any:
        """``config`` (or the command-line options) plus the kit's values.

        ``netuid``, ``neuron.sample_size``, ``neuron.timeout``,
        ``neuron.moving_average_alpha``, ``neuron.epoch_length`` and
        ``neuron.full_path`` always come from the settings, so the template's
        code reads the values the kit really uses.
        """
        if config is None:
            parser = argparse.ArgumentParser()
            cls.add_args(parser)
            config = _namespace(parser.parse_known_args()[0])
        parser = argparse.ArgumentParser()
        TemplateValidatorAdapter.add_args(parser)
        defaults = _namespace(parser.parse_args([]))
        _fill(config, defaults)
        config.netuid = settings.netuid
        neuron = config.neuron
        neuron.sample_size = settings.sample_size
        neuron.timeout = settings.query_timeout_s
        neuron.moving_average_alpha = settings.score_alpha
        neuron.epoch_length = settings.min_weight_interval_blocks
        neuron.full_path = str(settings.state_dir)
        return config

    # ------------------------------------------------------------ template surface

    @property
    def metagraph(self) -> Metagraph:
        """The kit's metagraph with v10 attribute names (after start)."""
        return Metagraph(self.runner.metagraph)

    @property
    def gateway(self) -> ChainGateway:
        """The chain gateway (after start), for chain reads the template made."""
        return self.runner.gateway

    @property
    def dendrite(self) -> Dendrite:
        """``compat.Dendrite`` over the kit's validator client (after start)."""
        if self._dendrite is None:
            raise RuntimeError("the validator has not started")
        return self._dendrite

    @property
    def hotkeys(self) -> list[str]:
        """The metagraph's hotkeys, by UID."""
        return self.metagraph.hotkeys

    @property
    def uid(self) -> int:
        """This validator's UID."""
        return self.hotkeys.index(self.dendrite.hotkey)

    @property
    def block(self) -> int:
        """The block of the current metagraph snapshot."""
        return self.metagraph.block

    @property
    def scores(self) -> Any:
        """EMA score per UID (a numpy array when numpy is installed)."""
        n = self.metagraph.n if self._dendrite is not None else 0
        stored = self.runner.store.scores() if self.runner.store is not None else {}
        values = [float(stored.get(uid, 0.0)) for uid in range(n)]
        try:
            import numpy as np  # noqa: PLC0415 - template subnets have it; compat does not need it
        except ImportError:  # pragma: no cover - numpy is in every template subnet
            return values
        return np.asarray(values, dtype=np.float32)

    async def forward(self) -> Any:
        """The subnet's step: query miners, reward them, ``update_scores``."""
        raise NotImplementedError("implement async def forward(self)")

    def update_scores(
        self, rewards: Sequence[float] | Any, uids: Sequence[int] | Any
    ) -> None:
        """Fold ``rewards[i]`` for ``uids[i]`` into the kit's EMA score store."""
        values = [float(r) for r in rewards]
        targets = [int(u) for u in uids]
        if len(values) != len(targets):
            raise ValueError(
                f"Shape mismatch: {len(values)} rewards for {len(targets)} uids"
            )
        if not values:
            _log.warning("template_update_scores_empty")
            return
        cleaned = {}
        for uid, value in zip(targets, values, strict=True):
            finite = value if math.isfinite(value) else 0.0
            if not 0.0 <= finite <= 1.0 and not self._warned_clamp:
                self._warned_clamp = True
                _log.warning(
                    "template_reward_clamped",
                    hint="the kit's score store keeps rewards in [0, 1]",
                )
            cleaned[uid] = finite
        mg = self._snapshot()
        hotkeys = {n.uid: n.hotkey for n in mg.neurons}
        known = {uid: v for uid, v in cleaned.items() if uid in hotkeys}
        store = self._store()
        store.update(known, hotkeys, mg.block)
        self._round_scores.update(known)

    async def set_weights(self) -> Any:
        """Submit the stored scores as weights if the schedule allows it."""
        weights = self.runner.weights
        if weights is None:
            raise RuntimeError("the validator has not started")
        return await weights.maybe_submit(self._store().scores(), self._snapshot())

    def resync_metagraph(self) -> None:
        """Nothing to do: the kit keeps the metagraph fresh and resets the
        scores of replaced hotkeys at the start of every step."""

    def save_state(self) -> None:
        """Nothing to do: scores and steps are stored in ``TW_STATE_DIR``."""

    def load_state(self) -> None:
        """Nothing to do: scores and steps are stored in ``TW_STATE_DIR``."""

    # ------------------------------------------------------------ steps

    async def start(self) -> None:
        """Start the kit (hotkey, chain, metagraph, client, score store)."""
        await self.runner.start()
        client = self.runner.client
        if client is None:  # pragma: no cover - start() sets it
            raise RuntimeError("validator client missing after start")
        self._dendrite = Dendrite(client=client, on_results=self._collect)
        self.step = await asyncio.to_thread(self._store().next_round_id) - 1

    async def stop(self) -> None:
        """Stop the kit. Safe to call more than once."""
        self._dendrite = None
        await self.runner.stop()

    async def concurrent_forward(self) -> None:
        """Run ``neuron.num_concurrent_forwards`` ``forward()`` calls."""
        await asyncio.gather(
            *(self.forward() for _ in range(self.config.neuron.num_concurrent_forwards))
        )

    async def step_once(self) -> RoundReport | None:
        """One step: forward(s), then the kit's round bookkeeping and weights."""
        mg = self.runner.metagraph.snapshot()
        if mg is None:
            _log.warning("round_skipped", reason="no metagraph snapshot")
            return None
        started = time.perf_counter()
        await self.runner.begin_round(mg)
        self._round_results, self._round_scores = {}, {}
        _log.info("template_step", step=self.step, block=mg.block)
        await self.concurrent_forward()
        report = await self.runner.end_round(
            self.step + 1,
            self._snapshot(),
            self._round_results,
            self._round_scores,
            started,
            submit_weights=not self.config.neuron.disable_set_weights,
        )
        self.step += 1
        return report

    def _collect(self, results: dict[int, MinerResult]) -> None:
        self._round_results.update(results)

    def _snapshot(self) -> MetagraphView:
        return self.metagraph.snapshot()

    def _store(self) -> Any:
        if self.runner.store is None:
            raise RuntimeError("the validator has not started")
        return self.runner.store

    # ------------------------------------------------------------ running

    def run(self) -> None:
        """Run until SIGINT/SIGTERM (or ``should_exit``). Exit 3 when the
        hotkey is not registered, 2 on invalid settings."""
        configure_logging(self.settings.log_level)
        try:
            asyncio.run(self._serve(handle_signals=True))
        except KeyboardInterrupt:
            sys.exit(130)
        except StartupError as exc:
            _log.critical("startup_refused", reason=str(exc))
            sys.exit(exc.exit_code)
        except ConfigError as exc:
            _log.critical("config_invalid", reason=str(exc))
            sys.exit(2)

    def run_in_background_thread(self) -> None:
        """v10's background mode: run in a daemon thread."""
        if self.is_running:
            return
        self.should_exit = False
        self.thread = threading.Thread(
            target=lambda: asyncio.run(self._serve(handle_signals=False)),
            name="tensorwire-template-validator",
            daemon=True,
        )
        self.thread.start()
        self.is_running = True

    def stop_run_thread(self) -> None:
        """Stop the background thread (waits for the current step)."""
        if not self.is_running:
            return
        self.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout=self.settings.query_timeout_s * 3 + 30)
        self.is_running = False

    def __enter__(self) -> TemplateValidatorAdapter:
        """Start in the background (v10's ``with Validator() as v:`` form).

        In the main thread, SIGTERM (when not handled already) raises
        ``KeyboardInterrupt`` like Ctrl-C, so the ``with`` block exits and
        the validator stops cleanly.
        """
        configure_logging(self.settings.log_level)
        if (
            threading.current_thread() is threading.main_thread()
            and signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
        ):
            signal.signal(signal.SIGTERM, _interrupt)
            self._restore_sigterm = True
        self.run_in_background_thread()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop_run_thread()
        if self._restore_sigterm:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            self._restore_sigterm = False

    async def _serve(self, *, handle_signals: bool) -> None:
        await self.start()
        bind = self.settings.metrics_bind
        server = NoSignalServer(
            uvicorn.Config(
                self.runner.health_app(),
                host=bind.host,
                port=bind.port,
                lifespan="off",
                log_config=None,
                access_log=False,
                server_header=False,
            )
        )
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        if handle_signals:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
        health = loop.create_task(server.serve(), name="tensorwire-health")
        steps = loop.create_task(self._steps(stop), name="tensorwire-steps")
        _log.info("template_validator_started", block=self.block)
        try:
            await stop.wait()
        finally:
            server.should_exit = True
            steps.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await steps
            with contextlib.suppress(Exception):
                await health
            await self.stop()
            _log.info("validator_stopped")

    async def _steps(self, stop: asyncio.Event) -> None:
        interval = self.settings.round_interval_s
        while not self.should_exit:
            started = time.monotonic()
            try:
                await self.step_once()
            except Exception:  # noqa: BLE001 - a bad step must not stop the validator
                _log.exception("step_failed", step=self.step)
            # should_exit is v10's plain attribute, set from another thread: poll it.
            while not self.should_exit and time.monotonic() - started < interval:  # noqa: ASYNC110
                await asyncio.sleep(min(0.5, interval))
        stop.set()
