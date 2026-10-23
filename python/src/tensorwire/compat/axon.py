"""v10-shaped ``Axon`` over the TensorWire miner (spec 10b.2.2).

::

    from tensorwire import Miner
    from tensorwire.compat import Axon

    axon = Axon(miner=Miner.from_env())           # was: bt.axon(wallet=..., config=...)
    axon.attach(forward_fn=forward, blacklist_fn=blacklist, priority_fn=priority)
    axon.serve(netuid=1)                           # config check only
    axon.start()                                   # runs the miner (blocks)

Each attached Synapse class becomes ``POST /<SynapseName>``, the path v10
used, served over btauth/1 and, while ``TW_LEGACY_V10_UNTIL`` is set, over
v10 too (spec 8.11.2). Every request runs the kit's whole pipeline first
(signature, replay, caller policy, rate limits); the team's functions run
after it and can only narrow access:

- ``blacklist_fn(synapse) -> (bool, str)`` sees ``synapse.dendrite.hotkey``
  set to the verified caller; ``True`` answers 403 ``tw.forbidden_blacklisted``.
- ``priority_fn(synapse) -> float`` orders admission once the route's
  concurrency limit is reached (higher first; at most ``TW_COMPAT_MAX_QUEUE``
  waiting, then 429).
- ``verify_fn`` must be ``None``: signature checking is the kit's job.
- ``forward_fn(synapse) -> synapse`` keeps its v10 signature; ``def``
  functions run in a worker thread.
- A ``StreamingSynapse`` route is a kit streaming route (spec 9.2):
  ``forward_fn`` returns ``synapse.create_streaming_response(streamer)``,
  each body frame the streamer sends becomes one signed chunk, and v10
  Dendrites get the v10-shaped ``tw.invalid_request`` (D33).
"""

from __future__ import annotations

import asyncio
import functools
import heapq
import inspect
import itertools
import typing
from collections.abc import AsyncIterator, Callable
from typing import Any

import anyio.to_thread
import structlog

from tensorwire.compat.stream import BTStreamingResponse, StreamingSynapse, frames
from tensorwire.compat.synapse import Synapse, TerminalInfo
from tensorwire.errors import Forbidden, HandlerError, RateLimited
from tensorwire.miner.app import Miner
from tensorwire.miner.routes import RouteContext

__all__ = ["DEFAULT_ROUTE_CONCURRENCY", "Axon", "PriorityGate"]

_log = structlog.stdlib.get_logger("tensorwire.compat")

#: Concurrent ``forward_fn`` calls per Synapse route when ``priority_fn`` is set.
DEFAULT_ROUTE_CONCURRENCY = 16


async def _call(fn: Callable[..., Any], *args: Any) -> Any:
    if inspect.iscoroutinefunction(fn):
        return await fn(*args)
    result = await anyio.to_thread.run_sync(functools.partial(fn, *args))
    if inspect.isawaitable(result):
        return await result
    return result


class PriorityGate:
    """Admits at most ``limit`` callers at once; waiters go in priority order.

    At most ``max_queue`` callers wait; one more raises
    :class:`~tensorwire.errors.RateLimited`. Ties keep arrival order.
    """

    def __init__(self, limit: int, max_queue: int) -> None:
        if limit < 1 or max_queue < 1:
            raise ValueError("limit and max_queue must be at least 1")
        self.limit = limit
        self.max_queue = max_queue
        self.active = 0
        self._waiting: list[tuple[float, int, asyncio.Future[None]]] = []
        self._seq = itertools.count()

    @property
    def queued(self) -> int:
        """Callers waiting for a slot."""
        return sum(1 for _, _, f in self._waiting if not f.done())

    async def acquire(self, priority: float) -> None:
        """Wait for a slot (higher ``priority`` first)."""
        if self.active < self.limit and not self.queued:
            self.active += 1
            return
        if self.queued >= self.max_queue:
            raise RateLimited(retry_after_s=1.0, layer="hotkey")
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        heapq.heappush(self._waiting, (-priority, next(self._seq), future))
        try:
            await future
        except asyncio.CancelledError:
            if future.done() and not future.cancelled():
                self.release()  # the slot was handed over just as we gave up
            raise

    def release(self) -> None:
        """Free a slot, handing it to the highest-priority waiter."""
        while self._waiting:
            _, _, future = heapq.heappop(self._waiting)
            if not future.done():
                future.set_result(None)
                return
        self.active -= 1


def _synapse_class(forward_fn: Callable[..., Any]) -> type[Synapse]:
    params = list(inspect.signature(forward_fn).parameters.values())
    if not params:
        raise TypeError("forward_fn must take the synapse as its first argument")
    try:
        hints = typing.get_type_hints(forward_fn)
    except Exception:  # noqa: BLE001 - unresolved annotations: fall through to the error
        hints = {}
    cls = hints.get(params[0].name)
    if not (isinstance(cls, type) and issubclass(cls, Synapse)):
        raise TypeError(
            "annotate forward_fn's first parameter with its tensorwire.compat.Synapse "
            "subclass (e.g. def forward(synapse: Dummy) -> Dummy)"
        )
    return cls


class Axon:
    """The v10 ``axon`` API, served by a :class:`~tensorwire.Miner`."""

    def __init__(self, miner: Miner | None = None, **v10_kwargs: Any) -> None:
        """``miner`` defaults to ``Miner.from_env()``.

        v10 constructor arguments (``wallet``, ``config``, ``port``, ...) are
        refused: the kit reads its settings from ``TW_*`` variables.
        """
        if v10_kwargs:
            raise TypeError(
                f"compat.Axon does not take {', '.join(sorted(v10_kwargs))}; "
                "configure the miner with TW_* settings (docs/migration-from-v10.md)"
            )
        self.miner = Miner.from_env() if miner is None else miner
        self.routes: dict[str, type[Synapse]] = {}
        self.gates: dict[str, PriorityGate] = {}

    def attach(
        self,
        forward_fn: Callable[..., Any],
        blacklist_fn: Callable[..., Any] | None = None,
        priority_fn: Callable[..., Any] | None = None,
        verify_fn: Callable[..., Any] | None = None,
        *,
        max_concurrency: int = DEFAULT_ROUTE_CONCURRENCY,
    ) -> Axon:
        """Serve ``forward_fn`` at ``/<SynapseName>``. Returns the axon (chainable)."""
        if verify_fn is not None:
            raise ValueError(
                "custom verify_fn is not supported: the kit verifies every request "
                "(btauth/1 or v10). Restrict callers with the caller policy "
                "(TW_REQUIRE_PERMIT, TW_MIN_CALLER_STAKE_TAO, TW_ALLOW_HOTKEYS) "
                "or blacklist_fn"
            )
        cls = _synapse_class(forward_fn)
        path = "/" + cls.__name__
        if path in self.routes:
            raise ValueError(f"{cls.__name__} is already attached")
        gate = (
            None
            if priority_fn is None
            else PriorityGate(max_concurrency, self.miner.settings.compat_max_queue)
        )
        handler = self._handler(cls, forward_fn, blacklist_fn, priority_fn, gate)
        if issubclass(cls, StreamingSynapse):
            self.miner.route(path, request=cls, legacy_synapse=cls, stream=True)(
                handler
            )
        else:
            self.miner.route(
                path,
                request=cls,
                response=cls,
                legacy_synapse=cls,
                encode=_encode,
            )(handler)
        self.routes[path] = cls
        if gate is not None:
            self.gates[path] = gate
        return self

    def _handler(
        self,
        cls: type[Synapse],
        forward_fn: Callable[..., Any],
        blacklist_fn: Callable[..., Any] | None,
        priority_fn: Callable[..., Any] | None,
        gate: PriorityGate | None,
    ) -> Callable[[Synapse, RouteContext], Any]:
        settings = self.miner.settings

        async def handle(synapse: Synapse, ctx: RouteContext) -> Any:
            caller = ctx.caller
            synapse.dendrite = TerminalInfo(
                hotkey=caller.hotkey_ss58, nonce=caller.nonce_ns
            )
            synapse.axon = TerminalInfo(
                hotkey=self.miner.lifecycle.runtime.hotkey_ss58,
                ip=settings.external_ip,
                port=settings.effective_external_port,
            )
            if blacklist_fn is not None:
                blocked, _reason = await _call(blacklist_fn, synapse)
                if blocked:
                    raise Forbidden(code="tw.forbidden_blacklisted")
            if gate is None or priority_fn is None:
                return await self._forward(cls, forward_fn, synapse)
            priority = float(await _call(priority_fn, synapse))
            await gate.acquire(priority)
            if issubclass(cls, StreamingSynapse):
                # forward_fn and the token streamer both run under the slot; the
                # stream gives it back when it ends, fails or is closed.
                try:
                    reply = await self._forward(cls, forward_fn, synapse)
                except BaseException:
                    gate.release()
                    raise
                return _GatedFrames(reply, gate.release)
            try:
                return await self._forward(cls, forward_fn, synapse)
            finally:
                gate.release()

        return handle

    @staticmethod
    async def _forward(
        synapse_cls: type[Synapse], forward_fn: Callable[..., Any], synapse: Synapse
    ) -> Any:
        result = await _call(forward_fn, synapse)
        if issubclass(synapse_cls, StreamingSynapse):
            if not isinstance(result, BTStreamingResponse):
                _log.error(
                    "forward_bad_return",
                    route="/" + synapse_cls.__name__,
                    expected="synapse.create_streaming_response(token_streamer)",
                )
                raise HandlerError()
            return frames(result.token_streamer)
        if not isinstance(result, synapse_cls):
            name = synapse_cls.__name__
            raise TypeError(f"forward_fn must return the {name} it was given")
        return result

    def serve(self, netuid: int | None = None, **_v10_kwargs: Any) -> Axon:
        """Check ``netuid`` against ``TW_NETUID`` (the kit publishes at startup)."""
        if netuid is not None and netuid != self.miner.settings.netuid:
            raise ValueError(
                f"serve(netuid={netuid}) but TW_NETUID={self.miner.settings.netuid}"
            )
        return self

    def start(self) -> Axon:
        """Run the miner until SIGINT/SIGTERM (blocks, unlike v10)."""
        self.miner.run()
        return self

    @property
    def app(self) -> Any:
        """The miner's ASGI app (tests, custom servers)."""
        return self.miner.app


class _GatedFrames:
    """A stream's frames holding a gate slot until they end or are closed.

    ``release`` runs exactly once: at the end of the frames, on an error, or
    on ``aclose()`` (also of a stream that never started), so the slot never
    leaks however the kit drops the stream.
    """

    def __init__(self, frames: AsyncIterator[Any], release: Callable[[], None]) -> None:
        self._frames = frames
        self._release: Callable[[], None] | None = release

    def __aiter__(self) -> _GatedFrames:
        return self

    async def __anext__(self) -> Any:
        try:
            return await anext(self._frames)
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        """Close the frames and give the slot back (idempotent)."""
        release, self._release = self._release, None
        if release is None:
            return
        try:
            close = getattr(self._frames, "aclose", None)
            if close is not None:
                await close()
        finally:
            release()


def _encode(synapse: Synapse) -> bytes:
    return synapse.user_json()
