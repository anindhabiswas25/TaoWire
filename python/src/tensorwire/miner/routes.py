"""Route registry and the handler contract (spec 8.7.1).

A route is one signed endpoint: a path, a request model, a response model,
a handler, and its limits and caller policy. Handlers are ``async def`` or
plain ``def`` (run in a worker thread) and are called as
``handler(request, ctx)``:

- ``request`` is an instance of the route's request model, parsed from the
  verified raw body. Without a request model it is the raw body (``bytes``).
- ``ctx`` is a :class:`RouteContext`: who called and the request ID.

A handler returns an instance of the response model, or ``bytes``.
Routes are ``POST`` by default. ``GET`` routes take no body (a non-empty
body is rejected) but are signed like any other route.
"""

from __future__ import annotations

import inspect
import math
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from tensorwire.auth.verifier import Caller
from tensorwire.chain.gateway import NeuronView
from tensorwire.errors import InvalidRequest
from tensorwire.policy.caller import CallerPolicy

__all__ = [
    "RESERVED_PATHS",
    "Handler",
    "Route",
    "RouteContext",
    "RouteRegistry",
]

#: Paths the kit serves itself (health endpoints; metrics live on their own bind).
RESERVED_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})

Handler = Callable[[Any, "RouteContext"], Awaitable[Any] | Any]


@dataclass(frozen=True, slots=True)
class RouteContext:
    """What a handler knows about the request besides its body."""

    caller: Caller
    """The verified caller (``caller.hotkey_ss58``)."""

    caller_neuron: NeuronView | None
    """The caller's neuron in the latest snapshot; ``None`` for an
    allow-listed hotkey that is not registered."""

    request_id: str | None
    """The request ID, also returned in ``X-TW-Request-Id``."""

    route: str
    """The route path."""


@dataclass(frozen=True, slots=True)
class Route:
    """One registered route. Build with :meth:`RouteRegistry.add`."""

    path: str
    method: Literal["POST", "GET"]
    handler: Handler
    request_model: type[BaseModel] | None
    response_model: type[BaseModel] | None
    timeout_s: float
    max_body_bytes: int
    policy: CallerPolicy

    @property
    def is_async(self) -> bool:
        """Whether the handler is a coroutine function."""
        return inspect.iscoroutinefunction(self.handler)

    def parse(self, body: bytes) -> Any:
        """Step 9: turn the verified body into the handler's argument.

        Raises :class:`InvalidRequest` (422). Pydantic's error details are not
        returned to the caller.
        """
        if self.method == "GET":
            if body:
                raise InvalidRequest("GET routes take no request body")
            return None
        if self.request_model is None:
            return body
        try:
            return self.request_model.model_validate_json(body)
        except ValidationError:
            raise InvalidRequest() from None


def _check_path(path: str) -> str:
    if not path.startswith("/") or "?" in path or "#" in path or "{" in path:
        raise ValueError("route path must be a plain absolute path, e.g. /v1/transform")
    if path in RESERVED_PATHS:
        raise ValueError(f"{path} is reserved for the kit")
    return path


class RouteRegistry:
    """The routes of one miner, in registration order. Frozen once the app is built."""

    def __init__(self) -> None:
        self._routes: dict[str, Route] = {}
        self._frozen = False

    def __iter__(self) -> Iterator[Route]:
        return iter(self._routes.values())

    def __len__(self) -> int:
        return len(self._routes)

    def get(self, path: str) -> Route | None:
        """The route at ``path``, or ``None``."""
        return self._routes.get(path)

    def freeze(self) -> None:
        """Refuse further registrations (the app has been built)."""
        self._frozen = True

    def add(
        self,
        path: str,
        handler: Handler,
        *,
        method: Literal["POST", "GET"] = "POST",
        request: type[BaseModel] | None = None,
        response: type[BaseModel] | None = None,
        timeout_s: float,
        max_body_bytes: int,
        policy: CallerPolicy,
    ) -> Route:
        """Validate and register a route."""
        if self._frozen:
            raise RuntimeError("routes must be registered before miner.app is built")
        _check_path(path)
        if path in self._routes:
            raise ValueError(f"route {path} is already registered")
        if method not in ("POST", "GET"):
            raise ValueError("method must be POST or GET")
        if method == "GET" and request is not None:
            raise ValueError("GET routes take no request body, so no request model")
        if not math.isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError("timeout_s must be a positive number of seconds")
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be at least 1")
        if not callable(handler):
            raise TypeError("handler must be callable")
        route = Route(
            path=path,
            method=method,
            handler=handler,
            request_model=request,
            response_model=response,
            timeout_s=float(timeout_s),
            max_body_bytes=max_body_bytes,
            policy=policy,
        )
        self._routes[path] = route
        return route
