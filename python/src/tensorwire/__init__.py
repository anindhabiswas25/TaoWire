"""TensorWire: a production-grade networking kit for Bittensor v11 subnets.

The public API is importable from here; heavy modules load on first use::

    from tensorwire import Miner, RouteContext, CallerPolicy
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from tensorwire.version import __version__

if TYPE_CHECKING:
    from tensorwire.auth.verifier import Caller
    from tensorwire.config import MinerSettings
    from tensorwire.miner.app import Miner
    from tensorwire.miner.routes import RouteContext
    from tensorwire.policy.caller import CallerPolicy

__all__ = [
    "Caller",
    "CallerPolicy",
    "Miner",
    "MinerSettings",
    "RouteContext",
    "__version__",
]

_LAZY = {
    "Caller": "tensorwire.auth.verifier",
    "CallerPolicy": "tensorwire.policy.caller",
    "Miner": "tensorwire.miner.app",
    "MinerSettings": "tensorwire.config",
    "RouteContext": "tensorwire.miner.routes",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module 'tensorwire' has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
