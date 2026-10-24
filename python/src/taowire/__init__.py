"""TaoWire: a production-grade networking kit for Bittensor v11 subnets.

The public API is importable from here; heavy modules load on first use::

    from taowire import Miner, RouteContext, CallerPolicy
    from taowire import SubnetValidator, Task, ValidatorRunner, MinerResult
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from taowire.version import __version__

if TYPE_CHECKING:
    from taowire.auth.signer import RequestSigner
    from taowire.auth.verifier import Caller
    from taowire.config import MinerSettings, ValidatorSettings
    from taowire.extensions.streaming import StreamingReply, StreamLimits
    from taowire.miner.app import Miner
    from taowire.miner.routes import RouteContext
    from taowire.policy.caller import CallerPolicy
    from taowire.validator.client import MinerResult, MinerStream, ValidatorClient
    from taowire.validator.loop import SubnetValidator, Task, ValidatorRunner
    from taowire.validator.stream import UnverifiedChunk

__all__ = [
    "Caller",
    "CallerPolicy",
    "Miner",
    "MinerResult",
    "MinerSettings",
    "MinerStream",
    "RequestSigner",
    "RouteContext",
    "StreamLimits",
    "StreamingReply",
    "SubnetValidator",
    "Task",
    "UnverifiedChunk",
    "ValidatorClient",
    "ValidatorRunner",
    "ValidatorSettings",
    "__version__",
]

_LAZY = {
    "Caller": "taowire.auth.verifier",
    "CallerPolicy": "taowire.policy.caller",
    "Miner": "taowire.miner.app",
    "MinerSettings": "taowire.config",
    "RouteContext": "taowire.miner.routes",
    "MinerResult": "taowire.validator.client",
    "MinerStream": "taowire.validator.client",
    "StreamLimits": "taowire.extensions.streaming",
    "StreamingReply": "taowire.extensions.streaming",
    "UnverifiedChunk": "taowire.validator.stream",
    "RequestSigner": "taowire.auth.signer",
    "SubnetValidator": "taowire.validator.loop",
    "Task": "taowire.validator.loop",
    "ValidatorClient": "taowire.validator.client",
    "ValidatorRunner": "taowire.validator.loop",
    "ValidatorSettings": "taowire.config",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module 'taowire' has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
