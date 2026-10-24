"""How a validator scores one answer (spec 10).

``1.0`` for a correct result, times a latency factor
``max(0.2, 1 - latency_ms / timeout_ms)``. A failed request, a response
that failed its signature check, or a wrong result scores ``0``.
"""

from __future__ import annotations

from taowire import MinerResult

from text_ops.protocol import TransformRequest, TransformResponse, expected

MIN_LATENCY_FACTOR = 0.2


def latency_factor(latency_ms: float | None, timeout_ms: float) -> float:
    """``max(0.2, 1 - latency / timeout)``; unknown latency counts as the timeout."""
    if latency_ms is None or timeout_ms <= 0:
        return MIN_LATENCY_FACTOR
    return max(MIN_LATENCY_FACTOR, 1.0 - latency_ms / timeout_ms)


def score(req: TransformRequest, result: MinerResult, timeout_ms: float) -> float:
    """The score of one miner's answer to ``req``."""
    if not result.ok or not isinstance(result.data, TransformResponse):
        return 0.0
    if result.data.result != expected(req):
        return 0.0
    return latency_factor(result.latency_ms, timeout_ms)
