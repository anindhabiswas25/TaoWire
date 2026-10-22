"""The text-ops validator.

Every round it sends one random task to a sample of miners, scores the
answers (``scoring.py``) and lets TensorWire keep the scores and set
weights::

    python -m text_ops.validator
"""

from __future__ import annotations

import random

from tensorwire import (
    MinerResult,
    SubnetValidator,
    Task,
    ValidatorRunner,
    ValidatorSettings,
)

from text_ops.protocol import ROUTE, TransformRequest, TransformResponse, random_request
from text_ops.scoring import score


class TextOpsValidator(SubnetValidator):
    """Random transform tasks, exact checking, latency-weighted scores."""

    def __init__(self, *, timeout_s: float = 12.0, rng: random.Random | None = None):
        self.timeout_ms = timeout_s * 1000
        self.rng = rng if rng is not None else random.SystemRandom()

    async def make_task(self, round_id: int) -> Task:
        req = random_request(self.rng)
        return Task(
            route=ROUTE,
            body=req.model_dump_json().encode(),
            response_model=TransformResponse,
            expected=req,
        )

    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        req: TransformRequest = task.expected
        return {uid: score(req, r, self.timeout_ms) for uid, r in results.items()}


def main() -> None:
    """Start the validator from ``TW_*`` settings."""
    settings = ValidatorSettings.from_env()
    validator = TextOpsValidator(timeout_s=settings.query_timeout_s)
    ValidatorRunner(validator, settings).run()


if __name__ == "__main__":
    main()
