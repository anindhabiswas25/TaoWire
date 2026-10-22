"""The text-ops miner.

Run it with the ``TW_*`` settings of your miner hotkey (see ``.env.example``)::

    python -m text_ops.miner
"""

from __future__ import annotations

from tensorwire import Miner, RouteContext

from text_ops.protocol import ROUTE, TransformRequest, TransformResponse, expected


def register(miner: Miner) -> Miner:
    """Add the subnet's route to ``miner`` and return it."""

    @miner.route(
        ROUTE,
        request=TransformRequest,
        response=TransformResponse,
        timeout_s=5.0,
        max_body_bytes=64_000,
    )
    async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse:
        return TransformResponse(result=expected(req))

    return miner


def main() -> None:
    """Start the miner from ``TW_*`` settings."""
    register(Miner.from_env()).run()


if __name__ == "__main__":
    main()
