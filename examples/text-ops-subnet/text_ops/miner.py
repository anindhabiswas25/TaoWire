"""The text-ops miner.

Run it with the ``TW_*`` settings of your miner hotkey (see ``.env.example``)::

    python -m text_ops.miner
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from taowire import Miner, RouteContext

from text_ops.protocol import (
    ROUTE,
    STREAM_ROUTE,
    TransformPiece,
    TransformRequest,
    TransformResponse,
    expected,
    pieces,
)


def register(miner: Miner) -> Miner:
    """Add the subnet's routes to ``miner`` and return it."""

    @miner.route(
        ROUTE,
        request=TransformRequest,
        response=TransformResponse,
        timeout_s=5.0,
        max_body_bytes=64_000,
    )
    async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse:
        return TransformResponse(result=expected(req))

    @miner.route(
        STREAM_ROUTE,
        request=TransformRequest,
        response=TransformPiece,
        timeout_s=5.0,
        max_body_bytes=64_000,
        stream=True,
    )
    async def transform_stream(
        req: TransformRequest, ctx: RouteContext
    ) -> AsyncIterator[TransformPiece]:
        for piece in pieces(req):
            yield piece

    return miner


def main() -> None:
    """Start the miner from ``TW_*`` settings."""
    register(Miner.from_env()).run()


if __name__ == "__main__":
    main()
