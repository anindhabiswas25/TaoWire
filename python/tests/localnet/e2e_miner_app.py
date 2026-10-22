"""The miner the end-to-end localnet test runs as a subprocess (spec 17, Phase 1).

Configured only through ``TW_*`` environment variables, as an operator would
run it. One route, the spec 8.7.1 example.
"""

from __future__ import annotations

import hashlib
import importlib
from typing import Any, Literal

from pydantic import BaseModel

# Looked up at run time: Engineer A's Miner lands on eng-a/core in Phase 1,
# and this file must type-check in trees that do not have it yet.
_kit: Any = importlib.import_module("tensorwire")
Miner: Any = _kit.Miner


class TransformRequest(BaseModel):
    text: str
    op: Literal["upper", "reverse", "sha256"]


class TransformResponse(BaseModel):
    result: str


miner = Miner.from_env()


async def transform(req: TransformRequest, ctx: Any) -> TransformResponse:
    if req.op == "upper":
        return TransformResponse(result=req.text.upper())
    if req.op == "reverse":
        return TransformResponse(result=req.text[::-1])
    return TransformResponse(result=hashlib.sha256(req.text.encode()).hexdigest())


miner.route(
    "/v1/transform",
    request=TransformRequest,
    response=TransformResponse,
    timeout_s=5.0,
    max_body_bytes=64_000,
)(transform)


if __name__ == "__main__":
    miner.run()
