"""The sealed-challenge miner of the timelock localnet test (spec 8.10, Phase 4).

``POST /v1/sealed``: opens the validator's sealed challenge at its reveal
(real drand), answers with the sum sealed to a short reveal. Configured only
by ``TW_*`` variables.
"""

from __future__ import annotations

from pydantic import BaseModel

from taowire.extensions.timelock import SealedChallenge, SealedResponse
from taowire.miner.app import Miner
from taowire.miner.routes import RouteContext


class Question(BaseModel):
    a: int
    b: int


class Answer(BaseModel):
    total: int


def build() -> Miner:
    miner = Miner.from_env()

    @miner.route(
        "/v1/sealed", request=SealedChallenge, response=SealedResponse, timeout_s=60
    )
    async def solve(challenge: SealedChallenge, ctx: RouteContext) -> SealedResponse:
        question = await miner.timelock.open_challenge(challenge, Question)
        return await miner.timelock.seal_response(
            Answer(total=question.a + question.b), reveal_in=3
        )

    return miner


if __name__ == "__main__":
    build().run()
