"""The compat streaming validator of the streaming localnet test (Phase 4, WP4).

Usage: ``python stream_validator_app.py <miner hotkey>``, configured by ``TW_*``.

Every round it streams the template's ``StreamPrompting`` to the miner with
``compat.Dendrite`` the way the template's ``client.py`` does
(``streaming=True``; token lists, then the final Synapse), scores the
**final** item only (status 200 means the signed trailer verified, and the
completion must echo the prompt), and sets weights through the kit's
``WeightScheduler`` (timelocked commit, re-planned if it misses its round).
Prints one JSON line per round and per weight decision.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from stream_miner_app import load_protocol

from tensorwire import RequestSigner, ValidatorSettings
from tensorwire.auth.keys import load_hotkey
from tensorwire.chain.gateway import BittensorGateway
from tensorwire.compat import AxonInfo, Dendrite
from tensorwire.validator.weights import WeightScheduler

PROMPT = "streaming works on the localnet with a signed trailer at the end"


def emit(**fields: Any) -> None:
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()


async def main(miner_hotkey: str) -> None:
    settings = ValidatorSettings.from_env()
    protocol = load_protocol()
    hotkey = load_hotkey(
        settings.wallet_path, settings.wallet_name, settings.wallet_hotkey
    )
    gateway = BittensorGateway.from_settings(settings, hotkey)
    await gateway.connect()
    scheduler = WeightScheduler(
        gateway,
        settings.netuid,
        hotkey.ss58_address,
        min_interval_blocks=settings.min_weight_interval_blocks,
        version_key=settings.weights_version_key,
    )
    async with Dendrite(RequestSigner(hotkey), timeout_s=settings.query_timeout_s) as d:
        while True:
            mg = await gateway.metagraph(settings.netuid)
            miner = mg.by_hotkey(miner_hotkey)
            if miner is None or miner.axon is None:
                emit(event="waiting_for_axon")
                await asyncio.sleep(2)
                continue
            responses = await d(
                [AxonInfo.from_neuron(miner)],
                protocol.StreamPrompting(roles=["user"], messages=[PROMPT]),
                deserialize=False,
                streaming=True,
            )
            chunks, final = 0, None
            async for item in responses[0]:
                if isinstance(item, list):
                    chunks += 1
                else:
                    final = item
            assert final is not None
            ok = (
                final.dendrite.status_code == 200 and final.completion.strip() == PROMPT
            )
            emit(
                event="stream_round",
                ok=ok,
                chunks=chunks,
                status_code=final.dendrite.status_code,
                status_message=final.dendrite.status_message,
                completion=final.completion,
            )
            decision = await scheduler.maybe_submit({miner.uid: 1.0 if ok else 0.0}, mg)
            emit(
                event="weights",
                reason=decision.reason,
                block=decision.block,
                replans=decision.replans,
                miner_uid=miner.uid,
            )
            await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
