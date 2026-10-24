"""The TaoWire miner of the mixed-fleet test (spec 13.8), run as a subprocess.

The archived template's ``Dummy`` Synapse on a ``compat.Synapse`` route, so
v10 validators reach it too while ``TW_LEGACY_V10_UNTIL`` is set. Configured
only through ``TW_*`` environment variables.
"""

from __future__ import annotations

import importlib
from typing import Any, ClassVar

# Looked up at run time: Engineer A's Miner and compat land on eng-a/core, and
# this file must type-check in trees that do not have them yet.
Miner: Any = importlib.import_module("taowire").Miner
Synapse: Any = importlib.import_module("taowire.compat.synapse").Synapse


class Dummy(Synapse):  # type: ignore[misc]
    """The archived template's Synapse."""

    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


miner = Miner.from_env()


async def dummy(synapse: Dummy, ctx: Any) -> Dummy:
    synapse.dummy_output = synapse.dummy_input * 2
    return synapse


miner.route("/Dummy", request=Dummy, response=Dummy, legacy_synapse=Dummy)(dummy)


if __name__ == "__main__":
    miner.run()
