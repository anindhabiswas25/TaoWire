"""The compat streaming miner of the streaming localnet test (spec 17 Phase 4, WP4).

The archived template's ``StreamPrompting`` (``after/docs/stream_tutorial``,
the ``migrate apply`` output of the v10 original) on ``compat.Axon``, with the
template's forward shape: ``synapse.create_streaming_response(streamer)``,
the streamer sending body frames of three tokens. The "model" echoes the
prompt word by word, so the validator can check the completion. Configured
only by ``TW_*`` variables.
"""

from __future__ import annotations

import asyncio
import importlib.util
import warnings
from functools import partial
from pathlib import Path
from typing import Any

from tensorwire.compat import Axon
from tensorwire.miner.app import Miner

PROTOCOL = (
    Path(__file__).resolve().parents[3]
    / "examples/migrations/template-v10-to-v11/after"
    / "docs/stream_tutorial/protocol.py"
)


def load_protocol() -> Any:
    spec = importlib.util.spec_from_file_location("stream_protocol", PROTOCOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PROTOCOL}")
    module = importlib.util.module_from_spec(spec)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the template's pydantic v1 Field options
        spec.loader.exec_module(module)
    return module


protocol = load_protocol()


def prompt(synapse: Any) -> Any:
    """The template's ``prompt`` (docs/stream_tutorial/miner.py), echo "model"."""

    async def _prompt(text: str, send: Any) -> None:
        buffer: list[str] = []
        n = 3
        for token in text.split(" "):
            buffer.append(token + " ")
            if len(buffer) == n:
                body = "".join(buffer).encode("utf-8")
                await send(
                    {"type": "http.response.body", "body": body, "more_body": True}
                )
                buffer = []
                await asyncio.sleep(0.05)
        body = "".join(buffer).encode("utf-8")
        await send({"type": "http.response.body", "body": body, "more_body": False})

    return synapse.create_streaming_response(partial(_prompt, synapse.messages[0]))


prompt.__annotations__ = {"synapse": protocol.StreamPrompting}

if __name__ == "__main__":  # the validator script imports load_protocol only
    Axon(miner=Miner.from_env()).attach(forward_fn=prompt).start()
