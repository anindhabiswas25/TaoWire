"""A hostile "miner" for the stream abuse tests (spec 13.6, D29).

It answers every request with a ``200 text/event-stream`` that never
finishes properly, below the kit's framing (a real attacker is not bound by
the kit):

- ``/drip``: a valid-looking stream sent one byte at a time, each byte a
  little inside the validator's idle limit, so no event ever completes in
  time;
- ``/endless``: complete chunk events, forever.

Run: ``python -m uvicorn hostile_stream_miner:app --port N`` from this
directory. ``DRIP_S`` sets the pause between two bytes (default 0.9 s).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

DRIP_S = float(os.environ.get("DRIP_S", "0.9"))
HEADERS = [
    (b"content-type", b"text/event-stream"),
    (b"x-tw-resp-version", b"1"),
    (b"x-tw-resp-hotkey", b"5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"),
]


async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200, "headers": HEADERS})
    if scope["path"] == "/drip":
        while True:
            for byte in b'event: chunk\ndata: {"t":"slow"}\n\n':
                await send(
                    {
                        "type": "http.response.body",
                        "body": bytes([byte]),
                        "more_body": True,
                    }
                )
                await asyncio.sleep(DRIP_S)
    while True:
        await send(
            {
                "type": "http.response.body",
                "body": b'event: chunk\ndata: {"t":"more"}\n\n',
                "more_body": True,
            }
        )
        await asyncio.sleep(0.01)
