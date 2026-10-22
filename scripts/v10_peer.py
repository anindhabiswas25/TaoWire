#!/usr/bin/env python3
"""A real bittensor==10.5.0 Axon or Dendrite, for interop tests of the legacy bridge.

Run ONLY with the legacy interpreter from ``scripts/legacy_venv.sh``:

    PY="$(scripts/legacy_venv.sh | tail -1)"
    "$PY" -I scripts/v10_peer.py axon --port 8099 --hotkey-uri //Bob
    "$PY" -I scripts/v10_peer.py dendrite --ip 127.0.0.1 --port 8099 \\
        --axon-hotkey 5FHne... --hotkey-uri //Alice --count 200

``axon`` serves the archived template's ``Dummy`` (``dummy_output =
dummy_input * 2``) on loopback and prints ``READY <port>`` once it listens;
it stops on SIGTERM or when stdin closes. ``dendrite`` sends ``--count``
sequential ``Dummy`` queries and prints one JSON object per answer, then a
``SUMMARY`` line. Dev keys only (``//Alice``, ``//Bob``...); nothing leaves
the machine: the external-IP lookup is disabled.
"""

# No ``from __future__ import annotations``: the v10 Axon inspects forward
# function annotations and needs real classes.
import argparse
import asyncio
import importlib.metadata
import json
import signal
import socket
import sys
import tempfile
import threading
import time
import typing
from typing import ClassVar

REQUIRED_VERSION = "10.5.0"

if importlib.metadata.version("bittensor") != REQUIRED_VERSION:
    raise SystemExit(f"run this with the bittensor=={REQUIRED_VERSION} venv")

import bittensor as bt  # noqa: E402  (after the version guard)
import bittensor.utils.networking as bt_networking  # noqa: E402
from bittensor.core.chain_data import AxonInfo  # noqa: E402

bt_networking.get_external_ip = lambda: "127.0.0.1"


class Dummy(bt.Synapse):
    """The archived template's Synapse."""

    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[typing.Tuple[str, ...]] = ("dummy_input",)  # noqa: UP006

    def deserialize(self) -> int | None:
        return self.dummy_output


async def forward_dummy(synapse: Dummy) -> Dummy:
    synapse.dummy_output = synapse.dummy_input * 2
    return synapse


def _wait_listening(host: str, port: int, timeout_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            if sock.connect_ex((host, port)) == 0:
                return
        time.sleep(0.05)
    raise SystemExit(f"axon did not listen on {host}:{port}")


def run_axon(args: argparse.Namespace) -> None:
    key = bt.Keypair.create_from_uri(args.hotkey_uri)
    with tempfile.TemporaryDirectory() as tmp:
        wallet = bt.Wallet(name="peer", hotkey="default", path=tmp)
        wallet.set_hotkey(key, encrypt=False, overwrite=True)
        wallet.set_coldkeypub(bt.Keypair.create_from_uri(args.hotkey_uri + "//stash"))
        axon = bt.Axon(wallet=wallet, port=args.port, ip=args.ip, external_ip=args.ip)
        axon.fast_config.host = args.ip  # v10 binds 0.0.0.0 by default
        axon.attach(forward_fn=forward_dummy)
        axon.start()
        _wait_listening(args.ip, args.port)
        print(f"READY {args.port}", flush=True)
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        threading.Thread(
            target=lambda: (sys.stdin.read(), stop.set()), daemon=True
        ).start()
        stop.wait()
        axon.stop()


async def run_dendrite(args: argparse.Namespace) -> None:
    key = bt.Keypair.create_from_uri(args.hotkey_uri)
    dendrite = bt.Dendrite(wallet=key)
    target = AxonInfo(
        version=0,
        ip=args.ip,
        port=args.port,
        ip_type=4,
        hotkey=args.axon_hotkey,
        coldkey=args.axon_hotkey,
    )
    ok = 0
    try:
        for i in range(args.count):
            synapse = await dendrite.call(
                target, Dummy(dummy_input=i), timeout=args.timeout, deserialize=False
            )
            good = synapse.dendrite.status_code == 200 and synapse.dummy_output == i * 2
            ok += good
            print(
                json.dumps(
                    {
                        "i": i,
                        "status_code": synapse.dendrite.status_code,
                        "status_message": synapse.dendrite.status_message,
                        "dummy_output": synapse.dummy_output,
                        "axon_hotkey": synapse.axon.hotkey,
                        "axon_signature": synapse.axon.signature,
                        "ok": good,
                    }
                ),
                flush=True,
            )
    finally:
        await dendrite.aclose_session()
    print(f"SUMMARY {ok}/{args.count}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    axon = sub.add_parser("axon")
    axon.add_argument("--ip", default="127.0.0.1")
    axon.add_argument("--port", type=int, required=True)
    axon.add_argument("--hotkey-uri", default="//Bob")
    dendrite = sub.add_parser("dendrite")
    dendrite.add_argument("--ip", default="127.0.0.1")
    dendrite.add_argument("--port", type=int, required=True)
    dendrite.add_argument("--axon-hotkey", required=True)
    dendrite.add_argument("--hotkey-uri", default="//Alice")
    dendrite.add_argument("--count", type=int, default=1)
    dendrite.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args()
    if not args.hotkey_uri.startswith("//"):
        raise SystemExit("dev URIs only (//Alice, //Bob, ...)")
    if args.mode == "axon":
        run_axon(args)
    else:
        asyncio.run(run_dendrite(args))


if __name__ == "__main__":
    main()
