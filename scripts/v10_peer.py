#!/usr/bin/env python3
"""A real bittensor==10.5.0 Axon or Dendrite, for interop tests of the legacy bridge.

Run ONLY with the legacy interpreter from ``scripts/legacy_venv.sh``:

    PY="$(scripts/legacy_venv.sh | tail -1)"
    "$PY" -I scripts/v10_peer.py axon --port 8099 --hotkey-uri //Bob
    "$PY" -I scripts/v10_peer.py dendrite --ip 127.0.0.1 --port 8099 \\
        --axon-hotkey 5FHne... --hotkey-uri //Alice --count 200

``axon`` serves the archived template's ``Dummy`` (``dummy_output =
dummy_input * 2``) and prints ``READY <port>`` once it listens; it stops on
SIGTERM or when stdin closes. ``dendrite`` sends ``--count`` sequential
``Dummy`` queries and prints one JSON object per answer, then a ``SUMMARY``
line. ``stream-dendrite`` sends the template's ``StreamPrompting``
(``docs/stream_tutorial``) once with ``streaming=True`` and prints one JSON
object: the final Synapse's status and how many chunks arrived (spec 10b.3,
D33: a TensorWire miner refuses v10 streaming).

On localnet (mixed fleet, spec 13.8), ``--chain ws://127.0.0.1:9944`` with
``--wallet-name``/``--wallet-path`` uses a localnet dev wallet's hotkey:
``axon --chain ...`` also publishes the axon with the v10 SDK's
``serve_axon``; ``validator`` reads the v10 metagraph and queries the given
UIDs' axons, printing one ``RESULT`` JSON line per UID.

``validator --rounds N --set-weights`` (rollout walk-through, spec 10b.5) runs
like the archived template's validator: every ``--interval`` seconds it
re-reads the metagraph, queries the UIDs, and sets weights proportional to the
correct answers with the v10 SDK's ``set_weights`` and the template's
``version_key`` (``--version-key``, default 0 = template ``__spec_version__``).
Like the template it only sets weights when more than ``--epoch-length``
blocks (template default 100) have passed since its last update, and prints a
``WEIGHTS`` JSON line per attempt. Under commit-reveal a commit can be
accepted and its reveal still be dropped, so whether weights *landed* is read
from the chain (the ``Weights`` row) by the caller, not from this line.
``--block-time`` is passed to the v10 ``set_weights``, which uses it to pick
the drand round of the timelocked commit: on a fast-block localnet (0.25 s)
the SDK default of 12 s picks a round ~48x too late and the chain never
reveals the commit. ``--rounds 0`` runs until SIGTERM.

Dev keys and localnet wallets only; never a public network. Nothing else
leaves the machine: the external-IP lookup is disabled.
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


class StreamPrompting(bt.StreamingSynapse):
    """The archived template's streaming Synapse (docs/stream_tutorial/protocol.py)."""

    roles: typing.List[str]  # noqa: UP006
    messages: typing.List[str]  # noqa: UP006
    completion: str = ""
    required_hash_fields: ClassVar[typing.Tuple[str, ...]] = ("messages",)  # noqa: UP006

    async def process_streaming_response(self, response):  # type: ignore[no-untyped-def]
        async for chunk in response.content.iter_any():
            tokens = chunk.decode("utf-8").split("\n")
            self.completion += "".join(t for t in tokens if t)
            yield tokens

    def deserialize(self) -> str:
        return self.completion

    def extract_response_json(self, response) -> dict:  # type: ignore[no-untyped-def]  # noqa: ARG002 - v10 signature
        return {"roles": self.roles, "messages": self.messages}


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


def _local_chain(url: str) -> str:
    if not url.startswith(("ws://127.0.0.1:", "ws://localhost:")):
        raise SystemExit("localnet only: --chain must be ws://127.0.0.1:<port>")
    return url


def _wallet(args: argparse.Namespace, tmp: str) -> "bt.Wallet":
    if args.wallet_name:
        return bt.Wallet(name=args.wallet_name, hotkey="default", path=args.wallet_path)
    key = bt.Keypair.create_from_uri(args.hotkey_uri)
    wallet = bt.Wallet(name="peer", hotkey="default", path=tmp)
    wallet.set_hotkey(key, encrypt=False, overwrite=True)
    wallet.set_coldkeypub(bt.Keypair.create_from_uri(args.hotkey_uri + "//stash"))
    return wallet


def run_axon(args: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        wallet = _wallet(args, tmp)
        axon = bt.Axon(wallet=wallet, port=args.port, ip=args.ip, external_ip=args.ip)
        axon.fast_config.host = args.ip  # v10 binds 0.0.0.0 by default
        axon.attach(forward_fn=forward_dummy)
        axon.start()
        _wait_listening(args.ip, args.port)
        if args.chain:
            subtensor = bt.Subtensor(network=_local_chain(args.chain))
            served = subtensor.serve_axon(netuid=args.netuid, axon=axon)
            if not served.success:
                axon.stop()
                raise SystemExit(f"serve_axon failed: {served.message}")
        print(f"READY {args.port}", flush=True)
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        threading.Thread(
            target=lambda: (sys.stdin.read(), stop.set()), daemon=True
        ).start()
        stop.wait()
        axon.stop()


async def _query_uids(
    args: argparse.Namespace, dendrite: "bt.Dendrite", metagraph: "bt.Metagraph"
) -> dict[int, int]:
    """Query every ``--uids`` axon ``--count`` times; ``{uid: correct answers}``."""
    oks: dict[int, int] = {}
    for uid in args.uids:
        target = metagraph.axons[uid]
        statuses: dict[str, int] = {}
        ok = 0
        for i in range(args.count):
            synapse = await dendrite.call(
                target,
                Dummy(dummy_input=i),
                timeout=args.timeout,
                deserialize=False,
            )
            status = str(synapse.dendrite.status_code)
            statuses[status] = statuses.get(status, 0) + 1
            ok += status == "200" and synapse.dummy_output == i * 2
        oks[uid] = ok
        result = {
            "uid": uid,
            "axon": f"{target.ip}:{target.port}",
            "hotkey": target.hotkey,
            "count": args.count,
            "ok": ok,
            "statuses": statuses,
        }
        print("RESULT " + json.dumps(result), flush=True)
    return oks


def _set_weights(
    args: argparse.Namespace,
    subtensor: "bt.Subtensor",
    wallet: "bt.Wallet",
    oks: dict[int, int],
) -> None:
    uids = [uid for uid, ok in oks.items() if ok > 0]
    block = subtensor.get_current_block()
    metagraph = subtensor.metagraph(args.netuid)
    me = metagraph.hotkeys.index(wallet.hotkey.ss58_address)
    since = block - int(metagraph.last_update[me])
    line: dict[str, typing.Any] = {"block": block, "uids": uids, "since_update": since}
    if since <= args.epoch_length:
        line.update(submitted=False, message="not due (template epoch_length)")
    elif not uids:
        line.update(submitted=False, message="no correct answers this round")
    else:
        total = sum(oks[uid] for uid in uids)
        response = subtensor.set_weights(
            wallet=wallet,
            netuid=args.netuid,
            uids=uids,
            weights=[oks[uid] / total for uid in uids],
            version_key=args.version_key,
            block_time=args.block_time,
            wait_for_inclusion=True,
            wait_for_finalization=False,
            wait_for_revealed_execution=False,
        )
        line.update(
            submitted=True,
            version_key=args.version_key,
            success=bool(response.success),
            message=str(response.message),
        )
    print("WEIGHTS " + json.dumps(line), flush=True)


async def run_validator(args: argparse.Namespace) -> None:
    subtensor = bt.Subtensor(network=_local_chain(args.chain))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    with tempfile.TemporaryDirectory() as tmp:
        wallet = _wallet(args, tmp)
        dendrite = bt.Dendrite(wallet=wallet)
    try:
        n = 0
        while not stop.is_set():
            metagraph = subtensor.metagraph(args.netuid)
            oks = await _query_uids(args, dendrite, metagraph)
            if args.set_weights:
                _set_weights(args, subtensor, wallet, oks)
            n += 1
            if args.rounds and n >= args.rounds:
                break
            await asyncio.get_running_loop().run_in_executor(
                None, stop.wait, args.interval
            )
    finally:
        await dendrite.aclose_session()


async def run_dendrite(args: argparse.Namespace) -> None:
    if args.wallet_name:  # a registered localnet hotkey, so caller policy admits it
        with tempfile.TemporaryDirectory() as tmp:
            dendrite = bt.Dendrite(wallet=_wallet(args, tmp))
    else:
        dendrite = bt.Dendrite(wallet=bt.Keypair.create_from_uri(args.hotkey_uri))
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


async def run_stream_dendrite(args: argparse.Namespace) -> None:
    dendrite = bt.Dendrite(wallet=bt.Keypair.create_from_uri(args.hotkey_uri))
    target = AxonInfo(
        version=0,
        ip=args.ip,
        port=args.port,
        ip_type=4,
        hotkey=args.axon_hotkey,
        coldkey=args.axon_hotkey,
    )
    chunks, final = 0, None
    try:
        generator = await dendrite(
            [target],
            StreamPrompting(roles=["user"], messages=["hello"]),
            timeout=args.timeout,
            deserialize=False,
            streaming=True,
        )
        async for item in generator[0]:
            if isinstance(item, list):
                chunks += 1
            else:
                final = item
    finally:
        await dendrite.aclose_session()
    print(
        json.dumps(
            {
                "status_code": final.dendrite.status_code if final else None,
                "status_message": final.dendrite.status_message if final else None,
                "chunks": chunks,
                "completion": final.completion if final else None,
            }
        ),
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    axon = sub.add_parser("axon")
    axon.add_argument("--ip", default="127.0.0.1")
    axon.add_argument("--port", type=int, required=True)
    dendrite = sub.add_parser("dendrite")
    dendrite.add_argument("--ip", default="127.0.0.1")
    dendrite.add_argument("--port", type=int, required=True)
    dendrite.add_argument("--axon-hotkey", required=True)
    stream = sub.add_parser("stream-dendrite")
    stream.add_argument("--ip", default="127.0.0.1")
    stream.add_argument("--port", type=int, required=True)
    stream.add_argument("--axon-hotkey", required=True)
    stream.add_argument("--timeout", type=float, default=12.0)
    validator = sub.add_parser("validator")
    validator.add_argument("--uids", type=int, nargs="+", required=True)
    for mode, uri in (
        (axon, "//Bob"),
        (dendrite, "//Alice"),
        (stream, "//Alice"),
        (validator, "//Alice"),
    ):
        mode.add_argument("--hotkey-uri", default=uri)
        mode.add_argument("--wallet-name")
        mode.add_argument("--wallet-path")
        mode.add_argument("--netuid", type=int, default=2)
    for mode in (dendrite, validator):
        mode.add_argument("--count", type=int, default=1)
        mode.add_argument("--timeout", type=float, default=12.0)
    axon.add_argument("--chain")
    validator.add_argument("--chain", required=True)
    validator.add_argument("--rounds", type=int, default=1, help="0 = until SIGTERM")
    validator.add_argument("--interval", type=float, default=3.0)
    validator.add_argument("--set-weights", action="store_true")
    validator.add_argument("--version-key", type=int, default=0)
    validator.add_argument("--epoch-length", type=int, default=100)
    validator.add_argument("--block-time", type=float, default=12.0)
    args = parser.parse_args()
    if not args.hotkey_uri.startswith("//"):
        raise SystemExit("dev URIs only (//Alice, //Bob, ...)")
    if args.wallet_name and not args.wallet_path:
        raise SystemExit("--wallet-name needs --wallet-path (a localnet wallet folder)")
    if args.mode == "axon":
        run_axon(args)
    elif args.mode == "validator":
        asyncio.run(run_validator(args))
    elif args.mode == "stream-dendrite":
        asyncio.run(run_stream_dendrite(args))
    else:
        asyncio.run(run_dendrite(args))


if __name__ == "__main__":
    main()
