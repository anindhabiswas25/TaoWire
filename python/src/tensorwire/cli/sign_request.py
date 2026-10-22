"""``tensorwire sign-request``: sign one btauth/1 request with a hotkey (spec 8.14).

A debug helper. It prints a ``curl`` command carrying fresh btauth/1 headers,
or with ``--send`` sends the request itself and prints the response. The
signature is bound to the receiving miner's hotkey and is fresh for
``TW_AUTH_MAX_AGE_S`` (10 s by default), so run the printed command at once.

Only the hotkey file is read (``<wallet-path>/<wallet>/hotkeys/<hotkey>``).
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Annotated

import httpx
import typer

from tensorwire.auth.keys import load_hotkey
from tensorwire.auth.signer import RequestSigner
from tensorwire.errors import StartupError

__all__ = ["sign_request"]


def _body(data: str | None, data_file: Path | None) -> bytes:
    if data is not None and data_file is not None:
        raise typer.BadParameter("give --data or --data-file, not both")
    if data_file is not None:
        if str(data_file) == "-":
            return sys.stdin.buffer.read()
        return data_file.read_bytes()
    return b"" if data is None else data.encode()


def sign_request(
    url: Annotated[str, typer.Argument(help="Full URL, e.g. http://1.2.3.4:8091/v1/x")],
    *,
    receiver: Annotated[
        str, typer.Option("--receiver", "-r", help="The miner's hotkey (SS58)")
    ],
    wallet_name: Annotated[
        str, typer.Option("--wallet-name", "-w", envvar="TW_WALLET_NAME")
    ],
    wallet_hotkey: Annotated[
        str, typer.Option("--wallet-hotkey", "-H", envvar="TW_WALLET_HOTKEY")
    ] = "default",
    wallet_path: Annotated[
        Path, typer.Option("--wallet-path", envvar="TW_WALLET_PATH")
    ] = Path("~/.bittensor/wallets"),
    method: Annotated[str, typer.Option("--method", "-X")] = "POST",
    data: Annotated[
        str | None, typer.Option("--data", "-d", help="Request body")
    ] = None,
    data_file: Annotated[
        Path | None,
        typer.Option("--data-file", help="Read the body from a file; - = stdin"),
    ] = None,
    content_type: Annotated[str, typer.Option("--content-type")] = "application/json",
    send: Annotated[
        bool, typer.Option("--send", help="Send it now and print the response")
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Seconds, with --send")
    ] = 12.0,
) -> None:
    """Print a curl command with btauth/1 headers (or send the request)."""
    parsed = httpx.URL(url)
    if parsed.scheme not in ("http", "https") or not parsed.host:
        raise typer.BadParameter(
            "URL must be http(s)://host:port/path", param_hint="URL"
        )
    method = method.upper()
    body = _body(data, data_file)
    try:
        keypair = load_hotkey(wallet_path, wallet_name, wallet_hotkey)
    except StartupError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    try:
        signer = RequestSigner(keypair)
        headers = signer.sign(
            method=method,
            target=parsed.raw_path.decode("ascii"),
            body=body,
            receiver_ss58=receiver,
        )
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    if body:
        headers["Content-Type"] = content_type
    if send:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            response = client.request(method, parsed, content=body, headers=headers)
        typer.echo(f"HTTP {response.status_code}")
        for name in ("x-tw-request-id", "retry-after"):
            if name in response.headers:
                typer.echo(f"{name}: {response.headers[name]}")
        typer.echo(response.text)
        raise typer.Exit(0 if response.is_success else 1)
    parts = ["curl", "-sS", "--path-as-is", "-X", method, str(parsed)]
    for name, value in headers.items():
        parts += ["-H", f"{name}: {value}"]
    if body:
        parts += ["--data-binary", body.decode("utf-8", errors="surrogateescape")]
    typer.echo(shlex.join(parts))
