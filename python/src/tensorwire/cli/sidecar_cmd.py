"""``tensorwire sidecar``: the loopback service for non-Python miners (spec 11.6)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import structlog
import typer

from tensorwire.config import SidecarSettings
from tensorwire.errors import ConfigError, StartupError
from tensorwire.observability.logging import configure_logging
from tensorwire.sidecar import Sidecar

_log = structlog.stdlib.get_logger("tensorwire.sidecar")


def sidecar(
    host: Annotated[
        str,
        typer.Option(
            "--host",
            help="Bind address: 127.0.0.1 or ::1 (anything else needs "
            "TW_SIDECAR_UNSAFE_BIND=1).",
        ),
    ] = "127.0.0.1",
    port: Annotated[
        int | None,
        typer.Option("--port", help="Overrides TW_SIDECAR_PORT (default 9910)."),
    ] = None,
    env_file: Annotated[
        Path | None, typer.Option("--env-file", help="A .env file to read too.")
    ] = None,
) -> None:
    """Serve caller policy and serve-axon for a TS/Go/Rust miner (loopback only)."""
    try:
        settings = SidecarSettings.from_env(env_file)
    except ConfigError as exc:
        typer.echo(f"invalid settings: {exc}", err=True)
        raise typer.Exit(2) from None
    configure_logging(settings.log_level)
    try:
        Sidecar(settings, host=host, port=port).run()
    except StartupError as exc:
        _log.critical("startup_refused", reason=str(exc))
        raise typer.Exit(exc.exit_code) from None
