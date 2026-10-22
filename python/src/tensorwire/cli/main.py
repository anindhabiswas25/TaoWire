"""Entry point of the ``tensorwire`` command. Sub-commands are added per phase (spec 8.14)."""

from __future__ import annotations

import typer

from tensorwire.version import __version__

app = typer.Typer(name="tensorwire", no_args_is_help=True, add_completion=False)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"tensorwire {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_print_version, is_eager=True, help="Print the version."
    ),
) -> None:
    """TensorWire: networking kit for Bittensor v11 subnets."""
