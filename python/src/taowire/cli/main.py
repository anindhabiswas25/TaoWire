"""Entry point of the ``taowire`` command (spec 8.14).

Sub-commands are added phase by phase.
"""

from __future__ import annotations

import typer

from taowire.cli.bench_cmd import bench
from taowire.cli.conformance_cmd import conformance
from taowire.cli.doctor import doctor
from taowire.cli.init_cmd import init
from taowire.cli.mcp_cmd import mcp
from taowire.cli.migrate_cmd import migrate_app
from taowire.cli.sidecar_cmd import sidecar
from taowire.cli.sign_request import sign_request
from taowire.version import __version__

app = typer.Typer(name="taowire", no_args_is_help=True, add_completion=False)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"taowire {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_print_version,
        is_eager=True,
        help="Print the version.",
    ),
) -> None:
    """TaoWire: networking kit for Bittensor v11 subnets."""


app.command("bench")(bench)
app.command("conformance")(conformance)
app.command("doctor")(doctor)
app.command("init")(init)
app.command("mcp")(mcp)
app.command("sidecar")(sidecar)
app.command("sign-request")(sign_request)
app.add_typer(migrate_app, name="migrate")
