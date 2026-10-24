"""Entry point of the ``tensorwire`` command (spec 8.14).

Sub-commands are added phase by phase.
"""

from __future__ import annotations

import typer

from tensorwire.cli.bench_cmd import bench
from tensorwire.cli.conformance_cmd import conformance
from tensorwire.cli.doctor import doctor
from tensorwire.cli.init_cmd import init
from tensorwire.cli.migrate_cmd import migrate_app
from tensorwire.cli.sidecar_cmd import sidecar
from tensorwire.cli.sign_request import sign_request
from tensorwire.version import __version__

app = typer.Typer(name="tensorwire", no_args_is_help=True, add_completion=False)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"tensorwire {__version__}")
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
    """TensorWire: networking kit for Bittensor v11 subnets."""


app.command("bench")(bench)
app.command("conformance")(conformance)
app.command("doctor")(doctor)
app.command("init")(init)
app.command("sidecar")(sidecar)
app.command("sign-request")(sign_request)
app.add_typer(migrate_app, name="migrate")
