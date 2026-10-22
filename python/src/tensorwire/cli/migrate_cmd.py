"""``tensorwire migrate``: help a v10 subnet move to v11 (spec 10b.4).

``scan`` lists every v10 symbol and pattern with its replacement. ``apply``
(safe rewrites) and ``status`` (live btauth/1 vs v10 share) come later.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import typer

__all__ = ["migrate_app"]

migrate_app = typer.Typer(
    name="migrate", no_args_is_help=True, help="Migrate a v10 subnet to v11."
)


@migrate_app.command("scan")
def scan(
    repo: Annotated[
        Path,
        typer.Argument(help="The subnet repository to scan.", file_okay=False),
    ] = Path(),
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="text, json or md (Markdown)."),
    ] = "text",
) -> None:
    """Report every v10 symbol and risky pattern with its replacement.

    Exit status 0 when `migrate apply` can handle every finding, 1 otherwise.
    """
    if fmt not in ("text", "json", "md"):
        raise typer.BadParameter("use text, json or md", param_hint="--format")
    try:
        from tensorwire.migrate import scan as scanner  # noqa: PLC0415 - optional extra
    except ImportError:
        typer.echo(
            "tensorwire migrate needs libcst: pip install 'tensorwire[migrate]'",
            err=True,
        )
        raise typer.Exit(2) from None
    if not repo.is_dir():
        typer.echo(f"not a directory: {repo}", err=True)
        raise typer.Exit(2)
    chosen: Literal["text", "json", "md"] = fmt  # type: ignore[assignment]
    report = scanner.scan_repo(repo)
    typer.echo(scanner.render(report, chosen), nl=False)
    raise typer.Exit(report.exit_code)
