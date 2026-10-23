"""``tensorwire migrate``: help a v10 subnet move to v11 (spec 10b.4).

``scan`` lists every v10 symbol and pattern with its replacement, ``apply``
makes the safe rewrites and marks the rest with ``# TW-MIGRATE:``
comments, and ``status`` reads the nodes' ``/metrics`` and prints the
rollout numbers (spec 10b.5).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import typer

from tensorwire.migrate import status as rollout

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


@migrate_app.command("apply")
def apply(
    repo: Annotated[
        Path,
        typer.Argument(help="The subnet repository to rewrite.", file_okay=False),
    ] = Path(),
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print a unified diff; write nothing.")
    ] = False,
    allow_dirty: Annotated[
        bool,
        typer.Option(
            "--allow-dirty",
            help="Write even with uncommitted changes (or outside a git repository).",
        ),
    ] = False,
) -> None:
    """Rewrite every `auto` finding; mark the rest with `# TW-MIGRATE:` comments.

    Only .py files are touched. Without --dry-run it refuses to run on a git
    tree with uncommitted changes, so `git diff` shows exactly what changed.
    Exit status 0; 1 when a file could not be parsed; 2 when refused.
    """
    try:
        from tensorwire.migrate import apply as codemod  # noqa: PLC0415 - optional extra
    except ImportError:
        typer.echo(
            "tensorwire migrate needs libcst: pip install 'tensorwire[migrate]'",
            err=True,
        )
        raise typer.Exit(2) from None
    if not repo.is_dir():
        typer.echo(f"not a directory: {repo}", err=True)
        raise typer.Exit(2)
    if not dry_run and not allow_dirty:
        state = codemod.git_state(repo)
        if state != "clean":
            reason = (
                "has uncommitted changes"
                if state == "dirty"
                else "is not in a git repository"
            )
            typer.echo(
                f"{repo} {reason}: commit first (so `git diff` shows what apply "
                "changed), or pass --allow-dirty",
                err=True,
            )
            raise typer.Exit(2)
    report = codemod.plan_repo(repo)
    if dry_run:
        typer.echo(report.diff(), nl=False)
        typer.echo(report.summary(), err=True, nl=False)
    else:
        codemod.write_changes(report)
        typer.echo(report.summary(), nl=False)
    raise typer.Exit(1 if report.parse_errors else 0)


@migrate_app.command("status")
def status(
    metrics_url: Annotated[
        list[str] | None,
        typer.Option(
            "--metrics-url",
            help="A node's /metrics URL (TW_METRICS_BIND). Repeat for several.",
        ),
    ] = None,
    metrics_file: Annotated[
        list[Path] | None,
        typer.Option(
            "--metrics-file",
            help="A saved /metrics text (offline check). Repeat for several.",
            dir_okay=False,
        ),
    ] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="text or json.")] = "text",
    min_btauth_share: Annotated[
        float | None,
        typer.Option(
            "--min-btauth-share",
            help="Exit 1 unless this share (0-1) of miners answered over btauth/1.",
            min=0.0,
            max=1.0,
        ),
    ] = None,
) -> None:
    """Print the rollout numbers (spec 10b.5) from validators' and miners' metrics.

    Exit status 0; 1 when --min-btauth-share is given and not met; 2 when a
    URL or file cannot be read.
    """
    if fmt not in ("text", "json"):
        raise typer.BadParameter("use text or json", param_hint="--format")
    if not metrics_url and not metrics_file:
        raise typer.BadParameter(
            "give at least one --metrics-url or --metrics-file",
            param_hint="--metrics-url",
        )
    read: list[rollout.SourceStatus] = []
    unreachable: list[dict[str, str]] = []
    sources: list[str | Path] = [*(metrics_url or []), *(metrics_file or [])]
    for source in sources:
        try:
            text = (
                rollout.read_file(source)
                if isinstance(source, Path)
                else rollout.read_url(source)
            )
            read.append(rollout.parse_metrics_text(text, str(source)))
        except (OSError, rollout.MetricsTextError) as exc:
            unreachable.append({"source": str(source), "error": str(exc)})
    report = rollout.build_report(read, unreachable, min_btauth_share=min_btauth_share)
    typer.echo(rollout.render(report, fmt), nl=False)
    raise typer.Exit(report.exit_code)
