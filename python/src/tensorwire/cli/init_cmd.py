"""``tensorwire init``: scaffold a subnet project (spec 8.14).

::

    tensorwire init my-subnet                  # text-ops template, package my_subnet
    tensorwire init ./x --name my-subnet

The project has a protocol, a miner, a validator, tests that pass out of the
box (in process, on TensorWire's FakeChain), ``.env.example`` and a compose
file. Templates live in ``tensorwire/cli/templates/<name>/`` as ``*.tmpl``
files (``dot-x`` names become ``.x``, so dot-files survive packaging);
``text-ops-subnet`` and ``text_ops`` in them become the project name and its
package name. The target directory must be new or empty; nothing is
ever overwritten.
"""

from __future__ import annotations

import keyword
import re
import sys
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

if TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from importlib.resources.abc import Traversable
    else:
        from importlib.abc import Traversable

__all__ = ["TEMPLATES", "check_package", "init", "package_name", "render_project"]

TEMPLATES = ("text-ops",)
_NAME_TOKEN = "text-ops-subnet"  # noqa: S105 - a template placeholder
_PACKAGE_TOKEN = "text_ops"  # noqa: S105 - a template placeholder
_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}")
_RESERVED = frozenset({"tensorwire", "bittensor", "test", "tests"})


def package_name(project: str) -> str:
    """The Python package for a project name: ``my-subnet`` -> ``my_subnet``."""
    if not _NAME_RE.fullmatch(project):
        raise ValueError(
            "project name must start with a letter and use letters, digits, "
            "'-', '_' or '.' (at most 64 characters)"
        )
    return check_package(re.sub(r"[^a-z0-9]+", "_", project.lower()).strip("_"))


def check_package(package: str) -> str:
    """``package`` if it is a usable, lower-case Python package name."""
    if (
        not package.isidentifier()
        or not package.islower()
        or keyword.iskeyword(package)
        or package in _RESERVED
    ):
        raise ValueError(f"{package!r} is not a usable package name")
    return package


def _template_root(template: str) -> Traversable:
    if template not in TEMPLATES:
        raise ValueError(f"unknown template {template!r}; use one of {TEMPLATES}")
    return resources.files("tensorwire.cli").joinpath("templates").joinpath(template)


def _walk(node: Traversable, prefix: str = "") -> list[tuple[str, Traversable]]:
    out: list[tuple[str, Traversable]] = []
    for child in sorted(node.iterdir(), key=lambda c: c.name):
        rel = f"{prefix}{child.name}"
        if child.is_dir():
            out.extend(_walk(child, rel + "/"))
        elif child.name.endswith(".tmpl"):
            target = rel.removesuffix(".tmpl").split("/")
            target = [
                "." + part.removeprefix("dot-") if part.startswith("dot-") else part
                for part in target
            ]
            out.append(("/".join(target), child))
    return out


def render_project(
    project: str, template: str = "text-ops", package: str | None = None
) -> dict[str, str]:
    """``{relative path: content}`` of a new project (nothing is written)."""
    package = package_name(project) if package is None else check_package(package)
    files: dict[str, str] = {}
    for rel, source in _walk(_template_root(template)):
        path = rel.replace(_PACKAGE_TOKEN, package)
        text = source.read_text(encoding="utf-8")
        files[path] = text.replace(_NAME_TOKEN, project).replace(
            _PACKAGE_TOKEN, package
        )
    return files


def init(
    directory: Annotated[
        Path, typer.Argument(help="New (or empty) project directory.")
    ],
    *,
    template: Annotated[
        str, typer.Option("--template", "-t", help="Project template.")
    ] = "text-ops",
    name: Annotated[
        str | None,
        typer.Option("--name", help="Project name (default: the directory name)."),
    ] = None,
    package: Annotated[
        str | None,
        typer.Option("--package", help="Python package (default: from the name)."),
    ] = None,
) -> None:
    """Scaffold a subnet project whose tests pass out of the box."""
    project = name or directory.resolve().name
    try:
        files = render_project(project, template, package)
        package = package or package_name(project)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
        typer.echo(f"{directory} exists and is not empty; nothing written", err=True)
        raise typer.Exit(1)
    for rel, content in files.items():
        target = directory / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    typer.echo(f"created {project} in {directory} ({len(files)} files)")
    typer.echo("next:")
    typer.echo(f"  cd {directory}")
    typer.echo("  pip install -e '.[dev]' && pytest")
    typer.echo(
        f"  edit {package}/protocol.py, {package}/miner.py, {package}/scoring.py"
    )
