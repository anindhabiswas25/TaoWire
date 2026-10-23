"""``tensorwire migrate apply``: the safe rewrites (spec 10b.4.2).

Only ``auto`` rules are rewritten:

- ``bt.Synapse`` / ``bt.AxonInfo`` (and ``from bittensor import ...`` of them)
  -> ``tensorwire.compat`` (TWM001, TWM021);
- ``bt.logging.<level>(...)`` -> ``logging.<level>(...)``, ``trace`` ->
  ``debug``, ``success`` -> ``info`` (TWM007);
- ``bt.axon(...)`` -> ``Axon(miner=Miner.from_env())``,
  ``bt.dendrite(wallet=w)`` -> ``Dendrite(signer=RequestSigner(w))``
  (TWM003, TWM004);
- ``process_weights_for_netuid(uids=u, weights=w, ...)`` and
  ``convert_weights_and_uids_for_emit(u, w)`` -> ``(u, w)``: v11
  ``SetWeights`` normalises and quantises itself (TWM012);
- ``[m.metagraph.axons[uid] for uid in uids]`` -> ``axons_from(m.metagraph,
  uids)`` (TWM013);
- ``.item()`` / ``.tolist()`` on metagraph values are dropped (TWM023);
- the template's ``from template.base.validator import BaseValidatorNeuron``
  -> ``from tensorwire.compat import TemplateValidatorAdapter as
  BaseValidatorNeuron`` (TWM024), only when that base is the stock template
  (a customised one is TWM026, by hand);
- ``time.sleep(x)`` inside ``async def`` -> ``await asyncio.sleep(x)``
  (TWM027);
- string annotations ``"bt.metagraph.Metagraph"``, ``"bt.Synapse"``, ...
  -> the compat names.

``import bittensor as bt`` is removed once nothing refers to ``bt`` any more,
and the imports the rewrites need take its place. Every finding ``migrate
scan`` still reports afterwards (``manual``, ``risk``, and any ``auto`` case
that could not be rewritten safely) gets a ``# TW-MIGRATE: TWMxxx
<instruction>`` line above its statement. Running ``apply`` twice changes
nothing the second time.

Only ``.py`` files are read and written (so never wallets or ``.env``
files), with the same directory rules as ``scan``; a file is rewritten in
place only when it changed, and never through a symlink.
"""

from __future__ import annotations

import difflib
import os
import subprocess
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import libcst as cst
from libcst.metadata import MetadataWrapper, ParentNodeProvider, PositionProvider

from tensorwire.migrate.rules import RULES
from tensorwire.migrate.scan import (
    LOG_LEVELS,
    is_axons_list,
    is_metagraph_tensor_call,
    python_files,
    resolve_module,
    scan_source,
    template_bases,
)

__all__ = [
    "MARKER",
    "ApplyReport",
    "FileResult",
    "GitState",
    "apply_source",
    "git_state",
    "plan_repo",
    "write_changes",
]

#: The comment ``apply`` leaves for every finding it cannot rewrite.
MARKER = "# TW-MIGRATE:"

GitState = Literal["clean", "dirty", "not_git"]

_WEIGHT_HELPERS = frozenset(
    {"process_weights_for_netuid", "convert_weights_and_uids_for_emit"}
)
#: ``bt.<name>`` -> the compat name it becomes when used as a value or type.
_COMPAT_NAMES = {
    "Synapse": "Synapse",
    "AxonInfo": "AxonInfo",
    "axon": "Axon",
    "Axon": "Axon",
    "dendrite": "Dendrite",
    "Dendrite": "Dendrite",
}
#: ``"bt.<path>"`` string annotations -> the compat name.
_ANNOTATION_NAMES = {
    "Synapse": "Synapse",
    "AxonInfo": "AxonInfo",
    "Metagraph": "Metagraph",
    "metagraph": "Metagraph",
    "metagraph.Metagraph": "Metagraph",
}
_TEMPLATE_BASE = "BaseValidatorNeuron"
_ADAPTER = "TemplateValidatorAdapter"


@dataclass
class FileResult:
    """One file before and after ``apply``."""

    path: str
    before: str
    after: str
    rewrites: Counter[str] = field(default_factory=Counter)
    marked: Counter[str] = field(default_factory=Counter)

    @property
    def changed(self) -> bool:
        """Whether ``apply`` changes this file."""
        return self.before != self.after

    def diff(self) -> str:
        """The change as a unified diff (``a/<path>``, ``b/<path>``)."""
        return "".join(
            difflib.unified_diff(
                self.before.splitlines(keepends=True),
                self.after.splitlines(keepends=True),
                fromfile=f"a/{self.path}",
                tofile=f"b/{self.path}",
            )
        )


@dataclass
class ApplyReport:
    """What ``apply`` does to one repository."""

    root: str
    files: list[FileResult] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def changed(self) -> list[FileResult]:
        """The files that change."""
        return [f for f in self.files if f.changed]

    def diff(self) -> str:
        """Every change as one unified diff."""
        return "".join(f.diff() for f in self.changed)

    def summary(self) -> str:
        """Counts per rule, then one line per changed file."""
        rewrites: Counter[str] = Counter()
        marked: Counter[str] = Counter()
        for f in self.files:
            rewrites.update(f.rewrites)
            marked.update(f.marked)
        lines = [
            f"{len(self.files)} files read, {len(self.changed)} changed: "
            f"{sum(rewrites.values())} rewrites, {sum(marked.values())} "
            f"{MARKER} comments."
        ]
        if rewrites:
            lines.append(
                "rewritten: "
                + ", ".join(f"{r} x{n}" for r, n in sorted(rewrites.items()))
            )
        if marked:
            lines.append(
                "to do by hand: "
                + ", ".join(f"{r} x{n}" for r, n in sorted(marked.items()))
            )
        lines += [f"  {f.path}" for f in self.changed]
        lines += [f"parse error: {e}" for e in self.parse_errors]
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- helpers


def _dotted(node: cst.CSTNode) -> str | None:
    if isinstance(node, cst.Name):
        return str(node.value)
    if isinstance(node, cst.Attribute):
        inner = _dotted(node.value)
        return None if inner is None else f"{inner}.{node.attr.value}"
    return None


def _name_of(alias: cst.ImportAlias) -> str:
    return _dotted(alias.name) or ""


def _local_of(alias: cst.ImportAlias) -> str:
    if alias.asname is not None and isinstance(alias.asname.name, cst.Name):
        return str(alias.asname.name.value)
    return _name_of(alias).split(".")[0]


def _kwarg(name: str, value: cst.BaseExpression) -> cst.Arg:
    """``name=value`` (no spaces around ``=``)."""
    return cst.Arg(
        keyword=cst.Name(name),
        value=value,
        equal=cst.AssignEqual(
            whitespace_before=cst.SimpleWhitespace(""),
            whitespace_after=cst.SimpleWhitespace(""),
        ),
    )


def _arg(call: cst.Call, keyword: str, position: int) -> cst.BaseExpression | None:
    for arg in call.args:
        if arg.keyword is not None and arg.keyword.value == keyword:
            return arg.value
    positional = [a for a in call.args if a.keyword is None and not a.star]
    return positional[position].value if len(positional) > position else None


def _logging_args(call: cst.Call) -> Sequence[cst.Arg]:
    """``bt.logging`` arguments for the standard ``logging`` functions.

    v10 logs ``prefix - msg - suffix`` (``bt.logging.info(msg, prefix,
    suffix)``); the standard functions would take those as %-format
    arguments. ``logging.info("%s - %s", prefix, msg)`` keeps the text (v10
    also dropped empty parts).
    """
    named = {a.keyword.value: a for a in call.args if a.keyword is not None}
    positional = [a for a in call.args if a.keyword is None and not a.star]
    if len(positional) > 3 or any(a.star for a in call.args):
        return call.args  # rare; the extra arguments already were %-format args
    parts: dict[str, cst.BaseExpression] = {}
    for index, name in enumerate(("msg", "prefix", "suffix")):
        if index < len(positional):
            parts[name] = positional[index].value
        elif name in named:
            parts[name] = named.pop(name).value
    if set(parts) <= {"msg"}:
        return call.args
    order = [n for n in ("prefix", "msg", "suffix") if n in parts]
    fmt = cst.SimpleString('"' + " - ".join(["%s"] * len(order)) + '"')
    rest = [a.with_changes(comma=cst.MaybeSentinel.DEFAULT) for a in named.values()]
    args = [cst.Arg(value=fmt), *(cst.Arg(value=parts[n]) for n in order), *rest]
    return [
        a.with_changes(
            comma=cst.Comma(whitespace_after=cst.SimpleWhitespace(" "))
            if i < len(args) - 1
            else cst.MaybeSentinel.DEFAULT
        )
        for i, a in enumerate(args)
    ]


class _Names(cst.CSTVisitor):
    """Every ``Name`` used outside import statements."""

    def __init__(self) -> None:
        super().__init__()
        self.used: set[str] = set()

    def visit_Import(self, _node: cst.Import) -> bool:  # noqa: N802 - libcst API
        return False

    def visit_ImportFrom(self, _node: cst.ImportFrom) -> bool:  # noqa: N802 - libcst API
        return False

    def visit_Name(self, node: cst.Name) -> None:  # noqa: N802 - libcst API
        self.used.add(str(node.value))


def _used_names(module: cst.Module) -> set[str]:
    names = _Names()
    module.visit(names)
    return names.used


# ---------------------------------------------------------------- rewriting


class _Rewriter(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (ParentNodeProvider,)

    def __init__(
        self, bt_aliases: set[str], path: str, custom_bases: Mapping[str, list[str]]
    ) -> None:
        super().__init__()
        self.bt = bt_aliases
        self.path = path
        self.custom_bases = custom_bases
        self.rewrites: Counter[str] = Counter()
        self.need_logging = False
        self.need_asyncio = False
        self._async_stack: list[bool] = []
        self.need_kit: set[str] = set()  # from tensorwire import ...
        self.need_compat: set[str] = set()  # from tensorwire.compat import ...
        self.dropped_helpers = False
        self._annotation_depth = 0

    # -------------------------------------------------- bt.<name>

    def _is_bt(self, node: cst.BaseExpression) -> bool:
        return isinstance(node, cst.Name) and node.value in self.bt

    def _is_class_base(self, node: cst.CSTNode) -> bool:
        parent = self.get_metadata(ParentNodeProvider, node, None)
        return isinstance(parent, cst.Arg) and isinstance(
            self.get_metadata(ParentNodeProvider, parent, None), cst.ClassDef
        )

    def leave_Attribute(  # noqa: N802 - libcst API
        self, original_node: cst.Attribute, updated_node: cst.Attribute
    ) -> cst.BaseExpression:
        if not self._is_bt(original_node.value):
            return updated_node
        attr = original_node.attr.value
        compat = _COMPAT_NAMES.get(attr)
        if compat is None:
            return updated_node
        if compat in ("Axon", "Dendrite") and self._is_class_base(original_node):
            return updated_node  # a custom Axon/Dendrite subclass: TWM019, by hand
        parent = self.get_metadata(ParentNodeProvider, original_node, None)
        if isinstance(parent, cst.Attribute) and parent.value is original_node:
            return updated_node  # bt.axon.add_args(...): v10 config, TWM006
        self.need_compat.add(compat)
        rule = {"Synapse": "TWM001", "AxonInfo": "TWM021", "Axon": "TWM003"}.get(
            compat, "TWM004"
        )
        self.rewrites[rule] += 1
        return cst.Name(compat)

    # -------------------------------------------------- calls

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:  # noqa: N802 - libcst API
        self._async_stack.append(node.asynchronous is not None)

    def leave_FunctionDef(  # noqa: N802 - libcst API
        self, _original: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        self._async_stack.pop()
        return updated_node

    def visit_Lambda(self, _node: cst.Lambda) -> None:  # noqa: N802 - libcst API
        self._async_stack.append(False)

    def leave_Lambda(  # noqa: N802 - libcst API
        self, _original: cst.Lambda, updated_node: cst.Lambda
    ) -> cst.Lambda:
        self._async_stack.pop()
        return updated_node

    def leave_Call(  # noqa: N802 - libcst API
        self, original_node: cst.Call, updated_node: cst.Call
    ) -> cst.BaseExpression:
        func = original_node.func
        name = _dotted(func) or ""
        head, _, last = name.rpartition(".")
        if name == "time.sleep" and self._async_stack and self._async_stack[-1]:
            self.need_asyncio = True
            self.rewrites["TWM027"] += 1
            return cst.Await(
                expression=updated_node.with_changes(
                    func=cst.Attribute(
                        value=cst.Name("asyncio"), attr=cst.Name("sleep")
                    )
                )
            )
        if head.rpartition(".")[2] == "logging" and self._is_bt_path(head, 1):
            return self._logging_call(updated_node, last)
        if head in self.bt and last in ("axon", "Axon"):
            return self._axon_call()
        if head in self.bt and last in ("dendrite", "Dendrite"):
            return self._dendrite_call(original_node, updated_node)
        if last in _WEIGHT_HELPERS:
            return self._weights_call(updated_node)
        if is_metagraph_tensor_call(original_node) and isinstance(
            updated_node.func, cst.Attribute
        ):
            self.rewrites["TWM023"] += 1
            return updated_node.func.value
        return updated_node

    def _is_bt_path(self, dotted: str, depth: int) -> bool:
        parts = dotted.split(".")
        return len(parts) == depth + 1 and parts[0] in self.bt

    def _logging_call(self, call: cst.Call, level: str) -> cst.BaseExpression:
        target = LOG_LEVELS.get(level)
        if target is None:
            return call  # bt.logging.set_config(...) etc.: TWM025, by hand
        self.need_logging = True
        self.rewrites["TWM007"] += 1
        return call.with_changes(
            func=cst.Attribute(value=cst.Name("logging"), attr=cst.Name(target)),
            args=_logging_args(call),
        )

    def _axon_call(self) -> cst.BaseExpression:
        # bt.axon's arguments are dropped: every setting comes from TW_*
        # (TW_BIND_PORT, TW_EXTERNAL_IP, ...), as the TWM003 docs say.
        self.need_compat.add("Axon")
        self.need_kit.add("Miner")
        self.rewrites["TWM003"] += 1
        from_env = cst.Call(
            func=cst.Attribute(value=cst.Name("Miner"), attr=cst.Name("from_env"))
        )
        return cst.Call(
            func=cst.Name("Axon"),
            args=[_kwarg("miner", from_env)],
        )

    def _dendrite_call(
        self, original: cst.Call, updated: cst.Call
    ) -> cst.BaseExpression:
        wallet = _arg(updated, "wallet", 0)
        if wallet is None or len(original.args) > 1:
            # Unknown shape: keep it for a person (the scan will flag it).
            return updated.with_changes(func=original.func)
        self.need_compat.add("Dendrite")
        self.need_kit.add("RequestSigner")
        self.rewrites["TWM004"] += 1
        signer = cst.Call(func=cst.Name("RequestSigner"), args=[cst.Arg(value=wallet)])
        return cst.Call(
            func=cst.Name("Dendrite"),
            args=[_kwarg("signer", signer)],
        )

    def _weights_call(self, updated: cst.Call) -> cst.BaseExpression:
        uids, weights = _arg(updated, "uids", 0), _arg(updated, "weights", 1)
        if uids is None or weights is None:
            return updated  # the scan keeps flagging it
        self.rewrites["TWM012"] += 1
        self.dropped_helpers = True
        return cst.Tuple(
            elements=[cst.Element(uids), cst.Element(weights)],
            lpar=[cst.LeftParen()],
            rpar=[cst.RightParen()],
        )

    # -------------------------------------------------- [metagraph.axons[uid] ...]

    def leave_ListComp(  # noqa: N802 - libcst API
        self, original_node: cst.ListComp, updated_node: cst.ListComp
    ) -> cst.BaseExpression:
        if not is_axons_list(original_node):
            return updated_node
        elt = updated_node.elt
        if not (
            isinstance(elt, cst.Subscript) and isinstance(elt.value, cst.Attribute)
        ):
            return updated_node  # pragma: no cover - is_axons_list checked the shape
        self.need_compat.add("axons_from")
        self.rewrites["TWM013"] += 1
        return cst.Call(
            func=cst.Name("axons_from"),
            args=[
                cst.Arg(value=elt.value.value),
                cst.Arg(value=updated_node.for_in.iter),
            ],
        )

    # -------------------------------------------------- "bt.metagraph.Metagraph"

    def visit_Annotation(self, _node: cst.Annotation) -> None:  # noqa: N802 - libcst API
        self._annotation_depth += 1

    def leave_Annotation(  # noqa: N802 - libcst API
        self, _original: cst.Annotation, updated_node: cst.Annotation
    ) -> cst.Annotation:
        self._annotation_depth -= 1
        return updated_node

    def leave_SimpleString(  # noqa: N802 - libcst API
        self, original_node: cst.SimpleString, updated_node: cst.SimpleString
    ) -> cst.SimpleString:
        if not self._annotation_depth or original_node.prefix:
            return updated_node
        value = original_node.evaluated_value
        if not isinstance(value, str):
            return updated_node  # pragma: no cover - a prefix-less string is str
        alias, _, path = value.partition(".")
        compat = _ANNOTATION_NAMES.get(path) if alias in self.bt else None
        if compat is None:
            return updated_node
        self.need_compat.add(compat)
        quote = original_node.quote
        return updated_node.with_changes(value=f"{quote}{compat}{quote}")

    # -------------------------------------------------- import statements

    def leave_ImportFrom(  # noqa: N802 - libcst API
        self, _original: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom | cst.RemovalSentinel:
        module = _dotted(updated_node.module) if updated_node.module else ""
        if isinstance(updated_node.names, cst.ImportStar) or not module:
            return updated_node
        if module == "bittensor":
            return self._move_names(updated_node, {"Synapse", "AxonInfo"}, "TWM001")
        if module == "base.validator" or module.endswith(".base.validator"):
            target = resolve_module(module, len(updated_node.relative), self.path)
            if self.custom_bases.get(target):
                return updated_node  # customised base: TWM026, by hand
            return self._swap_template_base(updated_node)
        return updated_node

    def _move_names(
        self, node: cst.ImportFrom, names: set[str], rule: str
    ) -> cst.ImportFrom | cst.RemovalSentinel:
        if isinstance(
            node.names, cst.ImportStar
        ):  # pragma: no cover - checked by caller
            return node
        keep = [a for a in node.names if _name_of(a) not in names]
        moved = [a for a in node.names if _name_of(a) in names]
        if not moved:
            return node
        for alias in moved:
            local = _local_of(alias)
            self.need_compat.add(
                _name_of(alias)
                if local == _name_of(alias)
                else f"{_name_of(alias)} as {local}"
            )
            self.rewrites["TWM021" if _name_of(alias) == "AxonInfo" else rule] += 1
        if not keep:
            return cst.RemoveFromParent()
        return node.with_changes(names=_strip_trailing_comma(keep))

    def _swap_template_base(
        self, node: cst.ImportFrom
    ) -> cst.ImportFrom | cst.RemovalSentinel:
        if isinstance(
            node.names, cst.ImportStar
        ):  # pragma: no cover - checked by caller
            return node
        base = [a for a in node.names if _name_of(a) == _TEMPLATE_BASE]
        if not base:
            return node
        (alias,) = base
        self.rewrites["TWM024"] += 1
        swapped = cst.ImportFrom(
            module=cst.Attribute(value=cst.Name("tensorwire"), attr=cst.Name("compat")),
            names=[
                cst.ImportAlias(
                    name=cst.Name(_ADAPTER),
                    asname=cst.AsName(name=cst.Name(_local_of(alias))),
                )
            ],
        )
        rest = [a for a in node.names if _name_of(a) != _TEMPLATE_BASE]
        if rest:  # keep the other names; the adapter import follows
            self.need_compat.add(f"{_ADAPTER} as {_local_of(alias)}")
            return node.with_changes(names=_strip_trailing_comma(rest))
        return swapped


def _strip_trailing_comma(aliases: Sequence[cst.ImportAlias]) -> list[cst.ImportAlias]:
    out = list(aliases)
    if out:
        out[-1] = out[-1].with_changes(comma=cst.MaybeSentinel.DEFAULT)
    return out


class _BtAliases(cst.CSTVisitor):
    def __init__(self) -> None:
        super().__init__()
        self.aliases: set[str] = set()

    def visit_Import(self, node: cst.Import) -> None:  # noqa: N802 - libcst API
        for alias in node.names:
            if _name_of(alias) == "bittensor":
                self.aliases.add(_local_of(alias))


# ---------------------------------------------------------------- import lines


def _import_line(code: str) -> cst.SimpleStatementLine:
    statement = cst.parse_statement(code)
    if not isinstance(statement, cst.SimpleStatementLine):  # pragma: no cover
        raise TypeError(code)
    return statement


def _existing_imports(module: cst.Module) -> set[str]:
    """``"logging"`` and ``"<module>:<name>[ as <alias>]"`` for top-level imports."""
    have: set[str] = set()
    for statement in module.body:
        if not isinstance(statement, cst.SimpleStatementLine):
            continue
        for small in statement.body:
            if isinstance(small, cst.Import):
                have.update(_name_of(a) for a in small.names if a.asname is None)
            elif isinstance(small, cst.ImportFrom) and not isinstance(
                small.names, cst.ImportStar
            ):
                source = _dotted(small.module) if small.module else ""
                for a in small.names:
                    name, local = _name_of(a), _local_of(a)
                    have.add(
                        f"{source}:{name}"
                        if name == local
                        else f"{source}:{name} as {local}"
                    )
    return have


def _new_imports(rw: _Rewriter, module: cst.Module) -> list[str]:
    have = _existing_imports(module)
    lines = [
        f"import {name}"
        for name, needed in (("asyncio", rw.need_asyncio), ("logging", rw.need_logging))
        if needed and name not in have
    ]
    for package, names in (
        ("tensorwire", rw.need_kit),
        ("tensorwire.compat", rw.need_compat),
    ):
        missing = sorted(n for n in names if f"{package}:{n}" not in have)
        if missing:
            lines.append(f"from {package} import {', '.join(missing)}")
    return lines


def _fix_imports(module: cst.Module, rw: _Rewriter) -> cst.Module:
    """Drop unused ``bittensor`` / weight-helper imports; add what the rewrites need."""
    used = _used_names(module)
    body = list(module.body)
    insert_at: int | None = None
    leading: Sequence[cst.EmptyLine] = ()
    out: list[cst.BaseStatement] = []
    for statement in body:
        if isinstance(statement, cst.SimpleStatementLine) and any(
            isinstance(s, (cst.Import, cst.ImportFrom)) for s in statement.body
        ):
            droppable = {"time"} if rw.rewrites["TWM027"] else set()
            new, touched = _prune(
                statement, rw.bt | droppable, used, rw.dropped_helpers
            )
            if touched and insert_at is None:
                insert_at = len(out) + (0 if new is None else 1)
                if new is None:
                    leading = statement.leading_lines
            if new is not None:
                out.append(new)
            continue
        out.append(statement)
    lines = _new_imports(rw, module.with_changes(body=out))
    if not lines:
        return module.with_changes(body=out)
    if insert_at is None:
        insert_at = _after_last_import(out)
    added = [_import_line(code) for code in lines]
    added[0] = added[0].with_changes(leading_lines=leading)
    return module.with_changes(body=[*out[:insert_at], *added, *out[insert_at:]])


def _after_last_import(body: Sequence[cst.BaseStatement]) -> int:
    position = 0
    for index, statement in enumerate(body):
        if isinstance(statement, cst.SimpleStatementLine) and any(
            isinstance(s, (cst.Import, cst.ImportFrom)) for s in statement.body
        ):
            position = index + 1
    return position


def _prune(
    statement: cst.SimpleStatementLine,
    bt: set[str],
    used: set[str],
    helpers_dropped: bool,
) -> tuple[cst.SimpleStatementLine | None, bool]:
    """``statement`` without unused bittensor / weight-helper imports.

    Returns (the statement or ``None`` if nothing is left, whether it was a
    bittensor-related import at all).
    """
    smalls: list[cst.BaseSmallStatement] = []
    touched = False
    for small in statement.body:
        if isinstance(small, cst.Import):
            names = list(small.names)
            keep = [
                a
                for a in names
                if not (_name_of(a) in ("bittensor", "time") and _local_of(a) in bt)
                or _local_of(a) in used
            ]
            touched |= len(keep) != len(names) or any(
                _name_of(a).startswith("bittensor") for a in names
            )
            if keep:
                smalls.append(small.with_changes(names=_strip_trailing_comma(keep)))
            continue
        if (
            isinstance(small, cst.ImportFrom)
            and helpers_dropped
            and not isinstance(small.names, cst.ImportStar)
        ):
            names = list(small.names)
            keep = [
                a
                for a in names
                if _name_of(a) not in _WEIGHT_HELPERS or _local_of(a) in used
            ]
            if len(keep) != len(names):
                touched = True
            if keep:
                smalls.append(small.with_changes(names=_strip_trailing_comma(keep)))
            continue
        if isinstance(small, cst.ImportFrom):
            module = (_dotted(small.module) if small.module else None) or ""
            touched |= bool(module) and (
                module == "bittensor"
                or module.startswith("bittensor.")
                or module.endswith("base.validator")
                or module == "tensorwire.compat"
            )
        smalls.append(small)
    if not smalls:
        return None, touched
    smalls[-1] = smalls[-1].with_changes(semicolon=cst.MaybeSentinel.DEFAULT)
    return statement.with_changes(body=smalls), touched


# ---------------------------------------------------------------- markers


class _Marker(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, marks: dict[int, list[str]], lines: Sequence[str]) -> None:
        super().__init__()
        self.marks = marks
        self.lines = lines
        self.placed: Counter[str] = Counter()
        self._targets: dict[int, list[str]] = {}

    def _comments_above(self, line: int) -> list[str]:
        """The comment lines directly above source line ``line`` (1-based).

        Read from the text, not the tree: above a module's first statement
        libcst keeps comments in ``Module.header``, not in ``leading_lines``.
        """
        found = []
        index = line - 2
        while index >= 0 and self.lines[index].lstrip().startswith("#"):
            found.append(self.lines[index].strip())
            index -= 1
        return found

    def _claim(self, node: cst.CSTNode, header_end: int) -> None:
        start = self.get_metadata(PositionProvider, node).start.line
        for line in range(start, header_end + 1):
            if line in self.marks:
                self._targets.setdefault(id(node), []).extend(self.marks.pop(line))

    def _header_end(self, node: cst.BaseCompoundStatement) -> int:
        """The last line of a compound statement's header (``if ...:``)."""
        start = self.get_metadata(PositionProvider, node).start.line
        body = node.body
        if isinstance(body, cst.IndentedBlock) and body.body:
            first = self.get_metadata(PositionProvider, body.body[0]).start.line
            return max(start, first - 1)
        return start

    def on_visit(self, node: cst.CSTNode) -> bool:
        if isinstance(node, cst.SimpleStatementLine):
            self._claim(node, self.get_metadata(PositionProvider, node).end.line)
        elif isinstance(node, cst.BaseCompoundStatement):
            self._claim(node, self._header_end(node))
        return True

    def on_leave(  # type: ignore[override]  # returns statements only
        self, original_node: cst.CSTNode, updated_node: cst.CSTNode
    ) -> cst.CSTNode:
        rules = self._targets.pop(id(original_node), None)
        if not rules or not isinstance(
            updated_node, (cst.SimpleStatementLine, cst.BaseCompoundStatement)
        ):
            return updated_node
        start = self.get_metadata(PositionProvider, original_node).start.line
        existing = self._comments_above(start)
        added = []
        for rule in dict.fromkeys(rules):
            text = f"{MARKER} {rule} {RULES[rule].replacement}"
            if any(c.startswith(f"{MARKER} {rule} ") for c in existing):
                continue
            added.append(cst.EmptyLine(comment=cst.Comment(text)))
            self.placed[rule] += 1
        if not added:
            return updated_node
        return updated_node.with_changes(
            leading_lines=[*updated_node.leading_lines, *added]
        )


# ---------------------------------------------------------------- entry points


def apply_source(
    source: str,
    path: str = "<string>",
    *,
    custom_bases: Mapping[str, list[str]] | None = None,
) -> FileResult:
    """``source`` after the rewrites and the ``TW-MIGRATE`` markers.

    ``custom_bases``: :func:`~tensorwire.migrate.scan.template_bases` of the
    repository (without it, a ``BaseValidatorNeuron`` import is swapped).
    Raises ``libcst.ParserSyntaxError`` for code that does not parse.
    """
    bases = custom_bases or {}
    module = cst.parse_module(source)
    aliases = _BtAliases()
    module.visit(aliases)
    rewriter = _Rewriter(aliases.aliases, path, bases)
    rewritten = MetadataWrapper(module).visit(rewriter)
    if rewriter.rewrites or rewriter.need_compat:
        rewritten = _fix_imports(rewritten, rewriter)
    code = rewritten.code
    findings, _ = scan_source(code, path, custom_bases=bases)
    marks: dict[int, list[str]] = {}
    for finding in findings:
        marks.setdefault(finding.line, []).append(finding.rule)
    marker = _Marker(marks, code.splitlines())
    marked = MetadataWrapper(cst.parse_module(code)).visit(marker)
    return FileResult(
        path=path,
        before=source,
        after=marked.code,
        rewrites=+rewriter.rewrites,
        marked=marker.placed,
    )


def plan_repo(root: Path | str) -> ApplyReport:
    """What ``apply`` would change under ``root`` (nothing is written)."""
    base = Path(root)
    if not base.is_dir():
        raise NotADirectoryError(str(base))
    report = ApplyReport(root=str(base))
    bases = template_bases(base)
    for path in python_files(base):
        rel = path.relative_to(base).as_posix()
        if path.is_symlink():
            continue  # never written through a link
        try:
            source = path.read_text(encoding="utf-8")
            report.files.append(apply_source(source, rel, custom_bases=bases))
        except (UnicodeDecodeError, OSError) as exc:
            report.parse_errors.append(f"{rel}: {type(exc).__name__}")
        except cst.ParserSyntaxError as exc:
            report.parse_errors.append(f"{rel}:{exc.raw_line}: syntax error")
    return report


def write_changes(report: ApplyReport) -> list[str]:
    """Write every changed file in place (atomically, keeping its mode)."""
    base = Path(report.root).resolve()
    written = []
    for result in report.changed:
        target = (base / result.path).resolve()
        if not target.is_relative_to(base) or target.is_symlink():
            raise ValueError(f"refusing to write outside the repository: {result.path}")
        mode = target.stat().st_mode
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
                out.write(result.after)
            Path(tmp).chmod(mode & 0o7777)
            Path(tmp).replace(target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        written.append(result.path)
    return written


def git_state(root: Path | str) -> GitState:
    """``clean``, ``dirty`` (uncommitted changes) or ``not_git``."""
    try:
        run = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],  # noqa: S607 - git from PATH
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "not_git"
    if run.returncode != 0:
        return "not_git"
    return "dirty" if run.stdout.strip() else "clean"
