"""``tensorwire migrate scan``: find everything a v10 subnet must change (spec 10b.4.1).

Static analysis with ``libcst`` (extra ``tensorwire[migrate]``): the team's
code is parsed, never imported or run. Every finding names a rule from
:mod:`tensorwire.migrate.rules`, a file, a line and the replacement.

The scan also reports whether the repository has the archived template's
shape (``template/base/neuron.py``, ``BaseMinerNeuron``,
``BaseValidatorNeuron``), and runs the security checks: Synapses with empty
or partial ``required_hash_fields``, blacklist functions that never check
registration, ``allow_non_registered=True`` and
``force_validator_permit=False`` (including argparse defaults).

Exit status of the command: 0 when every finding is ``auto`` (``migrate
apply`` can handle it), 1 otherwise (or when a file could not be parsed).

Importing this module needs ``libcst``; the CLI imports it lazily and tells
the user to install the extra when it is missing.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

import libcst as cst
from libcst.metadata import MetadataWrapper, ParentNodeProvider, PositionProvider

from tensorwire.migrate.rules import ATTRIBUTE_RULES, MODULE_RULES, RULES, V11_PUBLIC

__all__ = [
    "CONFIG_GROUPS",
    "LOG_LEVELS",
    "STOCK_NEURON_METHODS",
    "STOCK_VALIDATOR_METHODS",
    "Finding",
    "ScanReport",
    "is_axons_list",
    "is_metagraph_tensor_call",
    "python_files",
    "render",
    "scan_repo",
    "scan_source",
    "template_bases",
]

Format = Literal["text", "json", "md"]

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "build",
        "dist",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
    }
)
_MAX_FILE_BYTES = 2 * 1024 * 1024
_TEMPLATE_CLASSES = frozenset({"BaseMinerNeuron", "BaseValidatorNeuron"})
_WEIGHT_HELPERS = frozenset(
    {"process_weights_for_netuid", "convert_weights_and_uids_for_emit"}
)
_V10_SERVER_BASES = frozenset({"axon", "Axon", "dendrite", "Dendrite"})
#: ``bt.logging.<name>(...)`` -> the standard ``logging`` function (TWM007).
LOG_LEVELS: dict[str, str] = {
    "trace": "debug",
    "debug": "debug",
    "info": "info",
    "success": "info",
    "warning": "warning",
    "warn": "warning",
    "error": "error",
    "critical": "critical",
    "exception": "exception",
}
#: The archived template's ``BaseValidatorNeuron`` / ``BaseNeuron`` methods.
#: A base with more than these was customised (TWM026 instead of TWM024).
STOCK_VALIDATOR_METHODS = frozenset(
    {
        "add_args", "__init__", "serve_axon", "concurrent_forward", "run",
        "run_in_background_thread", "stop_run_thread", "__enter__", "__exit__",
        "set_weights", "resync_metagraph", "update_scores", "save_state",
        "load_state",
    }
)  # fmt: skip
STOCK_NEURON_METHODS = frozenset(
    {
        "check_config", "add_args", "config", "block", "__init__", "forward",
        "run", "sync", "check_registered", "should_sync_metagraph",
        "should_set_weights", "save_state", "load_state",
    }
)  # fmt: skip
#: ``"bt.<path>"`` string annotations that have a compat type (TWM028).
ANNOTATION_COMPAT: dict[str, str] = {
    "Synapse": "Synapse",
    "AxonInfo": "AxonInfo",
    "TerminalInfo": "TerminalInfo",
    "Metagraph": "Metagraph",
    "metagraph": "Metagraph",
    "metagraph.Metagraph": "Metagraph",
    "Config": "Config",
    "config": "Config",
}
#: ``bt.logging.<name>(...)`` set-up calls a bare statement may make (TWM032).
LOGGING_SETUP = frozenset(
    {
        "set_debug", "set_trace", "set_info", "set_warning", "set_default",
        "set_console", "set_config", "enable_debug", "enable_trace", "enable_info",
        "enable_warning", "enable_default", "enable_third_party_loggers",
        "disable_third_party_loggers", "on", "off",
    }
)  # fmt: skip
#: ``bt.<group>.add_args(parser)`` -> ``add_v10_args(parser, "<group>")`` (TWM031).
CONFIG_GROUPS: dict[str, str] = {
    "wallet": "wallet",
    "Wallet": "wallet",
    "subtensor": "subtensor",
    "Subtensor": "subtensor",
    "axon": "axon",
    "Axon": "axon",
    "logging": "logging",
}
#: Names v11 kept with a different API: v10-shaped uses are flagged.
_RENAMED_V10 = {"Wallet": "TWM014", "Metagraph": "TWM009", "Subtensor": "TWM008"}
_DOTTED_PATH = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+")
_IN_STRING = re.compile(r"(?<![\w.])(?:[\w.]+\.)?(bt|bittensor)\.(\w+)")
_REGISTRATION_HINTS = (
    "hotkeys",
    "is_hotkey_registered",
    "allow_non_registered",
    "validator_permit",
)


@dataclass(frozen=True, order=True)
class Finding:
    """One place that needs attention."""

    path: str
    line: int
    rule: str
    detail: str = ""
    snippet: str = ""

    @property
    def severity(self) -> str:
        """``auto``, ``manual`` or ``risk``."""
        return RULES[self.rule].severity


@dataclass
class ScanReport:
    """The result of scanning one repository."""

    root: str
    template_detected: bool = False
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        """0 when ``apply`` can handle everything, else 1."""
        if self.parse_errors:
            return 1
        return 0 if all(f.severity == "auto" for f in self.findings) else 1

    def counts(self) -> dict[str, int]:
        """Findings per severity."""
        out = {"auto": 0, "manual": 0, "risk": 0}
        for f in self.findings:
            out[f.severity] += 1
        return out


# ---------------------------------------------------------------- the visitor


def _dotted(node: cst.CSTNode) -> str | None:
    if isinstance(node, cst.Name):
        return str(node.value)
    if isinstance(node, cst.Attribute):
        inner = _dotted(node.value)
        return None if inner is None else f"{inner}.{node.attr.value}"
    return None


def _strings(node: cst.BaseExpression) -> list[str] | None:
    """String elements of a tuple/list literal (``None`` if not such a literal)."""
    if isinstance(node, (cst.Tuple, cst.List)):
        values: list[str] = []
        for element in node.elements:
            value = element.value
            if not isinstance(value, cst.SimpleString):
                return None
            evaluated = value.evaluated_value
            values.append(
                evaluated if isinstance(evaluated, str) else evaluated.decode()
            )
        return values
    return None


def _hash_list(value: cst.BaseExpression) -> list[str] | None:
    """``required_hash_fields`` from a literal or a ``Field(default=[...])`` call."""
    if isinstance(value, cst.Call):
        for arg in value.args:
            keyword = arg.keyword.value if arg.keyword is not None else None
            if keyword in (None, "default"):
                return _strings(arg.value)
        return None
    return _strings(value)


def _synapse_shape(
    module: cst.Module, node: cst.ClassDef
) -> tuple[list[tuple[str, bool]], list[str] | None]:
    """A Synapse class's fields ``(name, has_default)`` and its hash field list."""
    fields: list[tuple[str, bool]] = []
    hash_fields: list[str] | None = None
    for stmt in node.body.body:
        if not isinstance(stmt, cst.SimpleStatementLine):
            continue
        for small in stmt.body:
            if isinstance(small, cst.AnnAssign) and isinstance(small.target, cst.Name):
                target = small.target.value
                if target == "required_hash_fields":
                    if small.value is not None:
                        hash_fields = _hash_list(small.value)
                elif "ClassVar" not in module.code_for_node(
                    small.annotation.annotation
                ):
                    fields.append((target, small.value is not None))
            elif isinstance(small, cst.Assign) and any(
                isinstance(t.target, cst.Name)
                and t.target.value == "required_hash_fields"
                for t in small.targets
            ):
                hash_fields = _hash_list(small.value)
    return fields, hash_fields


def in_coroutine(visitor: cst.MetadataDependent, node: cst.CSTNode) -> bool:
    """Whether ``node``'s nearest enclosing function is ``async def``."""
    current: cst.CSTNode | None = node
    while current is not None:
        current = visitor.get_metadata(ParentNodeProvider, current, None)
        if isinstance(current, cst.Lambda):
            return False
        if isinstance(current, cst.FunctionDef):
            return current.asynchronous is not None
    return False


def resolve_module(module: str, level: int, path: str) -> str:
    """The absolute dotted name of ``from <level dots><module> import ...``
    written in file ``path`` (relative to the repository root)."""
    if level == 0:
        return module
    package = path.removesuffix(".py").split("/")[:-1]
    base = package[: len(package) - (level - 1)] if level > 1 else package
    return ".".join([*base, module] if module else base)


def _class(module: cst.Module, name: str) -> cst.ClassDef | None:
    for statement in module.body:
        if isinstance(statement, cst.ClassDef) and statement.name.value == name:
            return statement
    return None


def _methods(module: cst.Module, name: str) -> set[str]:
    node = _class(module, name)
    if node is None:
        return set()
    return {s.name.value for s in node.body.body if isinstance(s, cst.FunctionDef)}


def template_bases(root: Path) -> dict[str, list[str] | None]:
    """``<package>.base.validator`` modules defining ``BaseValidatorNeuron``,
    mapped to the methods they add beyond the archived template (with their
    sibling ``neuron.py``'s ``BaseNeuron``). An empty list: a stock base.
    ``None``: already ported (it subclasses ``TemplateValidatorAdapter``)."""
    found: dict[str, list[str] | None] = {}
    for path in root.glob("**/base/validator.py"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts) or path.is_symlink():
            continue
        try:
            module = cst.parse_module(path.read_text(encoding="utf-8"))
            neuron_path = path.with_name("neuron.py")
            neuron = (
                cst.parse_module(neuron_path.read_text(encoding="utf-8"))
                if neuron_path.is_file() and not neuron_path.is_symlink()
                else None
            )
        except (OSError, UnicodeDecodeError, cst.ParserSyntaxError):
            continue
        node = _class(module, "BaseValidatorNeuron")
        if node is None:
            continue
        name = ".".join(rel.with_suffix("").parts)
        if any(
            (_dotted(b.value) or "").endswith("TemplateValidatorAdapter")
            for b in node.bases
        ):
            found[name] = None
            continue
        extras = _methods(module, "BaseValidatorNeuron") - STOCK_VALIDATOR_METHODS
        if neuron is not None:
            extras |= _methods(neuron, "BaseNeuron") - STOCK_NEURON_METHODS
        found[name] = sorted(extras)
    return found


def is_metagraph_tensor_call(node: cst.Call) -> bool:
    """``<x>.metagraph.<v>.item()`` / ``.tolist()``, also on ``<v>[i]``."""
    func = node.func
    if node.args or not (
        isinstance(func, cst.Attribute) and func.attr.value in ("item", "tolist")
    ):
        return False
    receiver = func.value
    base = receiver.value if isinstance(receiver, cst.Subscript) else receiver
    dotted = _dotted(base) or ""
    return ".metagraph." in f".{dotted}." and not dotted.endswith("metagraph")


def is_axons_list(node: cst.ListComp) -> bool:
    """``[<x>.metagraph.axons[uid] for uid in <uids>]`` (one ``for``, no ``if``)."""
    comp = node.for_in
    elt = node.elt
    if comp.inner_for_in is not None or comp.ifs or comp.asynchronous is not None:
        return False
    if not (isinstance(elt, cst.Subscript) and isinstance(comp.target, cst.Name)):
        return False
    owner = _dotted(elt.value) or ""
    if not (owner == "metagraph.axons" or owner.endswith(".metagraph.axons")):
        return False
    if len(elt.slice) != 1 or not isinstance(elt.slice[0].slice, cst.Index):
        return False
    index = elt.slice[0].slice.value
    return isinstance(index, cst.Name) and index.value == comp.target.value


def _is_bool(node: cst.BaseExpression, value: bool) -> bool:
    return isinstance(node, cst.Name) and node.value == ("True" if value else "False")


class _Visitor(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider, ParentNodeProvider)

    def __init__(
        self,
        path: str,
        module: cst.Module,
        lines: Sequence[str],
        custom_bases: Mapping[str, list[str] | None],
    ) -> None:
        super().__init__()
        self.path = path
        self.custom_bases = custom_bases
        self.module = module
        self.lines = lines
        self.bt_aliases: set[str] = set()
        self.findings: list[Finding] = []
        self._annotation_depth = 0
        self.template = False

    def add(self, node: cst.CSTNode, rule: str, detail: str = "") -> None:
        line = self.get_metadata(PositionProvider, node).start.line
        snippet = self.lines[line - 1].strip()[:160] if line <= len(self.lines) else ""
        self.findings.append(Finding(self.path, line, rule, detail, snippet))

    def module_rule(self, module: str) -> str | None:
        best = None
        for prefix, rule in MODULE_RULES.items():
            if (module == prefix or module.startswith(prefix + ".")) and (
                best is None or len(prefix) > len(best[0])
            ):
                best = (prefix, rule)
        return None if best is None else best[1]

    def visit_Import(self, node: cst.Import) -> None:  # noqa: N802 - libcst API
        for alias in node.names:
            name = _dotted(alias.name) or ""
            if name == "bittensor_wallet" or name.startswith("bittensor_wallet."):
                self.add(node, self.module_rule(name) or "TWM014", f"import {name}")
                continue
            if name != "bittensor" and not name.startswith("bittensor."):
                continue
            asname = alias.asname.name if alias.asname is not None else None
            local = asname.value if isinstance(asname, cst.Name) else name.split(".")[0]
            self.bt_aliases.add(local)
            rule = self.module_rule(name)
            if rule:
                self.add(node, rule, f"import {name}")

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:  # noqa: N802 - libcst API
        self.check_template_import(node)
        module = _dotted(node.module) if node.module is not None else None
        if module is not None and (
            module == "bittensor_wallet" or module.startswith("bittensor_wallet.")
        ):
            self.add(
                node, self.module_rule(module) or "TWM014", f"from {module} import ..."
            )
            return
        if module is None or not (
            module == "bittensor" or module.startswith("bittensor.")
        ):
            return
        if module != "bittensor":
            rule = self.module_rule(module)
            if rule:
                self.add(node, rule, f"from {module} import ...")
            return
        if isinstance(node.names, cst.ImportStar):
            self.add(node, "TWM018", "from bittensor import *")
            return
        for alias in node.names:
            name = _dotted(alias.name) or ""
            rule = "TWM025" if name == "logging" else ATTRIBUTE_RULES.get(name)
            if rule is None and name in ("Wallet", "Metagraph"):
                rule = _RENAMED_V10[name]
            elif rule is None and name not in V11_PUBLIC:
                rule = "TWM030"
            if rule:
                self.add(node, rule, f"from bittensor import {name}")

    def check_template_import(self, node: cst.ImportFrom) -> None:
        module = _dotted(node.module) if node.module is not None else ""
        if not module or not (
            module == "base.validator" or module.endswith(".base.validator")
        ):
            return
        if isinstance(node.names, cst.ImportStar):
            return
        if any(_dotted(a.name) == "BaseValidatorNeuron" for a in node.names):
            target = resolve_module(module, len(node.relative), self.path)
            extras = self.custom_bases.get(target, [])
            if extras is None:
                return  # already on TemplateValidatorAdapter
            if extras:
                self.add(node, "TWM026", f"{target} adds: {', '.join(extras)}")
            else:
                self.add(node, "TWM024", f"from {module} import BaseValidatorNeuron")

    def visit_Attribute(self, node: cst.Attribute) -> None:  # noqa: N802 - libcst API
        if not (
            isinstance(node.value, cst.Name) and node.value.value in self.bt_aliases
        ):
            return
        attr = node.attr.value
        full = self.full_name(node)
        if self.v10_config_call(node, attr, full):
            self.add(node, "TWM031", full)
            return
        if self.logging_setup_statement(node, attr, full):
            self.add(node, "TWM032", full)
            return
        if self.v10_wallet_call(node, attr):
            self.add(node, "TWM033", full)
            return
        rule = ATTRIBUTE_RULES.get(attr)
        if rule is None:
            rule = self.v10_shaped(node, attr, full)
            if rule:
                self.add(node, rule, full)
            return
        if "weight_utils" in full:
            rule = "TWM012"
        elif (
            full.rsplit(".", 1)[-1] in ("add_args", "check_config") and rule != "TWM007"
        ):
            rule = "TWM006"  # bt.axon.add_args(parser), bt.wallet.add_args(...)
        elif rule == "TWM007" and (
            full.rsplit(".", 1)[-1] not in LOG_LEVELS or not self.is_called(node)
        ):
            rule = "TWM025"  # bt.logging.set_config(...), a monkeypatch, ...
        self.add(node, rule, full)

    def v10_config_call(self, node: cst.Attribute, attr: str, full: str) -> bool:
        """``bt.<group>.add_args(p)``, ``bt.config(p)``, or a bare
        ``bt.<group>.check_config(c)`` statement: what ``apply`` rewrites (TWM031)."""
        if not self.is_called(node):
            return False
        parts = full.split(".")
        if len(parts) == 2 and attr in ("config", "Config"):
            return True
        if len(parts) != 3 or attr not in CONFIG_GROUPS:
            return False
        if parts[2] == "add_args":
            call = self.get_metadata(ParentNodeProvider, self.outermost(node), None)
            return isinstance(call, cst.Call) and len(call.args) == 1
        if parts[2] == "check_config":
            call = self.get_metadata(ParentNodeProvider, self.outermost(node), None)
            return call is not None and isinstance(
                self.get_metadata(ParentNodeProvider, call, None), cst.Expr
            )
        return False

    def _bare_call(self, node: cst.Attribute) -> cst.Call | None:
        """The call ``node`` makes when it is a whole expression statement."""
        whole = self.outermost(node)
        call = self.get_metadata(ParentNodeProvider, whole, None)
        if not (isinstance(call, cst.Call) and call.func is whole):
            return None
        parent = self.get_metadata(ParentNodeProvider, call, None)
        return call if isinstance(parent, cst.Expr) else None

    def logging_setup_statement(
        self, node: cst.Attribute, attr: str, full: str
    ) -> bool:
        """``bt.logging(...)`` / ``bt.logging.set_debug(...)`` as a bare statement."""
        if attr != "logging":
            return False
        parts = full.split(".")
        if len(parts) == 2:
            return self._bare_call(node) is not None
        return (
            len(parts) == 3
            and parts[2] in LOGGING_SETUP
            and (self._bare_call(node) is not None)
        )

    def v10_wallet_call(self, node: cst.Attribute, attr: str) -> bool:
        """``bt.Wallet(config=c)`` / ``bt.wallet(config=c)``: TWM033."""
        if attr not in ("Wallet", "wallet"):
            return False
        call = self.get_metadata(ParentNodeProvider, node, None)
        return (
            isinstance(call, cst.Call)
            and call.func is node
            and len(call.args) == 1
            and call.args[0].keyword is not None
            and call.args[0].keyword.value == "config"
        )

    def v10_shaped(self, node: cst.Attribute, attr: str, full: str) -> str | None:
        """The rule for a ``bt.<name>`` v11 also has (or none): only v10-shaped
        uses of ``Wallet`` / ``Metagraph`` / ``Subtensor``, and the catch-all."""
        if attr not in V11_PUBLIC:
            return "TWM030"
        if attr not in _RENAMED_V10:
            return None
        if full.rsplit(".", 1)[-1] in ("add_args", "check_config", "config"):
            return "TWM006"
        if attr == "Wallet" and not self._annotation_depth:
            call = self.get_metadata(ParentNodeProvider, node, None)
            if (
                isinstance(call, cst.Call)
                and call.func is node
                and all(
                    a.keyword is not None
                    and a.keyword.value in ("name", "hotkey", "path")
                    for a in call.args
                )
            ):
                return None  # bt.Wallet(name=..., hotkey=..., path=...): v11
        if attr != "Subtensor" or self._annotation_depth:
            return _RENAMED_V10[attr]
        parent = self.get_metadata(ParentNodeProvider, node, None)
        if isinstance(parent, cst.Call) and any(
            a.keyword is not None and a.keyword.value == "config" for a in parent.args
        ):
            return "TWM008"  # bt.Subtensor(config=...): v10's constructor
        return None  # bt.Subtensor("test"): v11

    def outermost(self, node: cst.Attribute) -> cst.Attribute:
        current = node
        while True:
            parent = self.get_metadata(ParentNodeProvider, current, None)
            if isinstance(parent, cst.Attribute) and parent.value is current:
                current = parent
            else:
                return current

    def is_called(self, node: cst.Attribute) -> bool:
        whole = self.outermost(node)
        parent = self.get_metadata(ParentNodeProvider, whole, None)
        return isinstance(parent, cst.Call) and parent.func is whole

    def visit_Annotation(self, _node: cst.Annotation) -> None:  # noqa: N802 - libcst API
        self._annotation_depth += 1

    def leave_Annotation(self, _node: cst.Annotation) -> None:  # noqa: N802 - libcst API
        self._annotation_depth -= 1

    def visit_SimpleString(self, node: cst.SimpleString) -> None:  # noqa: N802 - libcst API
        value = node.evaluated_value
        if not isinstance(value, str) or node.prefix:
            return
        if self._annotation_depth:
            alias, _, path = value.partition(".")
            if alias not in self.bt_aliases:
                return
            if path in ANNOTATION_COMPAT:
                self.add(node, "TWM028", value)
                return
            head = path.split(".")[0]
            rule = ATTRIBUTE_RULES.get(head) or _RENAMED_V10.get(head)
            if rule is None and head not in V11_PUBLIC:
                rule = "TWM030"
            if rule:
                self.add(node, rule, value)
            return
        if isinstance(self.get_metadata(ParentNodeProvider, node, None), cst.Expr):
            return  # a docstring or a bare string statement
        if not _DOTTED_PATH.fullmatch(value):
            return  # prose, not a name (mock.patch targets are dotted paths)
        for match in _IN_STRING.finditer(value):
            if match.group(2) in ATTRIBUTE_RULES:
                self.add(node, "TWM029", match.group(0)[:80])
                return

    def full_name(self, node: cst.Attribute) -> str:
        return _dotted(self.outermost(node)) or ""

    def visit_Call(self, node: cst.Call) -> None:  # noqa: N802 - libcst API
        func = node.func
        name = _dotted(func) or ""
        last = name.rsplit(".", 1)[-1]
        receiver = name.rsplit(".", 1)[0].lower() if "." in name else ""
        if name == "time.sleep" and in_coroutine(self, node):
            self.add(node, "TWM027", name)
        elif last in _WEIGHT_HELPERS:
            self.add(node, "TWM012", last)
        elif last == "set_weights" and "subtensor" in receiver:
            self.add(node, "TWM010", name)
        elif last == "serve_axon" and "subtensor" in receiver:
            self.add(node, "TWM011", name)
        elif last == "sync" and receiver.endswith("metagraph"):
            self.add(node, "TWM009", name)
        elif last == "add_argument":
            self.check_add_argument(node)
        elif is_metagraph_tensor_call(node):
            self.add(node, "TWM023", self.module.code_for_node(node.func))
        self.check_keywords(node, last)

    def check_keywords(self, node: cst.Call, last: str) -> None:
        for arg in node.args:
            keyword = arg.keyword.value if arg.keyword is not None else None
            is_none = isinstance(arg.value, cst.Name) and arg.value.value == "None"
            if keyword == "verify_fn" and last == "attach" and not is_none:
                self.add(node, "TWM020", "attach(verify_fn=...)")
            elif keyword == "allow_non_registered" and _is_bool(arg.value, True):
                self.add(node, "TWM102", "allow_non_registered=True")
            elif keyword == "force_validator_permit" and _is_bool(arg.value, False):
                self.add(node, "TWM103", "force_validator_permit=False")

    def check_add_argument(self, node: cst.Call) -> None:
        if not node.args or not isinstance(node.args[0].value, cst.SimpleString):
            return
        flag = str(node.args[0].value.evaluated_value)
        kw = {a.keyword.value: a.value for a in node.args if a.keyword is not None}
        default = kw.get("default")
        action = kw.get("action")
        store_true = (
            isinstance(action, cst.SimpleString)
            and action.evaluated_value == "store_true"
        )
        if flag.endswith("allow_non_registered") and default is not None:
            if _is_bool(default, True):
                self.add(node, "TWM102", f"{flag} defaults to True")
        elif flag.endswith("force_validator_permit"):
            off = (default is not None and _is_bool(default, False)) or (
                default is None and store_true
            )
            if off:
                self.add(node, "TWM103", f"{flag} defaults to False")

    def visit_Assign(self, node: cst.Assign) -> None:  # noqa: N802 - libcst API
        for target in node.targets:
            name = _dotted(target.target) or ""
            if name.endswith("allow_non_registered") and _is_bool(node.value, True):
                self.add(node, "TWM102", f"{name} = True")
            elif name.endswith("force_validator_permit") and _is_bool(
                node.value, False
            ):
                self.add(node, "TWM103", f"{name} = False")

    def visit_ListComp(self, node: cst.ListComp) -> None:  # noqa: N802 - libcst API
        if is_axons_list(node):
            self.add(node, "TWM013", self.module.code_for_node(node))

    def visit_ClassDef(self, node: cst.ClassDef) -> None:  # noqa: N802 - libcst API
        if node.name.value in _TEMPLATE_CLASSES:
            self.template = True
        for base in node.bases:
            name = _dotted(base.value) or ""
            if name in _TEMPLATE_CLASSES:
                self.template = True
            head, _, tail = name.rpartition(".")
            if head in self.bt_aliases and tail in _V10_SERVER_BASES:
                self.add(node, "TWM019", f"class {node.name.value}({name})")
            if tail in ("Synapse", "StreamingSynapse"):
                self.check_synapse(node)

    def check_synapse(self, node: cst.ClassDef) -> None:
        fields, hash_fields = _synapse_shape(self.module, node)
        if not fields:
            return
        name = node.name.value
        if not hash_fields:
            self.add(node, "TWM100", f"{name}: no required_hash_fields")
            return
        missing = [
            f for f, has_default in fields if not has_default and f not in hash_fields
        ]
        if missing:
            self.add(
                node,
                "TWM101",
                f"{name}: not in required_hash_fields: {', '.join(missing)}",
            )

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:  # noqa: N802 - libcst API
        if "blacklist" not in node.name.value.lower():
            return
        body = self.module.code_for_node(node.body)
        if not any(hint in body for hint in _REGISTRATION_HINTS):
            self.add(node, "TWM104", f"{node.name.value}() never checks registration")


# ---------------------------------------------------------------- scanning


def scan_source(
    source: str,
    path: str = "<string>",
    *,
    custom_bases: Mapping[str, list[str] | None] | None = None,
) -> tuple[list[Finding], bool]:
    """Scan one file's source. Returns (findings, template classes seen).

    ``custom_bases`` is :func:`template_bases` of the repository (without
    it, every ``BaseValidatorNeuron`` import counts as the stock template).
    Raises ``libcst.ParserSyntaxError`` for code that does not parse.
    """
    module = cst.parse_module(source)
    wrapper = MetadataWrapper(module)
    visitor = _Visitor(path, wrapper.module, source.splitlines(), custom_bases or {})
    wrapper.visit(visitor)
    findings = sorted(set(visitor.findings))
    return findings, bool(visitor.template)


def python_files(root: Path) -> Iterator[Path]:
    """Python files under ``root``, skipping venvs, caches and VCS dirs, never
    following a symlink out of the repository."""
    real_root = root.resolve()
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs if d not in _SKIP_DIRS and not d.endswith(".egg-info")
        )
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = Path(current) / name
            if path.is_symlink() and not path.resolve().is_relative_to(real_root):
                continue  # never read outside the repository
            yield path


def scan_repo(root: Path | str) -> ScanReport:
    """Scan every Python file under ``root`` (skipping venvs, caches, VCS dirs)."""
    base = Path(root)
    if not base.is_dir():
        raise NotADirectoryError(str(base))
    report = ScanReport(root=str(base))
    report.template_detected = (base / "template" / "base" / "neuron.py").is_file()
    bases = template_bases(base)
    for path in python_files(base):
        rel = path.relative_to(base).as_posix()
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                report.parse_errors.append(f"{rel}: skipped (larger than 2 MiB)")
                continue
            source = path.read_text(encoding="utf-8")
            findings, template = scan_source(source, rel, custom_bases=bases)
        except (UnicodeDecodeError, OSError) as exc:
            report.parse_errors.append(f"{rel}: {type(exc).__name__}")
            continue
        except cst.ParserSyntaxError as exc:
            report.parse_errors.append(f"{rel}:{exc.raw_line}: syntax error")
            continue
        except Exception as exc:  # noqa: BLE001 - one file must not stop the others
            report.parse_errors.append(
                f"{rel}: not scanned, internal error ({type(exc).__name__}: {exc}); "
                "please report it"
            )
            continue
        report.files_scanned += 1
        report.findings.extend(findings)
        report.template_detected |= template
    report.findings.sort()
    return report


# ---------------------------------------------------------------- output


def render(report: ScanReport, fmt: Format = "text") -> str:
    """The report as ``text``, ``json`` or ``md`` (Markdown)."""
    if fmt == "json":
        return _json(report)
    if fmt == "md":
        return _markdown(report)
    return _text(report)


def _json(report: ScanReport) -> str:
    payload = {
        "root": report.root,
        "template_detected": report.template_detected,
        "files_scanned": report.files_scanned,
        "counts": report.counts(),
        "exit_code": report.exit_code,
        "parse_errors": report.parse_errors,
        "findings": [
            {
                **asdict(f),
                "severity": f.severity,
                "title": RULES[f.rule].title,
                "replacement": RULES[f.rule].replacement,
                "doc": RULES[f.rule].doc,
            }
            for f in report.findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _summary(report: ScanReport) -> list[str]:
    c = report.counts()
    lines = []
    if report.template_detected:
        lines.append(
            "Template shape detected (template/base/neuron.py, BaseMinerNeuron / "
            "BaseValidatorNeuron): follow docs/migration-from-v10.md."
        )
    lines.append(
        f"{report.files_scanned} files scanned: {len(report.findings)} findings "
        f"({c['auto']} auto, {c['manual']} manual, {c['risk']} risk)."
    )
    return lines


def _text(report: ScanReport) -> str:
    lines = _summary(report)
    for f in report.findings:
        rule = RULES[f.rule]
        lines.append(f"{f.path}:{f.line}: {f.rule} [{rule.severity}] {rule.title}")
        if f.detail:
            lines.append(f"    found: {f.detail}")
        lines.append(f"    fix:   {rule.replacement}")
    lines.extend(f"parse error: {e}" for e in report.parse_errors)
    return "\n".join(lines) + "\n"


def _markdown(report: ScanReport) -> str:
    lines = ["# TensorWire migration scan", "", *_summary(report), ""]
    if report.findings:
        lines += [
            "| File | Line | Rule | Severity | Found | Fix |",
            "|---|---|---|---|---|---|",
        ]
        for f in report.findings:
            rule = RULES[f.rule]
            cells = [
                f"`{f.path}`",
                str(f.line),
                f"[{f.rule}]({rule.doc})",
                rule.severity,
                f.detail.replace("|", "\\|"),
                rule.replacement.replace("|", "\\|"),
            ]
            lines.append("| " + " | ".join(cells) + " |")
    if report.parse_errors:
        lines += ["", "## Parse errors", ""] + [f"- {e}" for e in report.parse_errors]
    return "\n".join(lines) + "\n"
