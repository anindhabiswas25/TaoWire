"""The customised-template-base swap of ``migrate apply`` (TWM026, spec 10b.4, D18).

A template-derived subnet often keeps its own copy of the template's bases
(``<pkg>/base/neuron.py``, ``miner.py``, ``validator.py``) with its own
methods added. ``apply`` puts those classes on the kit's adapters and keeps
every method the subnet wrote:

- ``BaseMinerNeuron(BaseNeuron)`` -> ``BaseMinerNeuron(BaseNeuron,
  TemplateMinerAdapter)``; ``BaseValidatorNeuron(BaseNeuron)`` ->
  ``BaseValidatorNeuron(BaseNeuron, TemplateValidatorAdapter)``.
- The methods the kit runs now are removed: the run loops and background
  threads (``run``, ``run_in_background_thread``, ``stop_run_thread``,
  ``__enter__``, ``__exit__``), ``serve_axon`` and ``set_weights`` (the
  validator's), and ``BaseNeuron.run`` (an abstract method that would hide
  the adapter's). A ``# TW-MIGRATE: TWM026`` line lists them, so a person
  can move any custom code they held.
- In ``__init__``: ``**kit_parts`` is passed through to the adapter (tests
  inject ``FakeChain`` this way), ``BaseNeuron.__init__`` calls
  ``super().__init__()`` first, and the statements that built what the kit
  now owns are removed: assignments to ``self.wallet``, ``self.subtensor``,
  ``self.metagraph``, ``self.dendrite``, ``self.axon``, ``self.uid``,
  ``self.loop`` and ``self.config``, the template's config merge
  (``base_config = copy.deepcopy(...config())``, ``self.config.merge``), and
  ``bt.logging(...)`` set-up calls. Everything else stays, in order.
- Class-level annotations of those attributes (``wallet: "bt.wallet"``) go.

The adapters (:mod:`tensorwire.compat.neuron`) give the rest of the template
surface (``self.wallet`` with the hotkey only, ``self.subtensor`` reads,
``sync()``, ``check_registered()``, ...), so the kept methods run as they
are. ``apply`` swaps a package only when all its bases have the template's
shape (:func:`swappable_packages`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import libcst as cst

__all__ = [
    "ADAPTERS",
    "CLASSES",
    "OWNED_ATTRIBUTES",
    "REMOVED_METHODS",
    "SwapResult",
    "role_of",
    "swap_base",
    "swappable_packages",
]

#: Base file -> the template class it defines.
CLASSES = {
    "neuron": "BaseNeuron",
    "miner": "BaseMinerNeuron",
    "validator": "BaseValidatorNeuron",
}
#: Base file -> the adapter its class is put on.
ADAPTERS = {"miner": "TemplateMinerAdapter", "validator": "TemplateValidatorAdapter"}
_LOOP = ("run", "run_in_background_thread", "stop_run_thread", "__enter__", "__exit__")
#: Methods the kit runs now, per base file.
REMOVED_METHODS = {
    "neuron": ("run",),
    "miner": _LOOP,
    "validator": ("serve_axon", *_LOOP, "set_weights"),
}
#: ``self.<name> = ...`` statements in ``__init__`` that ``apply`` removes.
OWNED_ATTRIBUTES = frozenset(
    {"wallet", "subtensor", "metagraph", "dendrite", "axon", "uid", "loop", "config"}
)
_KIT_PARTS = "kit_parts"


@dataclass
class SwapResult:
    """What :func:`swap_base` did to one file."""

    module: cst.Module
    swapped: bool = False
    removed_methods: list[str] = field(default_factory=list)
    removed_statements: int = 0
    adapter: str | None = None


def role_of(module_name: str) -> tuple[str, str] | None:
    """``("<pkg>.base", "miner")`` for ``<pkg>.base.miner``, else ``None``."""
    package, _, leaf = module_name.rpartition(".")
    if leaf in CLASSES and (package == "base" or package.endswith(".base")):
        return package, leaf
    return None


def _dotted(node: cst.CSTNode) -> str | None:
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        head = _dotted(node.value)
        return None if head is None else f"{head}.{node.attr.value}"
    return None


def _class(module: cst.Module, name: str) -> cst.ClassDef | None:
    for statement in module.body:
        if isinstance(statement, cst.ClassDef) and statement.name.value == name:
            return statement
    return None


def _base_names(node: cst.ClassDef) -> list[str]:
    return [_dotted(arg.value) or "" for arg in node.bases]


def swappable_packages(root: Path, packages: Sequence[str]) -> set[str]:
    """The ``<pkg>.base`` packages whose three bases have the template's shape.

    ``BaseNeuron`` in ``neuron.py``; ``BaseMinerNeuron`` and
    ``BaseValidatorNeuron`` subclassing it (and nothing else) in
    ``miner.py`` / ``validator.py``. Anything else is left for a person
    (the ``TWM026`` marker stays).
    """
    ok: set[str] = set()
    for package in packages:
        folder = root.joinpath(*package.split("."))
        shapes: dict[str, cst.ClassDef] = {}
        try:
            for role, name in CLASSES.items():
                path = folder / f"{role}.py"
                if not path.is_file() or path.is_symlink():
                    break
                node = _class(cst.parse_module(path.read_text(encoding="utf-8")), name)
                if node is None:
                    break
                shapes[role] = node
        except (OSError, UnicodeDecodeError, cst.ParserSyntaxError):
            continue
        if len(shapes) != len(CLASSES):
            continue
        if all(_base_names(shapes[r]) == ["BaseNeuron"] for r in ADAPTERS):
            ok.add(package)
    return ok


# ---------------------------------------------------------------- statements


def _target_attr(target: cst.BaseExpression) -> str | None:
    if (
        isinstance(target, cst.Attribute)
        and isinstance(target.value, cst.Name)
        and target.value.value == "self"
    ):
        return target.attr.value
    return None


class _InitCleaner:
    """Removes the plumbing statements of the template's ``__init__``."""

    def __init__(self, bt_aliases: set[str], module: cst.Module) -> None:
        self.bt = bt_aliases
        self.module = module
        self.removed = 0

    def _owned_assignment(self, small: cst.BaseSmallStatement) -> bool:
        if isinstance(small, cst.Assign):
            targets = [t.target for t in small.targets]
            if any(_target_attr(t) in OWNED_ATTRIBUTES for t in targets):
                return True
            value = small.value
            return (
                len(targets) == 1
                and isinstance(targets[0], cst.Name)
                and isinstance(value, cst.Call)
                and _dotted(value.func) == "copy.deepcopy"
                and ".config()" in self.module.code_for_node(value)
            )
        if isinstance(small, cst.AnnAssign):
            return _target_attr(small.target) in OWNED_ATTRIBUTES
        return False

    def _setup_call(self, small: cst.BaseSmallStatement) -> bool:
        if not (isinstance(small, cst.Expr) and isinstance(small.value, cst.Call)):
            return False
        name = _dotted(small.value.func) or ""
        if name == "self.config.merge":
            return True
        head, _, rest = name.partition(".")
        return head in self.bt and (
            rest == "logging" or rest in ("logging.set_config", "logging.check_config")
        )

    def _drop(self, small: cst.BaseSmallStatement) -> bool:
        return self._owned_assignment(small) or self._setup_call(small)

    def block(self, statements: Sequence[cst.BaseStatement]) -> list[cst.BaseStatement]:
        out: list[cst.BaseStatement] = []
        for statement in statements:
            if isinstance(statement, cst.SimpleStatementLine):
                kept = [s for s in statement.body if not self._drop(s)]
                self.removed += len(statement.body) - len(kept)
                if kept:
                    out.append(statement.with_changes(body=_no_trailing_semi(kept)))
                continue
            if isinstance(statement, cst.BaseCompoundStatement):
                out.append(self._compound(statement))
                continue
            out.append(statement)  # pragma: no cover - every statement is one of them
        return out

    def _suite(self, suite: cst.BaseSuite) -> cst.BaseSuite:
        if isinstance(suite, cst.IndentedBlock):
            body = self.block(suite.body)
            return suite.with_changes(body=body or [_pass()])
        return suite  # a one-line suite ("if x: y"): left as written

    def _compound(self, node: cst.BaseCompoundStatement) -> cst.BaseCompoundStatement:
        changes: dict[str, object] = {"body": self._suite(node.body)}
        orelse = getattr(node, "orelse", None)
        if orelse is not None:
            changes["orelse"] = orelse.with_changes(body=self._suite(orelse.body))
        handlers = getattr(node, "handlers", None)
        if handlers:
            changes["handlers"] = [
                h.with_changes(body=self._suite(h.body)) for h in handlers
            ]
        final = getattr(node, "finalbody", None)
        if final is not None:
            changes["finalbody"] = final.with_changes(body=self._suite(final.body))
        return node.with_changes(**changes)


def _pass() -> cst.SimpleStatementLine:
    return cst.SimpleStatementLine(body=[cst.Pass()])


def _no_trailing_semi(
    smalls: list[cst.BaseSmallStatement],
) -> list[cst.BaseSmallStatement]:
    last = smalls[-1]
    if hasattr(last, "semicolon"):
        smalls[-1] = last.with_changes(semicolon=cst.MaybeSentinel.DEFAULT)
    return smalls


def _is_super_init(statement: cst.BaseStatement) -> cst.Call | None:
    if not isinstance(statement, cst.SimpleStatementLine):
        return None
    for small in statement.body:
        if isinstance(small, cst.Expr) and isinstance(small.value, cst.Call):
            func = small.value.func
            if (
                isinstance(func, cst.Attribute)
                and func.attr.value == "__init__"
                and isinstance(func.value, cst.Call)
                and _dotted(func.value.func) == "super"
            ):
                return small.value
    return None


def _with_kit_parts(call: cst.Call) -> cst.Call:
    if any(a.star == "**" for a in call.args):
        return call
    args = list(call.args)
    if args:
        args[-1] = args[-1].with_changes(
            comma=cst.Comma(whitespace_after=cst.SimpleWhitespace(" "))
        )
    args.append(cst.Arg(value=cst.Name(_KIT_PARTS), star="**"))
    return call.with_changes(args=args)


def _replace_call(
    statement: cst.SimpleStatementLine, old: cst.Call, new: cst.Call
) -> cst.SimpleStatementLine:
    body = [
        s.with_changes(value=new) if isinstance(s, cst.Expr) and s.value is old else s
        for s in statement.body
    ]
    return statement.with_changes(body=body)


def _docstring_count(body: Sequence[cst.BaseStatement]) -> int:
    if body and isinstance(body[0], cst.SimpleStatementLine):
        first = body[0].body[0]
        if isinstance(first, cst.Expr) and isinstance(
            first.value, (cst.SimpleString, cst.ConcatenatedString)
        ):
            return 1
    return 0


def _init(node: cst.FunctionDef, role: str, cleaner: _InitCleaner) -> cst.FunctionDef:
    params = node.params
    if not isinstance(params.star_kwarg, cst.Param):
        params = params.with_changes(star_kwarg=cst.Param(name=cst.Name(_KIT_PARTS)))
    names = {p.name.value for p in [*node.params.params, *node.params.kwonly_params]}
    if not isinstance(node.body, cst.IndentedBlock):
        return node.with_changes(params=params)  # pragma: no cover - "def f(): x"
    body = cleaner.block(node.body.body)
    found = False
    for index, statement in enumerate(body):
        call = _is_super_init(statement)
        if call is not None and isinstance(statement, cst.SimpleStatementLine):
            body[index] = _replace_call(statement, call, _with_kit_parts(call))
            found = True
            break
    if not found and role == "neuron":
        args = [
            cst.Arg(
                keyword=cst.Name("config"),
                value=cst.Name("config"),
                equal=cst.AssignEqual(
                    whitespace_before=cst.SimpleWhitespace(""),
                    whitespace_after=cst.SimpleWhitespace(""),
                ),
            )
        ]
        args = args if "config" in names else []
        call = _with_kit_parts(
            cst.Call(
                func=cst.Attribute(
                    value=cst.Call(func=cst.Name("super")), attr=cst.Name("__init__")
                ),
                args=args,
            )
        )
        at = _docstring_count(body)
        body.insert(at, cst.SimpleStatementLine(body=[cst.Expr(call)]))
    return node.with_changes(
        params=params, body=node.body.with_changes(body=body or [_pass()])
    )


def _has_code(node: cst.FunctionDef) -> bool:
    """Whether a method does more than ``...`` / ``pass`` / a docstring."""
    body = node.body.body if isinstance(node.body, cst.IndentedBlock) else ()
    for statement in body[_docstring_count(body) :]:
        if not (
            isinstance(statement, cst.SimpleStatementLine)
            and all(
                isinstance(s, cst.Pass)
                or (isinstance(s, cst.Expr) and isinstance(s.value, cst.Ellipsis))
                for s in statement.body
            )
        ):
            return True
    return False


def _marker(removed: list[str], adapter: str | None) -> cst.EmptyLine:
    runs = adapter or "the adapter"
    names = ", ".join(f"{m}()" for m in removed)
    return cst.EmptyLine(
        comment=cst.Comment(
            f"# TW-MIGRATE: TWM026 {runs} runs {names} now (removed here); "
            "move any custom code they held into sync() / resync_metagraph()"
        )
    )


def swap_base(
    module: cst.Module, role: str, bt_aliases: set[str], adapter_local: str | None
) -> SwapResult:
    """Put ``role``'s template class on its adapter (see the module docstring).

    ``adapter_local`` is the name the adapter is imported under (``None``
    for ``neuron.py``, which keeps its own bases).
    """
    name = CLASSES[role]
    node = _class(module, name)
    result = SwapResult(module=module)
    if node is None or not isinstance(node.body, cst.IndentedBlock):
        return result
    cleaner = _InitCleaner(bt_aliases, module)
    body: list[cst.BaseStatement] = []
    removed: list[str] = []
    for statement in node.body.body:
        if isinstance(statement, cst.FunctionDef):
            if statement.name.value in REMOVED_METHODS[role]:
                if _has_code(statement):
                    removed.append(statement.name.value)
                result.removed_methods.append(statement.name.value)
                continue
            if statement.name.value == "__init__":
                statement = _init(statement, role, cleaner)  # noqa: PLW2901
        elif isinstance(statement, cst.SimpleStatementLine) and all(
            isinstance(s, cst.AnnAssign)
            and s.value is None
            and isinstance(s.target, cst.Name)
            and s.target.value in OWNED_ATTRIBUTES
            for s in statement.body
        ):
            cleaner.removed += len(statement.body)
            continue
        body.append(statement)
    bases = list(node.bases)
    if adapter_local is not None and adapter_local not in _base_names(node):
        bases[-1] = bases[-1].with_changes(
            comma=cst.Comma(whitespace_after=cst.SimpleWhitespace(" "))
        )
        bases.append(cst.Arg(value=cst.Name(adapter_local)))
    new = node.with_changes(
        bases=bases, body=node.body.with_changes(body=body or [_pass()])
    )
    if removed:
        new = new.with_changes(
            leading_lines=[*node.leading_lines, _marker(removed, adapter_local)]
        )
    result.module = module.with_changes(
        body=[new if s is node else s for s in module.body]
    )
    result.swapped = True
    result.removed_statements = cleaner.removed
    result.adapter = None if role == "neuron" else ADAPTERS[role]
    return result
