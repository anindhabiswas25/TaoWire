"""``tensorwire migrate apply`` (spec 10b.4.2, 13.8).

Every ``auto`` rule has a positive fixture (the exact rewrite) and a
negative one (similar code ``apply`` must leave alone); everything else
gets a ``# TW-MIGRATE:`` marker above its statement.
"""

from __future__ import annotations

import stat
import subprocess
import textwrap
from pathlib import Path

import libcst as cst
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from tensorwire.cli.main import app
from tensorwire.migrate.apply import (
    MARKER,
    apply_source,
    git_state,
    plan_repo,
    write_changes,
)
from tensorwire.migrate.rules import RULES


def run(source: str) -> str:
    return apply_source(textwrap.dedent(source), "x.py").after


# rule -> (source, expected output); then similar code that must not change
REWRITES: dict[str, tuple[str, str]] = {
    "TWM001": (
        "import typing\nimport bittensor as bt\nclass A(bt.Synapse):\n    x: int = 0\n"
        "    required_hash_fields = ('x',)\n",
        "import typing\nfrom tensorwire.compat import Synapse\n"
        "class A(Synapse):\n    x: int = 0\n    required_hash_fields = ('x',)\n",
    ),
    "TWM003": (
        "import bittensor as bt\naxon = bt.axon(wallet=w, config=c, port=9)\n",
        "from tensorwire import Miner\nfrom tensorwire.compat import Axon\n"
        "axon = Axon(miner=Miner.from_env())\n",
    ),
    "TWM004": (
        "import bittensor as bt\nd = bt.dendrite(wallet=self.wallet)\n",
        "from tensorwire import RequestSigner\nfrom tensorwire.compat import Dendrite\n"
        "d = Dendrite(signer=RequestSigner(self.wallet))\n",
    ),
    "TWM007": (
        "import bittensor as bt\nbt.logging.trace('a')\nbt.logging.success(f'{b}')\n"
        "bt.logging.warning('c', exc_info=True)\n",
        "import logging\nlogging.debug('a')\nlogging.info(f'{b}')\n"
        "logging.warning('c', exc_info=True)\n",
    ),
    "TWM012": (
        "from template.base.utils.weight_utils import (\n"
        "    process_weights_for_netuid,\n    convert_weights_and_uids_for_emit,\n)\n"
        "u, w = process_weights_for_netuid(uids=ids, weights=raw, netuid=1,"
        " subtensor=s, metagraph=m)\n"
        "u2, w2 = convert_weights_and_uids_for_emit(u, w)\n",
        "u, w = (ids, raw)\nu2, w2 = (u, w)\n",
    ),
    "TWM013": (
        "import x\nresponses = d(axons=[self.metagraph.axons[uid] for uid in uids])\n",
        "import x\nfrom tensorwire.compat import axons_from\n"
        "responses = d(axons=axons_from(self.metagraph, uids))\n",
    ),
    "TWM021": (
        "from bittensor import AxonInfo, Subtensor\ninfo = AxonInfo(ip='1.2.3.4')\n",
        "from bittensor import Subtensor\nfrom tensorwire.compat import AxonInfo\n"
        "info = AxonInfo(ip='1.2.3.4')\n",
    ),
    "TWM023": (
        "for uid in range(self.metagraph.n.item()):\n"
        "    s = self.metagraph.S.tolist()\n    t = self.metagraph.S[uid].item()\n",
        "for uid in range(self.metagraph.n):\n    s = self.metagraph.S\n"
        "    t = self.metagraph.S[uid]\n",
    ),
    "TWM027": (
        "import time\nimport os\nasync def forward(self):\n    time.sleep(5)\n",
        "import asyncio\nimport os\nasync def forward(self):\n"
        "    await asyncio.sleep(5)\n",
    ),
    "TWM028": (
        'import bittensor as bt\ndef f(s: "bt.Synapse") -> None: ...\n',
        'from tensorwire.compat import Synapse\ndef f(s: "Synapse") -> None: ...\n',
    ),
    "TWM031": (
        "import argparse\nimport bittensor as bt\ndef config(cls):\n"
        "    parser = argparse.ArgumentParser()\n    bt.wallet.add_args(parser)\n"
        "    bt.Subtensor.add_args(parser)\n    bt.logging.add_args(parser)\n"
        "    bt.Axon.add_args(parser)\n    return bt.config(parser)\n"
        "def only(config: bt.Config) -> bt.config:\n"
        "    bt.logging.check_config(config)\n",
        "import argparse\n"
        "from tensorwire.compat import Config, add_v10_args, config as tw_config\n"
        "def config(cls):\n    parser = argparse.ArgumentParser()\n"
        '    add_v10_args(parser, "wallet")\n    add_v10_args(parser, "subtensor")\n'
        '    add_v10_args(parser, "logging")\n    add_v10_args(parser, "axon")\n'
        "    return tw_config(parser)\ndef only(config: Config) -> Config:\n"
        "    pass\n",
    ),
    "TWM026": (
        "import copy\nimport bittensor as bt\nfrom sub.base.neuron import BaseNeuron\n"
        "class BaseValidatorNeuron(BaseNeuron):\n"
        "    def __init__(self, config=None):\n"
        "        super().__init__(config=config)\n"
        "        self.hotkeys = copy.deepcopy(self.metagraph.hotkeys)\n"
        "        self.dendrite = bt.dendrite(wallet=self.wallet)\n"
        "    def run(self):\n        while True:\n            self.sync()\n"
        "    def log_step(self):\n        pass\n",
        "import copy\nfrom tensorwire.compat import TemplateValidatorAdapter\n"
        "from sub.base.neuron import BaseNeuron\n"
        "# TW-MIGRATE: TWM026 TemplateValidatorAdapter runs run() now (removed "
        "here); move any custom code they held into sync() / resync_metagraph()\n"
        "class BaseValidatorNeuron(BaseNeuron, TemplateValidatorAdapter):\n"
        "    def __init__(self, config=None, **kit_parts):\n"
        "        super().__init__(config=config, **kit_parts)\n"
        "        self.hotkeys = copy.deepcopy(self.metagraph.hotkeys)\n"
        "    def log_step(self):\n        pass\n",
    ),
    "TWM032": (
        "import bittensor as bt\nimport os\nbt.logging.set_debug(True)\n"
        "def f(c):\n    bt.logging(config=c, logging_dir=c.path)\n",
        "import os\ndef f(c):\n    pass\n",
    ),
    "TWM033": (
        "import bittensor as bt\nw = bt.Wallet(config=self.config)\n",
        "import bittensor as bt\nw = bt.Wallet(name=self.config.wallet.name, "
        "hotkey=self.config.wallet.hotkey, path=self.config.wallet.path)\n",
    ),
    "TWM024": (
        "# base\nfrom template.base.validator import BaseValidatorNeuron\n",
        "# base\nfrom tensorwire.compat import TemplateValidatorAdapter as "
        "BaseValidatorNeuron\n",
    ),
}

UNCHANGED = [
    "import logging\nlogging.info('x')\n",
    "import numpy as bt\nbt.logging.info('x')\nclass A(bt.Synapse): pass\n",
    "x = values.item()\ny = self.metagraph.item()\n",
    "a = self.metagraph.axons[uid]\n",
    "a = [self.metagraph.axons[u] for u in uids if u]\n",
    "from template.base.miner import BaseMinerNeuron\n",
    "from tensorwire.compat import Synapse\nclass A(Synapse): pass\n",
    "def f(metagraph: 'Metagraph') -> None: ...\n",
    "import time\ndef f():\n    time.sleep(1)\n",
    "import time\nasync def f():\n    t = time.time()\n",
]


@pytest.mark.parametrize("rule", sorted(REWRITES))
def test_rewrite(rule: str) -> None:
    source, expected = REWRITES[rule]
    role = "validator" if rule == "TWM026" else None  # plan_repo decides it
    result = apply_source(source, "x.py", swap_role=role)
    assert result.after == expected
    assert result.rewrites[rule] >= 1
    assert (MARKER in result.after) is (rule == "TWM026")  # TWM026 lists removals


@pytest.mark.parametrize("source", UNCHANGED)
def test_left_alone(source: str) -> None:
    result = apply_source(source, "x.py")
    assert result.after == source
    assert not result.changed


def test_every_auto_rule_is_rewritten() -> None:
    auto = {rid for rid, rule in RULES.items() if rule.severity == "auto"}
    assert auto == set(REWRITES)


def test_logging_prefix_and_suffix_keep_the_v10_text() -> None:
    out = run(
        """\
        import bittensor as bt
        bt.logging.info("raw_weights", w)
        bt.logging.debug("m", "p", "s", exc_info=True)
        bt.logging.warning(msg="m", suffix=s)
        bt.logging.info("a", "b", "c", d)
        """
    )
    assert out == textwrap.dedent(
        """\
        import logging
        logging.info("%s - %s", w, "raw_weights")
        logging.debug("%s - %s - %s", "p", "m", "s", exc_info=True)
        logging.warning("%s - %s", "m", s)
        logging.info("a", "b", "c", d)
        """
    )


def test_bittensor_import_stays_while_used_and_markers_are_added() -> None:
    out = run(
        """\
        import bittensor as bt


        class Miner:
            def __init__(self):
                bt.logging.set_config(config=self.config.logging)
                self.subtensor = bt.subtensor(config=self.config)
                bt.logging.info("ready")
        """
    )
    assert out == textwrap.dedent(
        f"""\
        import bittensor as bt
        import logging


        class Miner:
            def __init__(self):
                {MARKER} TWM008 {RULES["TWM008"].replacement}
                self.subtensor = bt.subtensor(config=self.config)
                logging.info("ready")
        """
    )


def test_markers_on_compound_and_multiline_statements() -> None:
    out = run(
        """\
        class Ask(Synapse):
            question: str

        def f(p):
            if True:
                p.add_argument(
                    "--blacklist.force_validator_permit",
                    action="store_true",
                )
        """
    )
    lines = out.splitlines()
    assert lines[0].startswith(f"{MARKER} TWM100 ")
    assert lines[1] == "class Ask(Synapse):"
    i = lines.index("        p.add_argument(")
    assert lines[i - 1] == f"        {MARKER} TWM103 {RULES['TWM103'].replacement}"


def test_manual_shapes_are_kept_and_marked() -> None:
    out = run(
        """\
        import bittensor as bt
        class MyAxon(bt.axon):
            pass
        d = bt.dendrite()
        u, w = process_weights_for_netuid(netuid=1)
        """
    )
    assert "class MyAxon(bt.axon):" in out
    config = run("import bittensor as bt\nbt.axon.add_args(parser, prefix=p)\n")
    assert "bt.axon.add_args(parser, prefix=p)" in config  # not v10's plain form
    assert f"{MARKER} TWM006 " in config
    assert f"{MARKER} TWM019 " in out
    assert "d = bt.dendrite()" in out
    assert f"{MARKER} TWM004 " in out  # could not be rewritten safely
    assert f"{MARKER} TWM012 " in out
    assert "import bittensor as bt" in out


def test_string_annotations_and_existing_imports() -> None:
    out = run(
        """\
        import bittensor as bt
        from tensorwire.compat import Synapse
        def f(m: "bt.metagraph.Metagraph", s: "bt.Synapse") -> "bt.Unknown": ...
        x: bt.Synapse
        """
    )
    assert out == textwrap.dedent(
        f"""\
        import bittensor as bt
        from tensorwire.compat import Metagraph
        from tensorwire.compat import Synapse
        {MARKER} TWM030 {RULES["TWM030"].replacement}
        def f(m: "Metagraph", s: "Synapse") -> "bt.Unknown": ...
        x: Synapse
        """
    )  # "bt.Unknown" still names bt: the import stays


def test_template_swap_keeps_other_names() -> None:
    out = run("from template.base.validator import helper, BaseValidatorNeuron as B\n")
    assert out == (
        "from template.base.validator import helper\n"
        "from tensorwire.compat import TemplateValidatorAdapter as B\n"
    )


def test_customised_template_base_is_not_swapped(tmp_path: Path) -> None:
    base = tmp_path / "sub" / "base"
    base.mkdir(parents=True)
    (base / "validator.py").write_text(
        "class BaseValidatorNeuron:\n    def log_step(self): ...\n"
    )
    (tmp_path / "v.py").write_text(
        "from sub.base.validator import BaseValidatorNeuron\n"
    )
    (result,) = [f for f in plan_repo(tmp_path).files if f.path == "v.py"]
    assert result.after.splitlines() == [
        f"{MARKER} TWM026 {RULES['TWM026'].replacement}",
        "from sub.base.validator import BaseValidatorNeuron",
    ]


def test_inserted_names_never_shadow_the_teams_own() -> None:
    out = run(
        """\
        import bittensor as bt
        class Miner:
            def __init__(self):
                self.axon = bt.Axon(wallet=self.wallet, port=8091)
        def axons_from(x):
            return [self.metagraph.axons[uid] for uid in x]
        """
    )
    assert "from tensorwire import Miner as TWMiner" in out
    assert "from tensorwire.compat import Axon, axons_from as tw_axons_from" in out
    assert "self.axon = Axon(miner=TWMiner.from_env())" in out
    assert "return tw_axons_from(self.metagraph, x)" in out
    assert run(out) == out


def test_match_statements() -> None:
    out = run(
        """\
        import bittensor as bt
        def f(x):
            match x:
                case 1:
                    bt.logging.info("one")
                case _:
                    w = bt.wallet()
        """
    )
    assert 'logging.info("one")' in out
    lines = out.splitlines()
    i = lines.index("            w = bt.wallet()")
    assert lines[i - 1].startswith(f"            {MARKER} TWM014 ")


def test_one_failing_file_does_not_stop_the_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tensorwire.migrate import apply as codemod

    (tmp_path / "a.py").write_text("import bittensor as bt\nbt.logging.info('a')\n")
    (tmp_path / "boom.py").write_text("x = 1\n")
    real = codemod.apply_source

    def flaky(source: str, path: str = "<string>", **kw: object) -> object:
        if path == "boom.py":
            raise RuntimeError("bug")
        return real(source, path, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(codemod, "apply_source", flaky)
    report = plan_repo(tmp_path)
    assert [f.path for f in report.changed] == ["a.py"]
    assert report.parse_errors == [
        "boom.py: not rewritten, internal error (RuntimeError: bug); please report it"
    ]


def test_markers_on_decorated_functions_are_idempotent() -> None:
    once = run(
        """\
        import bittensor as bt
        class N:
            @classmethod
            def check(cls, config: "bt.Mystery"):
                ...
        """
    )
    assert once.count(f"{MARKER} TWM030") == 1
    assert run(once) == once


def test_apply_is_idempotent_and_parse_errors_raise() -> None:
    source = "import bittensor as bt\nbt.logging.info('x')\nw = bt.wallet()\n"
    once = run(source)
    assert run(once) == once
    with pytest.raises(cst.ParserSyntaxError):
        apply_source("def (:\n")


# ---------------------------------------------------------------- property


SNIPPETS = [
    "bt.logging.info('a')",
    "bt.logging.trace(x)",
    "bt.logging.set_trace(True)",
    "s = bt.subtensor(config=c)",
    "a = bt.axon(wallet=w)",
    "d = bt.dendrite(wallet=w)",
    "d2 = bt.dendrite()",
    "r = [self.metagraph.axons[u] for u in uids]",
    "n = self.metagraph.n.item()",
    "u, w = process_weights_for_netuid(uids=a, weights=b)",
    "class S(bt.Synapse):\n    x: int",
    "class X(bt.axon):\n    pass",
    "if ok:\n    bt.logging.error('e')",
    "def f():\n    w = bt.wallet()\n    return w",
]
IMPORTS = [
    "import bittensor as bt",
    "import bittensor",
    "from bittensor import Synapse, AxonInfo",
    "from template.base.validator import BaseValidatorNeuron",
    "import logging",
]


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(
    st.lists(st.sampled_from(IMPORTS), max_size=3, unique=True),
    st.lists(st.sampled_from(SNIPPETS), max_size=6),
)
def test_apply_output_parses_and_is_a_fixed_point(
    imports: list[str], body: list[str]
) -> None:
    source = "\n".join([*imports, *body]) + "\n"
    once = apply_source(source, "p.py").after
    cst.parse_module(once)  # still valid Python
    assert apply_source(once, "p.py").after == once
    if "import bittensor as bt" in imports:  # every bt auto use is rewritten
        assert "bt.logging.info(" not in once
        assert "bt.Synapse" not in once


# ---------------------------------------------------------------- repo + CLI


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "subnet"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "m.py").write_text("import bittensor as bt\nbt.logging.info('x')\n")
    (root / "pkg" / "ok.py").write_text("x = 1\n")
    (root / ".env").write_text("TW_WALLET_NAME=x\n")
    (root / "wallets").mkdir()
    (root / "wallets" / "hotkey").write_text("secret")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "v10")
    return root


def test_cli_dry_run_prints_a_diff_and_writes_nothing(repo: Path) -> None:
    result = CliRunner().invoke(app, ["migrate", "apply", "--dry-run", str(repo)])
    assert result.exit_code == 0, result.output
    assert "-bt.logging.info('x')" in result.stdout
    assert "+logging.info('x')" in result.stdout
    assert "1 changed" in result.stderr
    assert "bt.logging" in (repo / "pkg" / "m.py").read_text()


def test_cli_writes_on_a_clean_tree_only(repo: Path) -> None:
    (repo / "pkg" / "m.py").chmod(0o640)  # git does not track this: still clean
    result = CliRunner().invoke(app, ["migrate", "apply", str(repo)])
    assert result.exit_code == 0, result.output
    assert (repo / "pkg" / "m.py").read_text() == "import logging\nlogging.info('x')\n"
    assert stat.S_IMODE((repo / "pkg" / "m.py").stat().st_mode) == 0o640
    assert (repo / ".env").read_text() == "TW_WALLET_NAME=x\n"
    assert (repo / "wallets" / "hotkey").read_text() == "secret"
    assert git_state(repo) == "dirty"  # git diff shows exactly what changed
    again = CliRunner().invoke(app, ["migrate", "apply", str(repo)])
    assert again.exit_code == 2
    assert "uncommitted changes" in again.output
    forced = CliRunner().invoke(app, ["migrate", "apply", "--allow-dirty", str(repo)])
    assert forced.exit_code == 0
    assert "0 changed" in forced.output


def test_cli_refuses_outside_git_and_reports_parse_errors(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("def (:\n")
    (tmp_path / "good.py").write_text("import bittensor as bt\nbt.logging.info('x')\n")
    result = CliRunner().invoke(app, ["migrate", "apply", str(tmp_path)])
    assert result.exit_code == 2
    assert "not in a git repository" in result.output
    result = CliRunner().invoke(
        app, ["migrate", "apply", "--allow-dirty", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "bad.py:1: syntax error" in result.output
    assert (tmp_path / "good.py").read_text() == "import logging\nlogging.info('x')\n"
    assert git_state(tmp_path) == "not_git"
    missing = CliRunner().invoke(app, ["migrate", "apply", str(tmp_path / "nope")])
    assert missing.exit_code == 2


def test_never_writes_through_a_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("import bittensor as bt\nbt.logging.info('x')\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "link.py").symlink_to(outside)
    report = plan_repo(root)
    assert report.changed == []
    assert write_changes(report) == []
    assert "bt.logging" in outside.read_text()
    with pytest.raises(NotADirectoryError):
        plan_repo(outside)


def test_summary_lists_rules(repo: Path) -> None:
    (repo / "pkg" / "w.py").write_text("import bittensor as bt\nw = bt.wallet()\n")
    report = plan_repo(repo)
    text = report.summary()
    assert "rewritten: TWM007 x1" in text
    assert "to do by hand: TWM014 x1" in text
    assert "  pkg/m.py" in text


# ---------------------------------------------------------------- TWM026 swap


def _customised_template(root: Path, *, miner_base: str = "BaseNeuron") -> None:
    base = root / "sub" / "base"
    base.mkdir(parents=True)
    (root / "sub" / "__init__.py").write_text("")
    (base / "__init__.py").write_text("")
    (base / "neuron.py").write_text(
        textwrap.dedent(
            """\
            import copy
            from abc import ABC, abstractmethod
            import bittensor as bt
            class BaseNeuron(ABC):
                wallet: "bt.wallet"
                def __init__(self, config=None):
                    base_config = copy.deepcopy(config or BaseNeuron.config())
                    self.config = self.config()
                    self.config.merge(base_config)
                    bt.logging(config=self.config, logging_dir=self.config.full_path)
                    self.wallet = bt.wallet(config=self.config)
                    self.subtensor = bt.subtensor(config=self.config)
                    self.metagraph = self.subtensor.metagraph(self.config.netuid)
                    hotkey = self.wallet.hotkey.ss58_address
                    self.uid = self.metagraph.hotkeys.index(hotkey)
                    self.parse_versions()
                @abstractmethod
                async def forward(self, synapse): ...
                @abstractmethod
                def run(self): ...
                def parse_versions(self):
                    self.version = "1"
            """
        )
    )
    (base / "miner.py").write_text(
        textwrap.dedent(
            f"""\
            import bittensor as bt
            from sub.base.neuron import BaseNeuron
            class BaseMinerNeuron({miner_base}):
                def __init__(self, config=None):
                    super().__init__(config=config)
                    self.axon = bt.axon(wallet=self.wallet, config=self.config)
                    self.axon.attach(forward_fn=self.forward)
                    self.blacklisted = set()
                def run(self):
                    self.axon.serve(netuid=self.config.netuid, subtensor=self.subtensor)
                    self.axon.start()
                def __enter__(self):
                    return self
            """
        )
    )
    (base / "validator.py").write_text(
        textwrap.dedent(
            """\
            import bittensor as bt
            from sub.base.neuron import BaseNeuron
            class BaseValidatorNeuron(BaseNeuron):
                def __init__(self, config=None):
                    super().__init__(config=config)
                    self.dendrite = bt.dendrite(wallet=self.wallet)
                    self.scores = [0.0] * len(self.metagraph.hotkeys)
                def set_weights(self):
                    self.subtensor.set_weights(netuid=1, uids=[], weights=[])
                def log_step(self):
                    bt.logging.info("step")
            """
        )
    )
    (root / "neurons").mkdir()
    (root / "neurons" / "validator.py").write_text(
        "from sub.base.validator import BaseValidatorNeuron\n"
        "class Validator(BaseValidatorNeuron):\n    async def forward(self): ...\n"
    )


def test_a_customised_template_package_is_swapped_onto_the_adapters(
    tmp_path: Path,
) -> None:
    _customised_template(tmp_path)
    report = plan_repo(tmp_path)
    assert not report.parse_errors
    out = {f.path: f for f in report.files}
    neuron = out["sub/base/neuron.py"].after
    miner = out["sub/base/miner.py"].after
    validator = out["sub/base/validator.py"].after
    assert "super().__init__(config=config, **kit_parts)" in neuron
    assert "def run(self)" not in neuron
    assert "self.parse_versions()" in neuron
    for gone in ("self.wallet =", "self.subtensor =", "self.uid =", "base_config",
                 "bt.logging(", 'wallet: "bt.wallet"', "import bittensor"):  # fmt: skip
        assert gone not in neuron, gone
    assert "class BaseMinerNeuron(BaseNeuron, TemplateMinerAdapter):" in miner
    assert "from tensorwire.compat import TemplateMinerAdapter" in miner
    assert "self.axon.attach(forward_fn=self.forward)" in miner
    assert "self.axon = " not in miner
    assert f"{MARKER} TWM026 TemplateMinerAdapter runs run(), __enter__() now" in miner
    assert (
        "class BaseValidatorNeuron(BaseNeuron, TemplateValidatorAdapter):" in validator
    )
    assert "self.dendrite =" not in validator
    assert "def set_weights" not in validator
    assert 'logging.info("step")' in validator
    # The subnet's import of its own base needs nothing now.
    assert out["neurons/validator.py"].after.startswith("from sub.base.validator")
    bases = [f for f in report.files if f.path.startswith("sub/base/") and
             not f.path.endswith("__init__.py")]  # fmt: skip
    assert len(bases) == 3
    assert all(f.rewrites.get("TWM026") for f in bases)
    write_changes(report)
    again = plan_repo(tmp_path)
    assert not again.changed  # idempotent: the swapped package counts as ported
    for path in ("sub/base/neuron.py", "sub/base/miner.py", "sub/base/validator.py"):
        compile((tmp_path / path).read_text(), path, "exec")


def test_a_package_without_the_template_shape_is_not_swapped(tmp_path: Path) -> None:
    _customised_template(tmp_path, miner_base="Something")
    report = plan_repo(tmp_path)
    out = {f.path: f for f in report.files}
    assert "TemplateMinerAdapter" not in out["sub/base/miner.py"].after
    assert "TemplateValidatorAdapter" not in out["sub/base/validator.py"].after
    assert out["neurons/validator.py"].after.startswith(f"{MARKER} TWM026")
