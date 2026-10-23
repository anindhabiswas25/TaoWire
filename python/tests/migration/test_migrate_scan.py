"""``tensorwire migrate scan`` (spec 10b.4.1, 13.8).

Every rule in ``migrate/rules.py`` has at least one positive and one
negative fixture here, and the scanner is run on the pinned v10 template
(``examples/migrations/template-v10-to-v11/before/``).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tensorwire.cli.main import app
from tensorwire.migrate.rules import RULES
from tensorwire.migrate.scan import render, scan_repo, scan_source

REPO = Path(__file__).resolve().parents[3]
BEFORE = REPO / "examples" / "migrations" / "template-v10-to-v11" / "before"

# rule -> (code that triggers it, similar code that must not)
FIXTURES: dict[str, tuple[str, str]] = {
    "TWM001": (
        "import bittensor as bt\nclass A(bt.Synapse):\n    x: int = 0\n"
        "    required_hash_fields: ClassVar[tuple[str, ...]] = ('x',)\n",
        "from tensorwire.compat import Synapse\nclass A(Synapse):\n    x: int = 0\n",
    ),
    "TWM002": (
        "from bittensor import StreamingSynapse\n",
        "from tensorwire.compat import Synapse\n",
    ),
    "TWM003": (
        "import bittensor\naxon = bittensor.axon(wallet=w)\n",
        "from tensorwire.compat import Axon\naxon = Axon(miner=m)\n",
    ),
    "TWM004": (
        "import bittensor as bt\nd = bt.dendrite(wallet=w)\n",
        "import bittensor as bt\nc = bt.Subtensor('test')\n",
    ),
    "TWM005": (
        "import bittensor as bt\nt: bt.Tensor\n",
        "import torch\nt: torch.Tensor\n",
    ),
    "TWM006": (
        "import bittensor as bt\nc = bt.config(parser)\n",
        "config = load_config()\n",
    ),
    "TWM007": (
        "import bittensor as bt\nbt.logging.info('x')\n",
        "import logging\nlogging.info('x')\n",
    ),
    "TWM008": (
        "import bittensor as bt\ns = bt.subtensor(config=c)\n",
        "import bittensor as bt\ns = bt.Subtensor('test')\n",
    ),
    "TWM009": (
        "self.metagraph.sync(subtensor=self.subtensor)\n",
        "self.cache.sync()\n",
    ),
    "TWM010": (
        "self.subtensor.set_weights(netuid=1, uids=u, weights=w)\n",
        "scheduler.set_weights(w)\n",
    ),
    "TWM011": (
        "self.subtensor.serve_axon(netuid=1, axon=a)\n",
        "router.serve_axon(a)\n",
    ),
    "TWM012": (
        "from bittensor.utils.weight_utils import process_weights_for_netuid\n",
        "from tensorwire.compat import weights\n",
    ),
    "TWM013": (
        "axons = [self.metagraph.axons[uid] for uid in uids]\n",
        "axons = axons_from(view, uids)\n",
    ),
    "TWM014": (
        "import bittensor as bt\nw = bt.wallet(config=c)\n",
        "from tensorwire.auth.keys import load_hotkey\nk = load_hotkey(p, n, h)\n",
    ),
    "TWM015": (
        "import bittensor as bt\nw = bt.MockWallet()\n",
        "from tensorwire.testing.fake_chain import FakeChain\n",
    ),
    "TWM016": (
        "import bittensor as bt\nclass Api(bt.SubnetsAPI): pass\n",
        "class Api: pass\n",
    ),
    "TWM017": (
        "import bittensor as bt\nk = bt.Keypair.create_from_uri('//Alice')\n",
        "from bittensor.keyfiles import Keypair\n",
    ),
    "TWM018": (
        "from bittensor.core.synapse import TerminalInfo\n",
        "from bittensor import http_auth\n",
    ),
    "TWM019": (
        "import bittensor as bt\nclass MyAxon(bt.axon): pass\n",
        "class MyAxon(Base): pass\n",
    ),
    "TWM020": (
        "axon.attach(forward_fn=f, verify_fn=check)\n",
        "axon.attach(forward_fn=f, verify_fn=None)\n",
    ),
    "TWM021": (
        "import bittensor as bt\ninfo = bt.AxonInfo(ip='1.2.3.4', port=1)\n",
        "from tensorwire.compat import AxonInfo\n",
    ),
    "TWM022": (
        "from bittensor import NeuronInfo, __ss58_format__\n",
        "from tensorwire.crypto import SS58_FORMAT\n",
    ),
    "TWM023": (
        "for uid in range(self.metagraph.n.item()):\n    pass\n",
        "for uid in range(self.metagraph.n):\n    pass\n",
    ),
    "TWM024": (
        "from template.base.validator import BaseValidatorNeuron\n",
        "from template.base.miner import BaseMinerNeuron\n",
    ),
    "TWM025": (
        "import bittensor as bt\nbt.logging.set_config(config=c)\n",
        "import logging\nlogging.basicConfig()\n",
    ),
    "TWM027": (
        "import time\nasync def forward(self):\n    time.sleep(5)\n",
        "import time\ndef forward(self):\n    time.sleep(5)\n",
    ),
    "TWM028": (
        "import bittensor as bt\ndef f(s: 'bt.Synapse') -> None: ...\n",
        "from tensorwire.compat import Synapse\ndef f(s: 'Synapse') -> None: ...\n",
    ),
    "TWM029": (
        "patch('vali_utils.miner_evaluator.bt.logging.info')\n",
        "patch('vali_utils.miner_evaluator.logging.info')\n",
    ),
    "TWM030": (
        "import bittensor as bt\nx = bt.Epistula()\n",
        "import bittensor as bt\nx = bt.Balance.from_tao(1)\n",
    ),
    "TWM100": (
        "class Ask(Synapse):\n    question: str\n    answer: str | None = None\n",
        "class Ask(Synapse):\n    question: str\n"
        "    required_hash_fields: ClassVar[tuple[str, ...]] = ('question',)\n",
    ),
    "TWM101": (
        "class Ask(Synapse):\n    question: str\n    model: str\n"
        "    required_hash_fields: ClassVar[tuple[str, ...]] = ('question',)\n",
        "class Ask(Synapse):\n    question: str\n    model: str = 'x'\n"
        "    required_hash_fields: ClassVar[tuple[str, ...]] = ('question',)\n",
    ),
    "TWM102": (
        "check(allow_non_registered=True)\n",
        "check(allow_non_registered=False)\n",
    ),
    "TWM103": (
        "config.blacklist.force_validator_permit = False\n",
        "config.blacklist.force_validator_permit = True\n",
    ),
    "TWM104": (
        "def blacklist(self, synapse):\n    return False, 'ok'\n",
        "def blacklist(self, synapse):\n"
        "    if synapse.dendrite.hotkey not in self.metagraph.hotkeys:\n"
        "        return True, 'unregistered'\n    return False, 'ok'\n",
    ),
}


def rules_in(source: str) -> set[str]:
    findings, _ = scan_source(textwrap.dedent(source), "x.py")
    return {f.rule for f in findings}


#: Rules that need the whole repository (tested in test_customised_template_base).
REPO_LEVEL = {"TWM026"}


def test_customised_template_base(tmp_path: Path) -> None:
    base = tmp_path / "subnet" / "base"
    base.mkdir(parents=True)
    (base / "validator.py").write_text(
        "class BaseValidatorNeuron(BaseNeuron):\n"
        "    def set_weights(self): ...\n"
        "    def log_step(self): ...\n"
    )
    (base / "neuron.py").write_text(
        "class BaseNeuron:\n    def sync(self): ...\n"
        "    def parse_versions(self): ...\n"
    )
    stock = tmp_path / "template" / "base"
    stock.mkdir(parents=True)
    (stock / "validator.py").write_text(
        "class BaseValidatorNeuron(BaseNeuron):\n    def set_weights(self): ...\n"
    )
    (tmp_path / "neurons").mkdir()
    (tmp_path / "neurons" / "v.py").write_text(
        "from subnet.base.validator import BaseValidatorNeuron\n"
    )
    (tmp_path / "neurons" / "t.py").write_text(
        "from template.base.validator import BaseValidatorNeuron\n"
    )
    (tmp_path / "subnet" / "x.py").write_text(
        "from .base.validator import BaseValidatorNeuron\n"
    )
    ported = tmp_path / "done" / "base"
    ported.mkdir(parents=True)
    (ported / "validator.py").write_text(
        "from tensorwire.compat import TemplateValidatorAdapter\n"
        "class BaseValidatorNeuron(TemplateValidatorAdapter):\n"
        "    def log_step(self): ...\n"
    )
    (tmp_path / "neurons" / "d.py").write_text(
        "from done.base.validator import BaseValidatorNeuron\n"
    )
    report = scan_repo(tmp_path)
    found = {(f.path, f.rule, f.detail) for f in report.findings}
    assert not [f for f in report.findings if f.path == "neurons/d.py"]  # ported
    custom = "subnet.base.validator adds: log_step, parse_versions"
    assert ("neurons/v.py", "TWM026", custom) in found
    assert ("subnet/x.py", "TWM026", custom) in found  # relative import
    assert ("neurons/t.py", "TWM024", "from template.base.validator import "
            "BaseValidatorNeuron") in found  # fmt: skip


def test_every_rule_has_fixtures() -> None:
    assert set(FIXTURES) | REPO_LEVEL == set(RULES)


@pytest.mark.parametrize("rule", sorted(FIXTURES))
def test_positive_fixture(rule: str) -> None:
    assert rule in rules_in(FIXTURES[rule][0])


@pytest.mark.parametrize("rule", sorted(FIXTURES))
def test_negative_fixture(rule: str) -> None:
    assert rule not in rules_in(FIXTURES[rule][1])


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        # argparse defaults (the template's own config.py)
        (
            "p.add_argument('--blacklist.force_validator_permit', "
            "action='store_true', default=False)\n",
            "TWM103",
        ),
        (
            "p.add_argument('--blacklist.force_validator_permit', "
            "action='store_true')\n",
            "TWM103",
        ),
        (
            "p.add_argument('--blacklist.allow_non_registered', default=True)\n",
            "TWM102",
        ),
        ("x.allow_non_registered = True\n", "TWM102"),
        ("f(force_validator_permit=False)\n", "TWM103"),
        # the deprecated pydantic-field style still counts as a list
        (
            "class A(bt.Synapse):\n    a: int\n"
            "    required_hash_fields: list[str] = Field(default=['b'])\n",
            "TWM101",
        ),
        ("import bittensor\nbittensor.utils.weight_utils.normalize(x)\n", "TWM012"),
        ("import bittensor.utils\n", "TWM018"),
        ("from bittensor import *\n", "TWM018"),
        ("w = convert_weights_and_uids_for_emit(u, w)\n", "TWM012"),
        ("from bittensor.subnets import SubnetsAPI\n", "TWM016"),
        ("uids = self.metagraph.uids.tolist()\n", "TWM023"),
        ("import bittensor as bt\nbt.logging(config=c)\n", "TWM025"),
        ("import bittensor as bt\nbt.logging.set_trace(True)\n", "TWM025"),
        ("from bittensor import logging\n", "TWM025"),
        ("import bittensor as bt\nbt.logging.trace('x')\n", "TWM007"),
        ("from .base.validator import BaseValidatorNeuron as B\n", "TWM024"),
        # B's data-universe misses (2026-10-23)
        ("import bittensor as bt\nw = bt.Wallet(config=self.config)\n", "TWM014"),
        ("import bittensor as bt\ns = bt.Subtensor(config=self.config)\n", "TWM008"),
        ("import bittensor as bt\ndef f(m: bt.Metagraph): ...\n", "TWM009"),
        ("import bittensor as bt\ndef f(s: bt.Subtensor): ...\n", "TWM008"),
        ("import bittensor as bt\nbt.Subtensor.add_args(p)\n", "TWM006"),
        ("from bittensor_wallet.keypair import Keypair\n", "TWM017"),
        ("import bittensor_wallet\n", "TWM014"),
        ("import bittensor as bt\ndef f(c: 'bt.Config' = None): ...\n", "TWM006"),
        ("import bittensor as bt\nt = bt.TerminalInfo(status_code=200)\n", "TWM001"),
        ("from bittensor import Epistula\n", "TWM030"),
        ("import bittensor as bt\noriginal = bt.logging.trace\n", "TWM025"),
        ("import bittensor as bt\nbt.logging.trace = mine\n", "TWM025"),
        (
            "import time\nclass V:\n    async def f(self):\n"
            "        if x:\n            time.sleep(1)\n",
            "TWM027",
        ),
    ],
)
def test_more_positives(source: str, rule: str) -> None:
    assert rule in rules_in(source)


@pytest.mark.parametrize(
    "source",
    [
        "p.add_argument('--blacklist.force_validator_permit', default=True)\n",
        "p.add_argument('--blacklist.allow_non_registered', default=False)\n",
        "p.add_argument('--other', default=False)\n",
        "p.add_argument(flag_name)\n",
        "class A(Synapse):\n    pass\n",  # no fields: nothing to hash
        "class A(Synapse):\n    limit: ClassVar[int] = 3\n",
        "import numpy as bt\nbt.Tensor\n",  # bt is not bittensor here
        "from bittensor import Subtensor, SetWeights\n",
        "import bittensor as bt\nc = bt.Subtensor('test')\n",  # v11 constructor
        "import bittensor as bt\nr = bt.SetWeights(netuid=1, weights=w)\n",
        "x = f('bt.logging is mentioned in prose only as bt.unknownthing')\n",
        'def f():\n    """Uses bt.logging.info and bt.Synapse."""\n',
        "x = values.item()\n",
        "a = self.metagraph.axons[uid]\n",  # works through compat.Metagraph
        "a = [self.metagraph.axons[u] for u in uids if u]\n",  # not the plain list
        "a = [self.metagraph.axons[0] for u in uids]\n",
        "from template.base.validator import helper\n",
        "import time\nasync def f():\n    def g():\n        time.sleep(1)\n",
        "import time\nasync def f():\n    g = lambda: time.sleep(1)\n",
    ],
)
def test_more_negatives(source: str) -> None:
    assert rules_in(source) == set()


def test_finding_position_and_snippet() -> None:
    findings, _ = scan_source(
        "x = 1\nimport bittensor as bt\nbt.logging.info('hi')\n", "m.py"
    )
    (f,) = findings
    assert (f.path, f.line, f.rule) == ("m.py", 3, "TWM007")
    assert f.snippet == "bt.logging.info('hi')"
    assert f.detail == "bt.logging.info"
    assert f.severity == "auto"


# ---------------------------------------------------------------- the template


def test_template_scan() -> None:
    report = scan_repo(BEFORE)
    assert report.template_detected
    assert report.parse_errors == []
    assert report.files_scanned >= 30
    found = {(f.path, f.rule) for f in report.findings}
    assert ("template/protocol.py", "TWM100") in found  # Dummy hashes nothing
    assert ("template/utils/config.py", "TWM103") in found
    assert ("template/base/validator.py", "TWM010") in found
    assert ("template/base/validator.py", "TWM012") in found
    assert ("neurons/miner.py", "TWM001") not in found  # uses template.protocol
    assert report.exit_code == 1


def test_formats() -> None:
    report = scan_repo(BEFORE)
    text = render(report)
    assert text.startswith("Template shape detected")
    assert "TWM100 [risk]" in text
    data = json.loads(render(report, "json"))
    assert data["template_detected"] is True
    assert data["counts"]["risk"] >= 2
    assert data["findings"][0]["doc"].startswith("docs/migration-from-v10.md#twm")
    md = render(report, "md")
    assert md.startswith("# TensorWire migration scan")
    assert "| `template/protocol.py` |" in md


def test_exit_code_zero_when_only_auto(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import bittensor as bt\nd = bt.dendrite(wallet=w)\n", encoding="utf-8"
    )
    report = scan_repo(tmp_path)
    assert report.counts() == {"auto": 1, "manual": 0, "risk": 0}
    assert report.exit_code == 0
    assert not report.template_detected


def test_skips_venvs_and_reports_parse_errors(tmp_path: Path) -> None:
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "x.py").write_text(
        "import bittensor as bt\nbt.axon\n"
    )
    (tmp_path / "broken.py").write_text("def (:\n")
    (tmp_path / "latin.py").write_bytes(b"x = '\xff'\n")
    (tmp_path / "big.py").write_text("#" * (2 * 1024 * 1024 + 1))
    (tmp_path / "notes.txt").write_text("bt.axon")
    report = scan_repo(tmp_path)
    assert report.findings == []
    assert report.files_scanned == 0
    assert len(report.parse_errors) == 3
    assert report.exit_code == 1
    assert "parse error" in render(report)
    assert "## Parse errors" in render(report, "md")


def test_never_follows_symlinks_out_of_the_repo(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("import bittensor as bt\nbt.axon\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "link.py").symlink_to(outside)
    (repo / "inside.py").write_text("import bittensor as bt\nbt.dendrite\n")
    (repo / "inner_link.py").symlink_to(repo / "inside.py")
    report = scan_repo(repo)
    assert {f.path for f in report.findings} == {"inside.py", "inner_link.py"}


def test_not_a_directory(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        scan_repo(tmp_path / "missing")


# ---------------------------------------------------------------- CLI


def test_cli_scan(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["migrate", "scan", str(BEFORE), "--format", "json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["template_detected"] is True
    (tmp_path / "ok.py").write_text("x = 1\n")
    clean = runner.invoke(app, ["migrate", "scan", str(tmp_path)])
    assert clean.exit_code == 0
    assert "0 findings" in clean.stdout


def test_cli_rejects_bad_input(tmp_path: Path) -> None:
    runner = CliRunner()
    bad_format = runner.invoke(app, ["migrate", "scan", str(tmp_path), "-f", "xml"])
    assert bad_format.exit_code == 2
    missing = runner.invoke(app, ["migrate", "scan", str(tmp_path / "nope")])
    assert missing.exit_code == 2


def test_every_rule_is_documented() -> None:
    guide = (REPO / "docs" / "migration-from-v10.md").read_text(encoding="utf-8")
    for rule in RULES.values():
        assert f'<a id="{rule.id.lower()}"></a>' in guide, rule.id
        assert rule.doc == f"docs/migration-from-v10.md#{rule.id.lower()}"
