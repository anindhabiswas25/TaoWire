"""``tensorwire conformance`` (spec 11.7): the Python run over every vector file."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from tensorwire.cli import conformance_cmd
from tensorwire.cli.conformance_cmd import REQUIRED_FILES, conformance, run_vectors

VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors"
app = typer.Typer()
app.command()(conformance)


def run(folder: Path, *args: str) -> tuple[int, str]:
    result = CliRunner().invoke(app, ["--vectors", str(folder), *args])
    return result.exit_code, result.output


@pytest.fixture
def copy(tmp_path: Path) -> Path:
    folder = tmp_path / "vectors"
    shutil.copytree(VECTORS, folder)
    return folder


def edit(folder: Path, name: str, change: Callable[[dict[str, Any]], None]) -> None:
    path = folder / name
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def vector(data: dict[str, Any], vid: str) -> dict[str, Any]:
    found: dict[str, Any] = next(v for v in data["vectors"] if v["id"] == vid)
    return found


def test_every_committed_vector_passes() -> None:
    code, out = run(VECTORS, "--verbose")
    assert code == 0, out
    assert out.strip().splitlines()[-1].startswith("PASS:")
    for name in REQUIRED_FILES:
        assert f"ok   {name}" in out
    assert "4 known divergence(s)" in out
    assert "divergence N19" in out


def test_without_verbose_divergences_are_counted_not_listed() -> None:
    code, out = run(VECTORS)
    assert code == 0
    assert "divergence N19" not in out


def test_run_vectors_counts() -> None:
    results = {r.name: r for r in run_vectors(VECTORS)}
    assert results["negative.json"].passed == 77
    assert results["payload.json"].passed == 10
    assert not any(r.failures for r in results.values())


Change = Callable[[dict[str, Any]], None]

TAMPERS: list[tuple[str, str, str, Change]] = [
    (
        "payload.json",
        "P4",
        "payload differs",
        lambda d: vector(d, "P4")["expected"].update(payload_base64="YQ=="),
    ),
    (
        "payload.json",
        "P2",
        "body sha256 differs",
        lambda d: vector(d, "P2")["expected"].update(body_sha256="00"),
    ),
    (
        "ed25519.json",
        "E1",
        "signature differs",
        lambda d: vector(d, "E1")["expected"].update(signature="0x00"),
    ),
    (
        "negative.json",
        "N12",
        "want valid=False code=tw.auth_replayed",
        lambda d: vector(d, "N12")["expected"].update(code="tw.auth_replayed"),
    ),
    (
        "negative.json",
        "N19",
        "want valid=False code=tw.auth_bad_signature",
        lambda d: vector(d, "N19").pop("python_reference"),
    ),
    (
        "negative.json",
        "N21",
        "prior request refused",
        lambda d: vector(d, "N21")["inputs"].update(
            prior=vector(d, "N12")["inputs"] | {"prior": None, "body_base64": "eA=="}
        ),
    ),
    (
        "sr25519_verify.json",
        "R3",
        "caller",
        lambda d: vector(d, "R3")["expected"].update(caller_ss58="5x"),
    ),
    (
        "twresp.json",
        "X1",
        "accepted, want refused",
        lambda d: vector(d, "X1")["inputs"].update(
            body_base64=vector(d, "V1")["inputs"]["body_base64"]
        ),
    ),
    (
        "twresp.json",
        "V1",
        "refused",
        lambda d: vector(d, "V1")["inputs"].update(status=201),
    ),
    (
        "twresp.json",
        "E1",
        "payload differs",
        lambda d: vector(d, "E1")["expected"].update(payload_utf8="x"),
    ),
    (
        "twresp.json",
        "S1",
        "signature does not verify",
        lambda d: (
            vector(d, "S1")["inputs"].update(
                chunks_base64=vector(d, "S1")["inputs"]["chunks_base64"][:2]
            )
            or vector(d, "S1")["expected"].update(
                payload_utf8=None,
            )
        ),
    ),
    (
        "legacy_v10.json",
        "V1",
        "computed_body_hash differs",
        lambda d: vector(d, "V1")["request_expected"].update(computed_body_hash="0"),
    ),
    (
        "legacy_v10.json",
        "V1",
        "v10 signature verifies=True, want False",
        lambda d: vector(d, "V1")["request_expected"].update(signature_verifies=False),
    ),
    (
        "legacy_v10.json",
        "V2",
        "recorded body sha256 differs",
        lambda d: vector(d, "V2")["request"].update(body_sha256="0"),
    ),
]


@pytest.mark.parametrize(
    ("name", "vid", "message", "change"),
    TAMPERS,
    ids=[f"{n}:{v}:{m[:20]}" for n, v, m, _ in TAMPERS],
)
def test_a_changed_vector_fails(
    copy: Path, name: str, vid: str, message: str, change: Change
) -> None:
    edit(copy, name, change)
    code, out = run(copy)
    assert code == 1, out
    assert f"FAIL {name}" in out
    failing = [line for line in out.splitlines() if line.strip().startswith(f"{vid}:")]
    assert failing, out
    assert any(message in line for line in failing), out


def test_unknown_file_fails(copy: Path) -> None:
    (copy / "extra.json").write_text('{"schema_version": 1, "vectors": []}', "utf-8")
    code, out = run(copy)
    assert code == 1
    assert "FAIL extra.json: 0/1 passed" in out
    assert "no checker for this file" in out


@pytest.mark.parametrize("name", REQUIRED_FILES)
def test_missing_file_fails(copy: Path, name: str) -> None:
    (copy / name).unlink()
    code, out = run(copy)
    assert code == 1
    assert f"FAIL {name}" in out
    assert "file missing" in out


def test_schema_version_and_empty_files_fail(copy: Path) -> None:
    edit(copy, "payload.json", lambda d: d.update(schema_version=2))
    edit(copy, "ed25519.json", lambda d: d.update(vectors=[]))
    code, out = run(copy)
    assert code == 1
    assert "unknown schema_version 2" in out
    assert "no vectors" in out


def test_a_vector_that_cannot_run_is_a_failure(copy: Path) -> None:
    edit(copy, "payload.json", lambda d: vector(d, "P1")["inputs"].pop("target"))
    code, out = run(copy)
    assert code == 1
    assert "P1: vector could not be run: KeyError" in out


def test_not_a_folder_and_bad_json_exit_2(copy: Path, tmp_path: Path) -> None:
    code, out = run(tmp_path / "missing")
    assert code == 2
    assert "is not a folder" in out
    (copy / "payload.json").write_text("{", encoding="utf-8")
    code, out = run(copy)
    assert code == 2
    assert "cannot read the vectors" in out


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(typer, "run", calls.append)
    conformance_cmd.main()
    assert calls == [conformance]
