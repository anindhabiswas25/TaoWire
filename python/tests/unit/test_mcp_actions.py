"""The MCP server's actions, called directly (no MCP transport)."""

from __future__ import annotations

import base64
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from taowire.auth.signer import RequestSigner
from taowire.crypto import HotkeySigner, keypair_from_uri
from taowire.extensions.response_sig import sign_response
from taowire.mcp_server import actions

BOB = keypair_from_uri("//Bob").ss58_address
CHARLIE = keypair_from_uri("//Charlie").ss58_address
BODY = b'{"text":"hello","op":"upper"}'
REPO = Path(__file__).resolve().parents[3]
BEFORE = REPO / "examples/migrations/template-v10-to-v11/before"


def _signed(target: str = "/v1/transform") -> dict[str, str]:
    signer = RequestSigner(keypair_from_uri("//Alice"))
    return signer.sign(method="POST", target=target, body=BODY, receiver_ss58=BOB)


def test_inspect_valid_request() -> None:
    report = actions.inspect_request(
        method="POST", target="/v1/transform", headers=_signed(), body=BODY
    )
    assert report["result"]["ok"] is True
    assert report["result"]["caller"] == keypair_from_uri("//Alice").ss58_address
    lines = report["signed_payload_lines"]
    assert lines[:4] == ["btauth/1", "sr25519", "POST", "/v1/transform"]
    assert lines[4] == report["body_sha256"]
    assert lines[-1] == BOB
    assert report["headers"]["valid"] is True
    assert report["headers"]["age_s"] < 60


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"body": b'{"text":"HACK"}'}, "tw.auth_bad_signature"),
        ({"target": "/v1/other"}, "tw.auth_bad_signature"),
        ({"receiver": CHARLIE}, "tw.auth_wrong_receiver"),
    ],
)
def test_inspect_explains_failures(change: dict[str, object], code: str) -> None:
    args: dict[str, object] = {
        "method": "POST",
        "target": "/v1/transform",
        "headers": _signed(),
        "body": BODY,
    }
    args.update(change)
    report = actions.inspect_request(**args)  # type: ignore[arg-type]
    assert report["result"]["ok"] is False
    assert report["result"]["code"] == code
    assert report["result"]["cause"]
    assert report["result"]["fix"]


def test_inspect_old_capture() -> None:
    headers = _signed()
    old = str(time.time_ns() - 3_600 * 10**9)
    headers = {**headers, "X-Bittensor-Nonce": old}
    stale = actions.inspect_request(
        method="POST", target="/v1/transform", headers=headers, body=BODY
    )
    assert stale["result"]["code"] == "tw.auth_stale"
    # The nonce is signed, so changing it also breaks the signature; with the
    # freshness check off, the signature check is what remains.
    unchecked = actions.inspect_request(
        method="POST",
        target="/v1/transform",
        headers=headers,
        body=BODY,
        check_freshness=False,
    )
    assert unchecked["result"]["code"] == "tw.auth_bad_signature"


def test_inspect_freshness_off_accepts_a_real_old_request() -> None:
    headers = _signed()
    nonce = int(headers["X-Bittensor-Nonce"])
    report = actions.inspect_request(
        method="POST",
        target="/v1/transform",
        headers=headers,
        body=BODY,
        check_freshness=False,
    )
    assert report["result"]["ok"] is True
    assert report["result"]["freshness_checked"] is False
    assert int(report["headers"]["nonce"]) == nonce


def test_inspect_without_receiver() -> None:
    headers = {k: v for k, v in _signed().items() if k != "X-Bittensor-Receiver"}
    report = actions.inspect_request(
        method="POST", target="/v1/transform", headers=headers, body=BODY
    )
    assert report["result"]["code"] == "tw.auth_malformed"


def test_inspect_bad_receiver_input() -> None:
    report = actions.inspect_request(
        method="POST",
        target="/v1/transform",
        headers=_signed(),
        body=BODY,
        receiver="not-an-address",
    )
    assert report["result"] == {
        "ok": False,
        "code": "invalid_input",
        "message": report["result"]["message"],
    }


def test_inspect_malformed_headers() -> None:
    report = actions.inspect_request(
        method="POST",
        target="/v1/transform",
        headers={"X-Bittensor-Hotkey": "x", "X-Bittensor-Nonce": "-1"},
        body=BODY,
        receiver=BOB,
    )
    assert report["result"]["code"] == "tw.auth_malformed"
    assert report["headers"]["valid"] is False
    assert "signed_payload_lines" not in report


@settings(max_examples=150, deadline=None)
@given(
    headers=st.dictionaries(
        st.sampled_from(
            [
                "X-Bittensor-Version",
                "X-Bittensor-Hotkey",
                "X-Bittensor-Receiver",
                "X-Bittensor-Nonce",
                "X-Bittensor-Crypto",
                "X-Bittensor-Signature",
                "Other",
            ]
        ),
        st.text(max_size=80),
        max_size=7,
    ),
    body=st.binary(max_size=200),
    target=st.text(max_size=40),
)
def test_inspect_never_crashes_on_arbitrary_input(
    headers: dict[str, str], body: bytes, target: str
) -> None:
    report = actions.inspect_request(
        method="POST", target=target, headers=headers, body=body, receiver=BOB
    )
    assert report["result"]["ok"] is False


def test_decode_body() -> None:
    assert actions.decode_body("aGk=", "base64") == b"hi"
    assert actions.decode_body("hi", "utf-8") == b"hi"
    with pytest.raises(ValueError, match="base64"):
        actions.decode_body("!!", "base64")


def test_inspect_response() -> None:
    miner = HotkeySigner(keypair_from_uri("//Bob"))
    sender = keypair_from_uri("//Alice").ss58_address
    body = b'{"result":"HELLO"}'
    headers = sign_response(
        miner, request_nonce=42, sender_ss58=sender, status=200, body=body
    )
    args = {
        "headers": headers,
        "status": 200,
        "expected_responder": BOB,
        "request_nonce": 42,
        "sender": sender,
    }
    ok = actions.inspect_response(body=body, **args)  # type: ignore[arg-type]
    assert ok["result"] == {"ok": True, "scheme": "sr25519"}
    assert ok["signed_payload_lines"][0] == "twresp/1"
    tampered = actions.inspect_response(body=b"{}", **args)  # type: ignore[arg-type]
    assert tampered["result"]["code"] == "tw.bad_response_signature"
    other = actions.inspect_response(
        body=body,
        **{**args, "request_nonce": 43},  # type: ignore[arg-type]
    )
    assert other["result"]["ok"] is False
    bad_scheme = actions.inspect_response(
        body=body,
        **{**args, "headers": {**headers, "X-TW-Resp-Crypto": "rsa"}},  # type: ignore[arg-type]
    )
    assert bad_scheme["result"]["ok"] is False
    assert "payload_error" in bad_scheme


def test_scaffold_project(tmp_path: Path) -> None:
    out = actions.scaffold_project(tmp_path / "my-subnet")
    assert out["package"] == "my_subnet"
    assert "my_subnet/miner.py" in out["files"]
    assert (tmp_path / "my-subnet/my_subnet/miner.py").is_file()
    with pytest.raises(FileExistsError):
        actions.scaffold_project(tmp_path / "my-subnet")


def _git_copy(tmp_path: Path) -> Path:
    repo = tmp_path / "v10"
    shutil.copytree(BEFORE, repo)
    git = ["git", "-C", str(repo)]
    ident = ["-c", "user.email=t@example.com", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)  # noqa: S603
    subprocess.run([*git, "add", "-A"], check=True)  # noqa: S603
    subprocess.run([*git, *ident, "commit", "-qm", "v10"], check=True)  # noqa: S603
    return repo


@pytest.mark.skipif(not BEFORE.is_dir(), reason="needs the repository")
def test_migrate_scan_and_apply(tmp_path: Path) -> None:
    repo = _git_copy(tmp_path)
    scan = actions.migrate_scan(repo)
    assert scan["findings"]
    assert scan["all_auto"] is False
    dry = actions.migrate_apply(repo, write=False, allow_dirty=False)
    assert dry["written"] is False
    assert dry["diff"].startswith("---")
    tracked = next(repo.rglob("*.py"))
    tracked.write_text(tracked.read_text() + "# edit\n")
    with pytest.raises(PermissionError, match="uncommitted"):
        actions.migrate_apply(repo, write=True, allow_dirty=False)
    done = actions.migrate_apply(repo, write=True, allow_dirty=True)
    assert done["written"] is True
    assert "diff" not in done


def test_migrate_refuses_a_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        actions.migrate_scan(tmp_path / "nope")
    with pytest.raises(NotADirectoryError):
        actions.migrate_apply(tmp_path / "nope", write=False, allow_dirty=False)


def test_migrate_apply_refuses_outside_git(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import bittensor as bt\n")
    with pytest.raises(PermissionError, match="not in a git repository"):
        actions.migrate_apply(tmp_path, write=True, allow_dirty=False)


async def test_doctor_refuses_a_missing_env_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        await actions.doctor("miner", tmp_path / "nope.env")


async def test_read_metagraph_unreachable_chain() -> None:
    with pytest.raises(RuntimeError, match="chain read failed"):
        await actions.read_metagraph("ws://127.0.0.1:1", 2, timeout_s=0.5)


def test_base64_body_reaches_the_check() -> None:
    encoded = base64.b64encode(BODY).decode()
    report = actions.inspect_request(
        method="POST",
        target="/v1/transform",
        headers=_signed(),
        body=actions.decode_body(encoded, "base64"),
    )
    assert report["result"]["ok"] is True
