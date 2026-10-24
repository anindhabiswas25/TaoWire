"""The MCP server's knowledge: error codes, settings and the bundled docs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from taowire.config import known_variables
from taowire.errors import CLIENT_ERROR_CODES, ERROR_CODES
from taowire.mcp_server import knowledge

REPO = Path(__file__).resolve().parents[3]


def test_every_error_code_has_a_hint() -> None:
    codes = set(ERROR_CODES) | CLIENT_ERROR_CODES
    assert codes == set(knowledge.ERROR_HINTS)
    for code, (raised_by, cause, fix) in knowledge.ERROR_HINTS.items():
        assert raised_by in {"miner", "validator", "sidecar"}, code
        assert cause, code
        assert fix, code


def test_explain_server_code_uses_the_catalogue() -> None:
    e = knowledge.explain_error(" tw.auth_stale ")
    assert e.known
    assert e.http_status == 401
    assert e.public_message == ERROR_CODES["tw.auth_stale"].public_message
    assert e.response_signed == "no"
    assert "clock" in e.cause


def test_explain_signed_and_layered_codes() -> None:
    assert (
        knowledge.explain_error("tw.forbidden_not_validator").response_signed == "yes"
    )
    rate = knowledge.explain_error("tw.rate_limited")
    assert rate.response_signed == "depends on the layer"


def test_explain_client_code() -> None:
    e = knowledge.explain_error("tw.bad_response_signature")
    assert e.known
    assert e.raised_by == "validator"
    assert e.http_status is None
    assert e.response_signed == "n/a (client side)"


def test_explain_http_code() -> None:
    e = knowledge.explain_error("tw.http_502")
    assert e.known
    assert e.http_status == 502
    assert "502" in e.cause


@pytest.mark.parametrize("code", ["tw.nope", "", "tw.http_99", "tw.http_600", "x"])
def test_explain_unknown_code(code: str) -> None:
    e = knowledge.explain_error(code)
    assert not e.known
    assert e.http_status is None


def test_all_error_codes_sorted_and_complete() -> None:
    codes = knowledge.all_error_codes()
    assert codes == sorted(codes)
    assert set(codes) == set(ERROR_CODES) | CLIENT_ERROR_CODES


def test_settings_cover_every_known_variable() -> None:
    names = {s.name for s in knowledge.list_settings("all")}
    assert names == known_variables()


def test_settings_details() -> None:
    by_name = {s.name: s for s in knowledge.list_settings("all")}
    port = by_name["TW_BIND_PORT"]
    assert port.default == "8091"
    assert port.limits == ">= 1, <= 65535"
    assert port.roles == ("miner",)
    assert by_name["TW_NETUID"].required
    assert set(by_name["TW_NETWORK"].roles) == {
        "common",
        "miner",
        "validator",
        "sidecar",
    }
    assert by_name["TW_REDIS_URL"].default == "unset"
    assert "TW_WORKERS" in by_name["TW_REDIS_URL"].description
    assert by_name["TW_REFUSE_IF_COLDKEY_PRESENT"].default == "1"
    assert by_name["TW_NTP_SERVERS"].default == "pool.ntp.org,time.cloudflare.com"


def test_settings_for_one_role() -> None:
    miner = {s.name for s in knowledge.list_settings("miner")}
    validator = {s.name for s in knowledge.list_settings("validator")}
    assert "TW_BIND_PORT" in miner
    assert "TW_BIND_PORT" not in validator
    assert "TW_SCORE_ALPHA" in validator


def test_docs_are_bundled_without_internal_files() -> None:
    docs = {d.name: d for d in knowledge.doc_names()}
    assert {"quickstart", "miner-guide", "protocol/twresp-1"} <= set(docs)
    assert not any(name.startswith("team") for name in docs)
    assert docs["quickstart"].title.startswith("Quickstart")
    assert docs["quickstart"].size > 1000


@pytest.mark.parametrize("name", ["quickstart", "quickstart.md", "docs/quickstart"])
def test_read_doc_accepts_name_forms(name: str) -> None:
    assert knowledge.read_doc(name).startswith("# Quickstart")


def test_read_unknown_doc() -> None:
    with pytest.raises(KeyError):
        knowledge.read_doc("../../pyproject")


def test_search_docs() -> None:
    hits = knowledge.search_docs("TW_REDIS_URL TW_WORKERS", limit=3)
    assert 0 < len(hits) <= 3
    assert all("tw_redis_url" in h["text"].lower() for h in hits)
    assert {"doc", "line", "section", "text"} <= set(hits[0])
    assert knowledge.search_docs("   ") == []
    assert knowledge.search_docs("zzqqxx-no-such-word") == []


@pytest.mark.skipif(not (REPO / "docs").is_dir(), reason="needs the repository")
def test_bundled_data_matches_the_repository() -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(REPO / "scripts/sync_mcp_data.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "run scripts/sync_mcp_data.py:\n" + result.stdout + result.stderr
    )
