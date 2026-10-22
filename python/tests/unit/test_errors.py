"""errors.py: the catalogue matches Appendix A; classes carry the right codes."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

import pytest

from tensorwire import errors as e


def _appendix_a(spec_text: str) -> str:
    start = spec_text.index("## Appendix A")
    return spec_text[start : spec_text.index("## Appendix B", start)]


def test_every_appendix_a_code_is_in_the_catalogue(spec_text: str) -> None:
    rows = re.findall(
        r"^\| `(tw\.[a-z0-9_]+)` \| (\d{3}) \|", _appendix_a(spec_text), re.M
    )
    assert len(rows) == 19
    for code, status in rows:
        assert code in e.ERROR_CODES, code
        assert e.ERROR_CODES[code].http_status == int(status), code


def test_signed_column_matches_appendix_a(spec_text: str) -> None:
    rows = re.findall(
        r"^\| `(tw\.[a-z0-9_]+)` \| \d{3} \| [^|]+ \| ([^|]+) \|",
        _appendix_a(spec_text),
        re.M,
    )
    for code, signed in rows:
        expected = {"no": False}.get(
            signed.strip(), True if signed.strip().startswith("yes") else None
        )
        assert e.ERROR_CODES[code].signed is expected, code


def test_client_codes_match_appendix_a(spec_text: str) -> None:
    line = next(
        ln
        for ln in _appendix_a(spec_text).splitlines()
        if ln.startswith("Client-side only")
    )
    codes = set(re.findall(r"`(tw\.[a-z_<>]+)`", line)) - {"tw.http_<status>"}
    assert codes == e.CLIENT_ERROR_CODES
    assert e.client_http_code(502) == "tw.http_502"
    with pytest.raises(ValueError, match="not an HTTP status"):
        e.client_http_code(42)


def test_catalogue_rejects_duplicates() -> None:
    spec = e.ErrorSpec("tw.x", 500, "x", signed=False)
    with pytest.raises(RuntimeError, match="duplicate"):
        e._catalogue(spec, spec)


@pytest.mark.parametrize(
    ("factory", "code", "status"),
    [
        (lambda: e.TWError(), "tw.internal", 500),
        (lambda: e.AuthFailed(), "tw.auth_failed", 401),
        (lambda: e.AuthFailed(code="tw.auth_stale"), "tw.auth_stale", 401),
        (lambda: e.Forbidden(), "tw.forbidden_denied", 403),
        (
            lambda: e.Forbidden(code="tw.forbidden_low_stake"),
            "tw.forbidden_low_stake",
            403,
        ),
        (
            lambda: e.Forbidden(code="tw.forbidden_blacklisted"),
            "tw.forbidden_blacklisted",
            403,
        ),
        (lambda: e.PayloadTooLarge(), "tw.payload_too_large", 413),
        (lambda: e.RateLimited(retry_after_s=0.2, layer="ip"), "tw.rate_limited", 429),
        (lambda: e.MetagraphStale(), "tw.metagraph_stale", 503),
        (lambda: e.ReplayStoreUnavailable(), "tw.replay_store_unavailable", 503),
        (lambda: e.InvalidRequest(), "tw.invalid_request", 422),
        (lambda: e.HandlerError(), "tw.handler_error", 500),
        (lambda: e.HandlerTimeout(), "tw.handler_timeout", 504),
        (lambda: e.LegacyAuthFailed(), "tw.legacy_auth_failed", 401),
        (lambda: e.LegacyDisabled(), "tw.legacy_disabled", 410),
        (lambda: e.ConfigError("bad"), "tw.config_invalid", 500),
        (lambda: e.ChainError("rate_limited", "wait"), "tw.internal", 500),
    ],
)
def test_classes_carry_code_and_status(
    factory: Callable[[], e.TWError], code: str, status: int
) -> None:
    err = factory()
    assert isinstance(err, e.TWError)
    assert err.code == code
    assert err.http_status == status
    assert err.public_message == e.ERROR_CODES[code].public_message
    assert repr(err).startswith(type(err).__name__)


def test_family_rejects_foreign_codes() -> None:
    with pytest.raises(ValueError, match="cannot carry"):
        e.AuthFailed(code="tw.forbidden_denied")
    with pytest.raises(ValueError, match="cannot carry"):
        e.Forbidden(code="tw.auth_stale")
    with pytest.raises(ValueError, match="cannot carry"):
        e.PayloadTooLarge(code="tw.internal")


def test_custom_public_message_is_kept() -> None:
    err = e.AuthFailed(
        "nonce is older than the 10s freshness window", code="tw.auth_stale"
    )
    assert (
        err.public_message == str(err) == "nonce is older than the 10s freshness window"
    )


def test_response_body_shape() -> None:
    body = json.loads(e.AuthFailed(code="tw.auth_replayed").response_body("01JABC"))
    assert body == {
        "error": {
            "code": "tw.auth_replayed",
            "message": "request was already accepted",
            "request_id": "01JABC",
        }
    }
    assert json.loads(e.TWError().response_body())["error"]["request_id"] is None
    assert e.TWError().response_headers() == {}


@pytest.mark.parametrize(
    ("retry", "header"), [(0.0, "1"), (0.01, "1"), (1.0, "1"), (1.2, "2"), (30, "30")]
)
def test_rate_limited_retry_after_is_whole_seconds(retry: float, header: str) -> None:
    err = e.RateLimited(retry_after_s=retry, layer="hotkey")
    assert err.response_headers() == {"Retry-After": header}


def test_rate_limited_signing_depends_on_layer() -> None:
    assert e.RateLimited(retry_after_s=1, layer="hotkey").signed is True
    assert e.RateLimited(retry_after_s=1, layer="ip").signed is False


@pytest.mark.parametrize("bad", [-1.0, float("nan"), float("inf")])
def test_rate_limited_rejects_bad_retry(bad: float) -> None:
    with pytest.raises(ValueError, match="retry_after_s"):
        e.RateLimited(retry_after_s=bad, layer="ip")


def test_signed_flags() -> None:
    assert e.Forbidden().signed is True
    assert e.HandlerTimeout().signed is True
    assert e.AuthFailed().signed is False
    assert e.PayloadTooLarge().signed is False


def test_chain_errors_never_leak_detail_publicly() -> None:
    err = e.ChainError("not_registered", "register first: btcli ...")
    assert err.chain_code == "not_registered"
    assert err.remediation == "register first: btcli ..."
    assert "not_registered" in str(err)
    assert err.public_message == "internal error"
    assert b"btcli" not in err.response_body()
    assert repr(err) == "ChainError(chain_code='not_registered')"


def test_config_error_detail_stays_private() -> None:
    err = e.ConfigError("TW_NETUID: field required")
    assert str(err) == "TW_NETUID: field required"
    assert err.detail == "TW_NETUID: field required"
    assert b"TW_NETUID" not in err.response_body()
