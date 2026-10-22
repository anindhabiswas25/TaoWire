"""observability/: JSON logs, ULID request IDs, Appendix B metrics, middleware."""

from __future__ import annotations

import io
import json
import logging
import re
from typing import Any

import pytest
import structlog

from tensorwire.observability.logging import (
    configure_logging,
    new_request_id,
    short_hotkey,
)
from tensorwire.observability.metrics import Metrics
from tensorwire.observability.middleware import RequestContext, state_of

ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")


@pytest.fixture
def restore_logging() -> Any:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    structlog.reset_defaults()


@pytest.mark.usefixtures("restore_logging")
def test_configure_logging_emits_json_for_structlog_and_stdlib() -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    configure_logging("INFO", stream=stream)  # idempotent: one handler
    structlog.stdlib.get_logger("tensorwire.x").info("hello", route="/v1/a")
    logging.getLogger("uvicorn.error").warning("from stdlib")
    structlog.stdlib.get_logger("tensorwire.x").debug("hidden")
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [line["event"] for line in lines] == ["hello", "from stdlib"]
    first = lines[0]
    assert first["level"] == "info"
    assert first["route"] == "/v1/a"
    assert first["logger"] == "tensorwire.x"
    assert first["ts"].endswith("Z")
    assert lines[1]["level"] == "warning"


def test_short_hotkey() -> None:
    hk = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
    assert short_hotkey(hk) == "5GrwvaEF…"
    assert short_hotkey(hk, full=True) == hk
    assert short_hotkey(None) is None


def test_request_ids_are_sortable_ulids() -> None:
    ids = [new_request_id() for _ in range(50)]
    assert all(ULID_RE.fullmatch(i) for i in ids)
    assert len(set(ids)) == 50
    assert [i[:10] for i in ids] == sorted(i[:10] for i in ids)  # timestamp prefix


def test_metrics_match_appendix_b(spec_text: str) -> None:
    section = spec_text.split("## Appendix B")[1].split("## Appendix C", maxsplit=1)[0]
    rows = re.findall(r"^\| `(tw_[a-z0-9_]+)` \| (\w+) \| (.*?) \|$", section, re.M)
    assert len(rows) == 20
    registry = Metrics().registry
    families = {m.name: m for m in registry.collect()}
    for name, kind, labels_cell in rows:
        base = name.removesuffix("_total") if kind == "counter" else name
        assert base in families, name
        assert families[base].type == kind, name
        without_values = re.sub(r"\([^)]*\)", "", labels_cell)
        expected_labels = sorted(re.findall(r"`(\w+)`", without_values))
        collector = registry._names_to_collectors[name]
        assert sorted(collector._labelnames) == expected_labels, name


def test_metrics_render_and_unsafe_settings() -> None:
    m = Metrics()
    m.set_unsafe_settings(["TW_ALLOW_PRIVATE_AXONS"])
    text = m.render().decode()
    assert 'tw_unsafe_settings_active{name="TW_ALLOW_PRIVATE_AXONS"} 1.0' in text
    assert "tw_metagraph_age_seconds NaN" in text
    assert callable(m.asgi_app())


# ---------------------------------------------------------------- middleware


async def run(
    mw: RequestContext, *, scope_type: str = "http", state: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    scope: dict[str, Any] = {"type": scope_type}
    if state is not None:
        scope["state"] = state

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    async def send(message: Any) -> None:
        sent.append(message)

    await mw(scope, receive, send)
    return sent


def app_responding(status: int, **state_values: Any) -> Any:
    async def app(scope: Any, receive: Any, send: Any) -> None:
        state_of(scope).update(state_values)
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"x-tw-request-id", b"spoofed")],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    return app


async def test_middleware_sets_request_id_and_counts() -> None:
    m = Metrics()
    mw = RequestContext(app_responding(200, tw_route="/v1/a"), metrics=m)
    sent = await run(mw)
    ids = [v for k, v in sent[0]["headers"] if k == b"x-tw-request-id"]
    assert len(ids) == 1
    assert ids[0] != b"spoofed"
    assert ULID_RE.fullmatch(ids[0].decode())
    labels = {"route": "/v1/a", "status": "200", "code": "ok"}
    assert m.registry.get_sample_value("tw_requests_total", labels) == 1


@pytest.mark.parametrize(
    ("code", "extra", "metric", "labels"),
    [
        ("tw.auth_stale", {}, "tw_auth_failures_total", {"code": "tw.auth_stale"}),
        ("tw.forbidden_denied", {}, "tw_policy_denials_total",
         {"code": "tw.forbidden_denied"}),
        ("tw.metagraph_stale", {}, "tw_policy_denials_total",
         {"code": "tw.metagraph_stale"}),
        ("tw.rate_limited", {"tw_rate_layer": "hotkey"}, "tw_rate_limited_total",
         {"layer": "hotkey"}),
        ("tw.payload_too_large", {}, "tw_payload_too_large_total", {}),
        ("tw.replay_store_unavailable", {"tw_store_backend": "redis"},
         "tw_nonce_store_errors_total", {"backend": "redis"}),
    ],
)  # fmt: skip
async def test_middleware_counts_rejections_by_code(
    code: str, extra: dict[str, str], metric: str, labels: dict[str, str]
) -> None:
    m = Metrics()
    mw = RequestContext(app_responding(400, tw_code=code, **extra), metrics=m)
    await run(mw)
    assert m.registry.get_sample_value(metric, labels) == 1


async def test_middleware_labels_unknown_paths_unmatched_and_survives_errors() -> None:
    m = Metrics()

    async def crash(scope: Any, receive: Any, send: Any) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await run(RequestContext(crash, metrics=m))
    labels = {"route": "unmatched", "status": "500", "code": "http_500"}
    assert m.registry.get_sample_value("tw_requests_total", labels) == 1


async def test_middleware_ignores_non_http() -> None:
    m = Metrics()
    seen: list[str] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    await run(RequestContext(app, metrics=m), scope_type="lifespan")
    assert seen == ["lifespan"]
    assert m.registry.get_sample_value("tw_requests_total", {}) is None


async def test_full_hotkeys_only_at_debug() -> None:
    hk = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
    for full, expected in ((False, "5GrwvaEF…"), (True, hk)):
        mw = RequestContext(
            app_responding(200, tw_caller=hk),
            metrics=Metrics(),
            log_full_hotkeys=lambda f=full: f,
        )
        with structlog.testing.capture_logs() as logs:
            await run(mw)
        assert logs[-1]["caller_hotkey"] == expected
