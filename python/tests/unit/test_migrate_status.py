"""``tensorwire migrate status`` (spec 10b.5): numbers from real metrics text."""

from __future__ import annotations

import datetime as dt
import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from prometheus_client import start_http_server
from typer.testing import CliRunner

from tensorwire.cli.main import app
from tensorwire.migrate import status as rollout
from tensorwire.observability.metrics import Metrics

TODAY_NS = int(dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc).timestamp() * 1e9)


def validator_metrics(btauth: int, v10: int, outbound: int = 0) -> Metrics:
    m = Metrics()
    m.validator_miners_by_protocol.labels(protocol="btauth/1").set(btauth)
    m.validator_miners_by_protocol.labels(protocol="v10").set(v10)
    if outbound:
        m.legacy_v10_requests.labels(direction="outbound", result="ok").inc(outbound)
    m.track_legacy_v10_end("outbound", dt.date(2026, 11, 20), clock_ns=lambda: TODAY_NS)
    return m


def miner_metrics(ok: int, refused: int, until: dt.date | None) -> Metrics:
    m = Metrics()
    m.legacy_v10_requests.labels(direction="inbound", result="ok").inc(ok)
    m.legacy_v10_requests.labels(
        direction="inbound", result="tw.legacy_auth_failed"
    ).inc(refused)
    if until is not None:
        m.track_legacy_v10_end("inbound", until, clock_ns=lambda: TODAY_NS)
    return m


def text(m: Metrics) -> str:
    return m.render().decode()


def test_validator_numbers() -> None:
    s = rollout.parse_metrics_text(text(validator_metrics(19, 1, outbound=7)), "v")
    assert (s.miners_btauth, s.miners_v10) == (19, 1)
    assert s.outbound_v10_total == 7
    assert s.inbound_v10_total == 0
    assert s.days_remaining == {"inbound": None, "outbound": 28}


def test_miner_numbers_count_every_result() -> None:
    s = rollout.parse_metrics_text(
        text(miner_metrics(5, 2, dt.date(2026, 10, 30))), "m"
    )
    assert (s.miners_btauth, s.miners_v10) == (0, 0)
    assert s.inbound_v10_total == 7
    assert s.days_remaining == {"inbound": 7, "outbound": None}


def test_fresh_process_reports_zero() -> None:
    s = rollout.parse_metrics_text(text(Metrics()), "fresh")
    assert s.inbound_v10_total == s.outbound_v10_total == 0
    assert s.days_remaining == {"inbound": None, "outbound": None}


def test_report_sums_sources_and_takes_smallest_days() -> None:
    a = rollout.parse_metrics_text(text(validator_metrics(10, 0)), "a")
    b = rollout.parse_metrics_text(text(validator_metrics(9, 1)), "b")
    m = rollout.parse_metrics_text(text(miner_metrics(1, 0, dt.date(2026, 11, 1))), "m")
    r = rollout.build_report([a, b, m], min_btauth_share=0.95)
    assert (r.miners_btauth, r.miners_v10) == (19, 1)
    assert r.btauth_share == pytest.approx(0.95)
    assert r.share_met is True
    assert r.days_remaining == {"inbound": 9, "outbound": 28}
    assert r.exit_code == 0


def test_share_not_met_and_unknown_share() -> None:
    low = rollout.parse_metrics_text(text(validator_metrics(8, 2)), "v")
    assert rollout.build_report([low], min_btauth_share=0.95).exit_code == 1
    none = rollout.build_report([], min_btauth_share=0.5)
    assert none.btauth_share is None
    assert none.share_met is False
    assert rollout.build_report([]).share_met is None


@pytest.mark.parametrize(
    "bad",
    [
        'tw_validator_miners_by_protocol{protocol="v10" 3\n',
        'tw_validator_miners_by_protocol{protocol="v10"} NaN\n',
        'tw_legacy_v10_requests_total{direction="inbound",result="ok"} -1\n',
        'tw_legacy_v10_days_remaining{direction="inbound"} +Inf\n',
        "not metrics at all\n",
    ],
)
def test_bad_text_is_a_metrics_text_error(bad: str) -> None:
    with pytest.raises(rollout.MetricsTextError):
        rollout.parse_metrics_text(bad, "x")


def test_other_labels_and_metrics_are_ignored() -> None:
    s = rollout.parse_metrics_text(
        'tw_validator_miners_by_protocol{protocol="grpc"} 4\n'
        'tw_legacy_v10_requests_total{direction="sideways",result="ok"} 2\n'
        "tw_requests_total 9\n",
        "x",
    )
    assert (s.miners_btauth, s.miners_v10, s.inbound_v10_total) == (0, 0, 0)


def test_render_text_and_json() -> None:
    v = rollout.parse_metrics_text(text(validator_metrics(19, 1, outbound=3)), "v")
    r = rollout.build_report(
        [v], [{"source": "http://x", "error": "HTTP 500"}], min_btauth_share=0.95
    )
    out = rollout.render(r, "text")
    assert "btauth/1 19, v10 1" in out
    assert "btauth/1 share: 95.0%" in out
    assert "outbound 3" in out
    assert "unreachable: http://x (HTTP 500)" in out
    assert "--min-btauth-share 0.95: met" in out
    data = json.loads(rollout.render(r, "json"))
    assert data["miners_btauth"] == 19
    assert data["btauth_share"] == pytest.approx(0.95)
    assert data["share_met"] is True
    assert data["unreachable"] == [{"source": "http://x", "error": "HTTP 500"}]
    assert data["sources"][0]["source"] == "v"
    assert r.exit_code == 2
    empty = rollout.render(rollout.build_report([]), "text")
    assert "n/a (no validator round seen)" in empty
    assert "inbound not set" in empty


def test_read_file_limits(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(b"#" * (rollout.MAX_METRICS_BYTES + 1))
    with pytest.raises(OSError, match="larger"):
        rollout.read_file(big)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\xff\xfe")
    with pytest.raises(OSError, match="UTF-8"):
        rollout.read_file(binary)


# ------------------------------------------------------------------ CLI


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def live_validator() -> Iterator[str]:
    """A real metrics listener, as the validator serves on TW_METRICS_BIND."""
    port = _free_port()
    m = validator_metrics(19, 1, outbound=2)
    server, thread = start_http_server(port, addr="127.0.0.1", registry=m.registry)
    yield f"http://127.0.0.1:{port}/metrics"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_cli_url_and_file(live_validator: str, tmp_path: Path) -> None:
    saved = tmp_path / "miner.prom"
    saved.write_text(text(miner_metrics(3, 0, dt.date(2026, 11, 1))))
    result = CliRunner().invoke(
        app,
        [
            "migrate", "status",
            "--metrics-url", live_validator,
            "--metrics-file", str(saved),
            "--min-btauth-share", "0.95",
            "--format", "json",
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [s["source"] for s in data["sources"]] == [live_validator, str(saved)]
    assert data["miners_btauth"] == 19
    assert data["inbound_v10_total"] == 3
    assert data["outbound_v10_total"] == 2


def test_cli_share_not_met_exits_1(tmp_path: Path) -> None:
    saved = tmp_path / "v.prom"
    saved.write_text(text(validator_metrics(1, 1)))
    result = CliRunner().invoke(
        app,
        [
            "migrate",
            "status",
            "--metrics-file",
            str(saved),
            "--min-btauth-share",
            "0.95",
        ],
    )
    assert result.exit_code == 1
    assert "NOT met" in result.output


def test_cli_unreadable_sources_exit_2(tmp_path: Path) -> None:
    garbage = tmp_path / "g.prom"
    garbage.write_text("{{{\n")
    port = _free_port()  # nothing listens here
    result = CliRunner().invoke(
        app,
        [
            "migrate", "status",
            "--metrics-url", f"http://127.0.0.1:{port}/metrics",
            "--metrics-file", str(garbage),
            "--metrics-file", str(tmp_path / "missing.prom"),
        ],
    )  # fmt: skip
    assert result.exit_code == 2
    assert "unreachable: 3" in result.output
    assert "ConnectError" in result.output
    assert "not Prometheus text format" in result.output


@pytest.fixture
def odd_server() -> Iterator[str]:
    """``/redirect`` answers 302, ``/big`` more than the size cap."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/metrics")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            chunk = b"#" * 65536
            for _ in range(rollout.MAX_METRICS_BYTES // len(chunk) + 1):
                self.wfile.write(chunk)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_read_url_does_not_follow_redirects(odd_server: str) -> None:
    with pytest.raises(OSError, match="HTTP 302"):
        rollout.read_url(f"{odd_server}/redirect")


def test_read_url_caps_the_answer(odd_server: str) -> None:
    with pytest.raises(OSError, match="larger"):
        rollout.read_url(f"{odd_server}/big")


def test_cli_needs_a_source_and_a_known_format() -> None:
    assert CliRunner().invoke(app, ["migrate", "status"]).exit_code == 2
    result = CliRunner().invoke(
        app, ["migrate", "status", "--metrics-file", "x", "--format", "md"]
    )
    assert result.exit_code == 2
