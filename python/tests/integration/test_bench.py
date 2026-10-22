"""``tensorwire bench`` (spec 13.7): its pieces in process, and one short real run."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from tensorwire.cli import bench_cmd
from tensorwire.cli.main import app
from tensorwire.config import MinerSettings
from tensorwire.testing import bench as tb
from tensorwire.testing.keys import dev_key


def settings() -> MinerSettings:
    return MinerSettings(
        netuid=tb.BENCH_NETUID,
        wallet_name="bench",
        wallet_path=Path("/nonexistent"),
        external_ip="127.0.0.2",
        allow_private_axons=True,
        ntp_servers=(),
        rate_ip_per_s=1_000_000,
        rate_ip_burst=1_000_000,
        rate_hotkey_per_s=1_000_000,
        rate_hotkey_burst=1_000_000,
    )


def test_bench_body_and_percentile() -> None:
    assert len(tb.bench_body(1024)) == 1024
    with pytest.raises(ValueError, match="at least"):
        tb.bench_body(3)
    assert tb.percentile([3.0, 1.0, 2.0, 4.0], 0.5) == 2.0
    assert tb.percentile([3.0, 1.0, 2.0, 4.0], 0.99) == 4.0
    assert tb.percentile([], 0.5) != tb.percentile([], 0.5)  # NaN


def test_validator_keys_are_distinct_and_bounded() -> None:
    assert tb.bench_validator(0).ss58_address == dev_key("alice").ss58
    keys = {tb.bench_validator(i).ss58_address for i in range(tb.MAX_LOAD_PROCESSES)}
    assert len(keys) == tb.MAX_LOAD_PROCESSES
    with pytest.raises(ValueError, match="validator index"):
        tb.bench_validator(tb.MAX_LOAD_PROCESSES)


def test_worker_app_attribute() -> None:
    with pytest.raises(AttributeError):
        _ = tb.no_such_thing  # type: ignore[attr-defined]


def test_parse_cpus() -> None:
    assert bench_cmd.parse_cpus("0-3,6") == [0, 1, 2, 3, 6]
    assert bench_cmd.parse_cpus("none") is None
    assert bench_cmd.parse_cpus(None) is None
    with pytest.raises(Exception, match="CPU list"):
        bench_cmd.parse_cpus("-1")


async def test_load_and_auth_overhead_in_process() -> None:
    miner = tb.bench_miner(settings())
    async with miner.running() as asgi:
        stats = await tb.run_load(
            "http://127.0.0.1:8091" + tb.BENCH_ROUTE,
            validator=1,
            miner_hotkey=dev_key("bob").ss58,
            body=tb.bench_body(1024),
            concurrency=4,
            duration_s=0.5,
            warmup_s=0.1,
            transport=httpx.ASGITransport(app=asgi),
        )
        timings = await tb.auth_overhead(miner, 20, body=tb.bench_body(1024))
    assert stats.ok > 0
    assert stats.failed == 0
    assert stats.statuses == {"200": stats.ok}
    assert len(stats.latencies) == stats.ok
    assert len(timings) == 20
    assert all(t > 0 for t in timings)


async def test_auth_overhead_needs_the_bench_route() -> None:
    from tensorwire.miner.app import Miner

    plain = tb.bench_miner(settings())
    other = Miner(
        settings(),
        gateway=plain.lifecycle.parts.gateway,
        metagraph=plain.lifecycle.parts.metagraph,
        hotkey=dev_key("bob").keypair,
        check_sdk=False,
    )
    async with other.running():
        with pytest.raises(ValueError, match="bench miner"):
            await tb.auth_overhead(other, 1, body=b"{}")


async def test_fanout_in_process() -> None:
    async with tb.serve_miners([0, 1, 2]) as ports:
        assert sorted(ports) == [0, 1, 2]
        seen: list[tuple[int, int]] = []
        rounds = await tb.fanout(
            tb.fanout_neurons(ports),
            body=tb.bench_body(256),
            rounds=2,
            max_concurrency=8,
            on_round=lambda i, t, n: seen.append((i, n)),
        )
    assert [n for _, n in rounds] == [3, 3]  # every answer twresp-verified
    assert seen == [(0, 3), (1, 3)]


def test_cli_short_run(tmp_path: Path) -> None:
    out = tmp_path / "bench.json"
    result = CliRunner().invoke(
        app,
        [
            "bench",
            "--duration",
            "1",
            "--warmup",
            "0.2",
            "--workers",
            "1",
            "--clients",
            "1",
            "--concurrency",
            "2",
            "--auth-requests",
            "20",
            "--fanout-miners",
            "4",
            "--fanout-hosts",
            "2",
            "--fanout-rounds",
            "1",
            "--miner-cpus",
            "none",
            "--client-cpus",
            "none",
            "--json",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text())
    assert report["throughput"]["ok"] > 0
    assert report["throughput"]["failed"] == 0
    assert report["fanout"]["n_ok_verified"] == [4]
    assert set(report["verdict"]) == {"rps", "auth_p50", "auth_p99", "fanout"}
    assert "verified requests/s" in result.output
    assert "fan-out to 4 miners" in result.output


def test_cli_refuses_workers_without_redis() -> None:
    result = CliRunner().invoke(app, ["bench", "--workers", "2"])
    assert result.exit_code != 0
    assert "redis-url" in result.output


def test_cli_rejects_unknown_skip() -> None:
    result = CliRunner().invoke(app, ["bench", "--workers", "1", "--skip", "nope"])
    assert result.exit_code != 0


def test_render_marks_skipped_and_misses() -> None:
    report = bench_cmd.BenchReport(
        environment={"tensorwire": "x"},
        auth={"p50_ms": 3.0, "p99_ms": 9.0, "requests": 1, "backend": "memory"},
    )
    report.verdict = bench_cmd._verdict(report, bench_cmd.Targets())
    text = bench_cmd.render(report, bench_cmd.Targets())
    assert report.verdict == {
        "rps": None,
        "auth_p50": False,
        "auth_p99": False,
        "fanout": None,
    }
    assert "[MISS] auth + policy p50: 3.0 ms" in text
    assert "unpinned" in text
