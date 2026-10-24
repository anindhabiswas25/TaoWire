"""``taowire bench`` (spec 13.7): its pieces in process, and one short real run."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from taowire.cli import bench_cmd
from taowire.cli.main import app
from taowire.config import MinerSettings
from taowire.testing import bench as tb
from taowire.testing.keys import dev_key


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
    from taowire.miner.app import Miner

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


@pytest.fixture(autouse=True)
def _keep_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    # The command sets process-wide logging; other tests read INFO logs.
    monkeypatch.setattr(bench_cmd, "configure_logging", lambda level: None)


NO_REDIS = bench_cmd.RedisPath(None, "none", "no Redis found (test)")


@pytest.fixture
def no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI tests must not depend on a Redis being up on this host."""
    monkeypatch.setattr(bench_cmd, "resolve_redis_path", lambda url: NO_REDIS)


@pytest.mark.usefixtures("no_redis")
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
    assert "redis path: none" in result.output
    assert report["environment"]["redis_path"]["kind"] == "none"


@pytest.mark.usefixtures("no_redis")
def test_cli_refuses_workers_without_redis() -> None:
    result = CliRunner().invoke(app, ["bench", "--workers", "2"])
    assert result.exit_code != 0
    assert "redis-url" in result.output


# ---------------------------------------------------------------- redis path (D17)

TW_REDIS = bench_cmd.DockerRedis(
    name="tw-redis", ip="172.17.0.3", published=(("127.0.0.1", 6379),)
)
HOST_NET = bench_cmd.DockerRedis(
    name="redis-host", ip=None, published=(), host_network=True
)


def resolve(
    url: str | None, found: list[bench_cmd.DockerRedis], up: set[str]
) -> bench_cmd.RedisPath:
    return bench_cmd.resolve_redis_path(
        url, containers=lambda: found, answers=lambda u: u in up
    )


def test_default_reaches_the_container_ip_not_docker_proxy() -> None:
    path = resolve(None, [TW_REDIS], {"redis://172.17.0.3:6379/14"})
    assert (path.url, path.kind, path.counts) == (
        "redis://172.17.0.3:6379/14",
        "direct",
        True,
    )
    assert path.describe() == "redis path: direct: container tw-redis at its own IP"


def test_default_uses_host_network_redis() -> None:
    path = resolve(None, [HOST_NET], {"redis://127.0.0.1:6379/14"})
    assert (path.url, path.kind) == ("redis://127.0.0.1:6379/14", "direct")
    assert "host network" in path.detail


def test_default_falls_back_to_the_proxy_and_says_so() -> None:
    # The container IP does not answer (e.g. Docker Desktop on macOS).
    path = resolve(None, [TW_REDIS], {"redis://127.0.0.1:6379/14"})
    assert (path.kind, path.counts) == ("docker-proxy", False)
    assert "extra information only" in path.describe()
    assert "redis://172.17.0.3:6379/14" in path.detail


def test_default_host_redis_without_docker() -> None:
    path = resolve(None, [], {"redis://127.0.0.1:6379/14"})
    assert path.kind == "direct"
    assert "not a Docker port mapping" in path.detail


def test_default_without_any_redis() -> None:
    path = resolve(None, [TW_REDIS], set())
    assert (path.url, path.kind) == (None, "none")


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("redis://127.0.0.1:6379/14", "docker-proxy"),
        ("redis://localhost:6379/3", "docker-proxy"),
        ("redis://172.17.0.3:6379/14", "direct"),
        ("unix:///run/redis.sock?db=14", "direct"),
        ("redis://127.0.0.1:6380/14", "direct"),
        ("redis://10.0.0.5:6379/14", "direct"),
    ],
)
def test_an_explicit_url_is_used_as_given_and_classified(url: str, kind: str) -> None:
    path = resolve(url, [TW_REDIS], set())
    assert (path.url, path.kind) == (url, kind)


def test_explicit_loopback_url_on_host_network_is_direct() -> None:
    path = resolve("redis://127.0.0.1:6379/14", [HOST_NET], set())
    assert path.kind == "direct"


def test_docker_inspect_is_parsed() -> None:
    inspect = [
        {
            "Name": "/tw-redis",
            "Config": {"Image": "redis:7"},
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {
                "Ports": {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": "6379"}]},
                "Networks": {"bridge": {"IPAddress": "172.17.0.3"}},
            },
        },
        {
            "Name": "/redis-host",
            "Config": {"Image": "redis:7"},
            "HostConfig": {"NetworkMode": "host"},
            "NetworkSettings": {"Ports": {}, "Networks": {"host": {"IPAddress": ""}}},
        },
        {
            "Name": "/postgres",
            "Config": {"Image": "postgres:16"},
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {"Ports": {"5432/tcp": None}, "Networks": {}},
        },
        {"Name": "/broken", "NetworkSettings": {"Ports": {"6379/tcp": [{}]}}},
        "not a container",
    ]

    def run(cmd: list[str]) -> str:
        return "a b c d e\n" if cmd[1] == "ps" else json.dumps(inspect)

    assert bench_cmd.docker_redis_containers(run) == [TW_REDIS, HOST_NET]


@pytest.mark.parametrize("output", ["", "not json"])
def test_docker_output_problems_mean_no_containers(output: str) -> None:
    def run(cmd: list[str]) -> str:
        return "a\n" if cmd[1] == "ps" and output else output

    assert bench_cmd.docker_redis_containers(run) == []


def test_no_docker_means_no_containers() -> None:
    def run(cmd: list[str]) -> str:
        raise FileNotFoundError(cmd[0])

    assert bench_cmd.docker_redis_containers(run) == []


def test_render_prints_the_redis_path() -> None:
    proxy = resolve("redis://127.0.0.1:6379/14", [TW_REDIS], set())
    report = bench_cmd.BenchReport(
        environment={"taowire": "x", "redis_path": dataclasses.asdict(proxy)}
    )
    report.verdict = bench_cmd._verdict(report, bench_cmd.Targets())
    text = bench_cmd.render(report, bench_cmd.Targets())
    assert "redis path: docker-proxy (extra information only" in text


def test_cli_rejects_unknown_skip() -> None:
    result = CliRunner().invoke(app, ["bench", "--workers", "1", "--skip", "nope"])
    assert result.exit_code != 0


def test_render_marks_skipped_and_misses() -> None:
    report = bench_cmd.BenchReport(
        environment={"taowire": "x"},
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
