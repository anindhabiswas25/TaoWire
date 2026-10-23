"""Prometheus metrics (spec Appendix B).

:class:`Metrics` registers the whole Appendix B catalogue on its own
``CollectorRegistry``, so several miners (or tests) in one process never
collide. The miner serves it on ``TW_METRICS_BIND`` (127.0.0.1:9100 by
default), never on the public port.

Label values never include hotkeys or IPs (cardinality and privacy): routes
are the registered route paths, codes are ``tw.*`` codes.

With ``TW_WORKERS > 1`` each uvicorn worker writes its values to the
directory in ``PROMETHEUS_MULTIPROC_DIR`` (prometheus_client's multiprocess
mode) and the supervising process serves the sum (counters, histograms) or
the most recent value (gauges) on ``TW_METRICS_BIND``; see
:func:`serve_multiprocess`.
"""

from __future__ import annotations

import datetime as dt
import os
import time
from collections.abc import Callable, Iterable
from typing import Any

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
    start_http_server,
)
from prometheus_client.asgi import make_asgi_app

__all__ = ["MULTIPROC_ENV", "Metrics", "serve_multiprocess"]

#: prometheus_client's multiprocess directory variable.
MULTIPROC_ENV = "PROMETHEUS_MULTIPROC_DIR"


def _days_left(until: dt.date, now_ns: Callable[[], int]) -> float:
    today = dt.datetime.fromtimestamp(now_ns() / 1e9, dt.timezone.utc).date()
    return float(max(0, (until - today).days))


class Metrics:
    """Every metric in Appendix B, on one registry."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = CollectorRegistry() if registry is None else registry
        #: Values go to ``PROMETHEUS_MULTIPROC_DIR`` (a ``TW_WORKERS > 1`` worker).
        self.multiprocess = bool(os.environ.get(MULTIPROC_ENV))
        r = self.registry
        recent: dict[str, Any] = {"multiprocess_mode": "mostrecent"}
        # miner request path
        self.requests = Counter(
            "tw_requests_total",
            "Requests answered, by route, HTTP status and tw code.",
            ["route", "status", "code"],
            registry=r,
        )
        self.request_duration = Histogram(
            "tw_request_duration_seconds",
            "Time from receiving a request to the end of the response.",
            ["route"],
            registry=r,
        )
        self.auth_verify_duration = Histogram(
            "tw_auth_verify_duration_seconds",
            "btauth/1 verification time, including the wait for a thread.",
            registry=r,
        )
        self.auth_failures = Counter(
            "tw_auth_failures_total", "btauth/1 rejections.", ["code"], registry=r
        )
        self.policy_denials = Counter(
            "tw_policy_denials_total",
            "Caller-policy rejections (403 and 503 tw.metagraph_stale).",
            ["code"],
            registry=r,
        )
        self.rate_limited = Counter(
            "tw_rate_limited_total",
            "Requests rejected by a token bucket.",
            ["layer"],
            registry=r,
        )
        self.payload_too_large = Counter(
            "tw_payload_too_large_total", "Requests over the body limit.", registry=r
        )
        # metagraph, clock, stores, settings
        self.metagraph_age = Gauge(
            "tw_metagraph_age_seconds",
            "Age of the metagraph snapshot (NaN before the first one).",
            registry=r,
            **recent,
        )
        self.metagraph_refresh_failures = Counter(
            "tw_metagraph_refresh_failures_total",
            "Failed metagraph refreshes.",
            registry=r,
        )
        self.metagraph_degraded = Gauge(
            "tw_metagraph_degraded",
            "Staleness stage: 0 fresh, 1 degraded, 2 known-callers-only.",
            registry=r,
            **recent,
        )
        self.clock_offset = Gauge(
            "tw_clock_offset_seconds",
            "Wall-clock offset against NTP (NaN when unknown).",
            registry=r,
            **recent,
        )
        self.clock_step = Gauge(
            "tw_clock_step_seconds",
            "Size of the last backwards wall-clock step that opened the "
            "fail-closed window (0 = none since start).",
            registry=r,
            **recent,
        )
        self.nonce_store_errors = Counter(
            "tw_nonce_store_errors_total",
            "Replay-store failures (fail-closed 503s).",
            ["backend"],
            registry=r,
        )
        self.unsafe_settings_active = Gauge(
            "tw_unsafe_settings_active",
            "1 for each active setting that weakens a secure default (spec 16.2).",
            ["name"],
            registry=r,
            **recent,
        )
        # legacy v10 bridge
        self.legacy_v10_requests = Counter(
            "tw_legacy_v10_requests_total",
            "Requests over the legacy v10 bridge.",
            ["direction", "result"],
            registry=r,
        )
        self.legacy_v10_days_remaining = Gauge(
            "tw_legacy_v10_days_remaining",
            "Days until the legacy v10 bridge end date.",
            ["direction"],
            registry=r,
            **recent,
        )
        # validator
        self.validator_miners_by_protocol = Gauge(
            "tw_validator_miners_by_protocol",
            "Miners reached per protocol.",
            ["protocol"],
            registry=r,
            **recent,
        )
        self.validator_round_duration = Histogram(
            "tw_validator_round_duration_seconds",
            "Duration of one validator round.",
            registry=r,
        )
        self.validator_miner_results = Counter(
            "tw_validator_miner_results_total",
            "Miner query results.",
            ["ok", "code"],
            registry=r,
        )
        self.validator_weight_submissions = Counter(
            "tw_validator_weight_submissions_total",
            "set_weights submissions.",
            ["ok", "code"],
            registry=r,
        )
        self.validator_last_weights_block = Gauge(
            "tw_validator_last_weights_block",
            "Block of the last successful weight submission.",
            registry=r,
            **recent,
        )
        self.metagraph_age.set(float("nan"))
        self.clock_offset.set(float("nan"))

    def set_unsafe_settings(self, names: Iterable[str]) -> None:
        """Export ``tw_unsafe_settings_active{name}`` = 1 for each name."""
        for name in names:
            self.unsafe_settings_active.labels(name=name).set(1)

    def track_legacy_v10_end(
        self,
        direction: str,
        until: dt.date,
        *,
        clock_ns: Callable[[], int] | None = None,
    ) -> None:
        """Keep ``tw_legacy_v10_days_remaining{direction}`` current (spec 8.11.2).

        The value is computed at every scrape from ``until`` and today's UTC
        date (``clock_ns``, wall-clock nanoseconds; tests inject one), so a
        long-running process reports the real count and the "< 14 days"
        alert fires on time. 0 from the end date on.
        """
        if self.multiprocess:
            return  # the supervising process exports it (serve_multiprocess)
        now_ns = time.time_ns if clock_ns is None else clock_ns
        self.legacy_v10_days_remaining.labels(direction=direction).set_function(
            lambda: _days_left(until, now_ns)
        )

    def render(self) -> bytes:
        """The registry in Prometheus text format."""
        return generate_latest(self.registry)

    def asgi_app(self) -> Callable[..., Any]:
        """An ASGI app serving :meth:`render` (for the metrics listener)."""
        return make_asgi_app(self.registry)


def serve_multiprocess(
    path: str,
    host: str,
    port: int,
    *,
    legacy_until: dt.date | None = None,
) -> Callable[[], None]:
    """Serve every worker's metrics from ``path`` on ``host:port`` (a thread).

    For the supervising process of a ``TW_WORKERS > 1`` miner. The workers
    must have ``PROMETHEUS_MULTIPROC_DIR=path`` in their environment before
    they import ``prometheus_client``. ``tw_legacy_v10_days_remaining`` is
    computed here at every scrape (workers do not export it). Returns a
    function that stops the server.
    """
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry, path=path)  # type: ignore[no-untyped-call]
    if legacy_until is not None:
        days = Gauge(
            "tw_legacy_v10_days_remaining",
            "Days until the legacy v10 bridge end date.",
            ["direction"],
            registry=registry,
        )
        days.labels(direction="inbound").set_function(
            lambda: _days_left(legacy_until, time.time_ns)
        )
    server, thread = start_http_server(port, addr=host, registry=registry)

    def stop() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    return stop
