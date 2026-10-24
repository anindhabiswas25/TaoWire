"""``taowire migrate status``: the numbers for the rollout runbook (spec 10b.5).

Reads the Prometheus ``/metrics`` text of validators and/or miners (live
URLs, or files saved earlier) and reports:

- ``miners_btauth`` / ``miners_v10``: the sum over validators of
  ``tw_validator_miners_by_protocol`` (miners that answered over each
  protocol in the validator's last round), and the btauth/1 share
  (stage 2 exit check);
- ``inbound_v10_total`` / ``outbound_v10_total``: the sum of
  ``tw_legacy_v10_requests_total`` per direction, every result included
  (stage 3 and 4 exit checks);
- ``days_remaining``: the smallest ``tw_legacy_v10_days_remaining`` per
  direction across the sources.

Needs nothing beyond the core install (no libcst). Parsing uses
``prometheus_client``'s own text parser; any text it cannot read is a
:class:`MetricsTextError`, never another exception.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx
from prometheus_client.parser import text_string_to_metric_families

__all__ = [
    "MAX_METRICS_BYTES",
    "MetricsTextError",
    "SourceStatus",
    "StatusReport",
    "build_report",
    "parse_metrics_text",
    "read_file",
    "read_url",
    "render",
]

#: Largest ``/metrics`` answer or file read (a kit node exports a few KiB).
MAX_METRICS_BYTES = 8 * 1024 * 1024

_BY_PROTOCOL = "tw_validator_miners_by_protocol"
_REQUESTS = "tw_legacy_v10_requests_total"
_DAYS = "tw_legacy_v10_days_remaining"
_DIRECTIONS = ("inbound", "outbound")


class MetricsTextError(ValueError):
    """The text is not Prometheus exposition format the command can read."""


@dataclass(frozen=True)
class SourceStatus:
    """The migration numbers of one ``/metrics`` source."""

    source: str
    miners_btauth: int = 0
    miners_v10: int = 0
    inbound_v10_total: float = 0.0
    outbound_v10_total: float = 0.0
    days_remaining: dict[str, int | None] = field(
        default_factory=lambda: dict.fromkeys(_DIRECTIONS)
    )


@dataclass(frozen=True)
class StatusReport:
    """The numbers summed over every source that could be read."""

    sources: list[SourceStatus]
    unreachable: list[dict[str, str]]
    miners_btauth: int
    miners_v10: int
    btauth_share: float | None
    inbound_v10_total: float
    outbound_v10_total: float
    days_remaining: dict[str, int | None]
    min_btauth_share: float | None = None

    @property
    def share_met(self) -> bool | None:
        """``None`` without ``--min-btauth-share``; else whether it is met."""
        if self.min_btauth_share is None:
            return None
        return (
            self.btauth_share is not None and self.btauth_share >= self.min_btauth_share
        )

    @property
    def exit_code(self) -> int:
        """2 if a source could not be read, 1 if the share is not met, else 0."""
        if self.unreachable:
            return 2
        return 1 if self.share_met is False else 0


def parse_metrics_text(text: str, source: str) -> SourceStatus:
    """The migration numbers in one Prometheus text exposition.

    Metrics that are absent count as 0 (``days_remaining``: ``None``), so a
    miner's text has no validator numbers and a validator with the bridge
    off has no legacy counters. Raises :class:`MetricsTextError` for text
    that is not exposition format or holds a non-finite or negative count.
    """
    by_protocol = {"btauth/1": 0.0, "v10": 0.0}
    requests = dict.fromkeys(_DIRECTIONS, 0.0)
    days: dict[str, float | None] = dict.fromkeys(_DIRECTIONS)
    try:
        samples = [
            s for family in text_string_to_metric_families(text) for s in family.samples
        ]
    except Exception as exc:  # the parser raises several types on bad input
        raise MetricsTextError(f"{source}: not Prometheus text format") from exc
    for s in samples:
        if s.name == _BY_PROTOCOL and s.labels.get("protocol") in by_protocol:
            by_protocol[s.labels["protocol"]] += _count(s.value, s.name, source)
        elif s.name == _REQUESTS and s.labels.get("direction") in requests:
            requests[s.labels["direction"]] += _count(s.value, s.name, source)
        elif s.name == _DAYS and s.labels.get("direction") in days:
            value = _count(s.value, s.name, source)
            previous = days[s.labels["direction"]]
            days[s.labels["direction"]] = (
                value if previous is None else min(previous, value)
            )
    return SourceStatus(
        source=source,
        miners_btauth=round(by_protocol["btauth/1"]),
        miners_v10=round(by_protocol["v10"]),
        inbound_v10_total=requests["inbound"],
        outbound_v10_total=requests["outbound"],
        days_remaining={k: None if v is None else round(v) for k, v in days.items()},
    )


def _count(value: float, name: str, source: str) -> float:
    if not math.isfinite(value) or value < 0:
        raise MetricsTextError(f"{source}: {name} is {value}, not a count")
    return value


def read_url(url: str, *, timeout_s: float = 5.0) -> str:
    """GET a ``/metrics`` URL (no redirects, at most :data:`MAX_METRICS_BYTES`).

    Raises :class:`OSError` with a one-line reason when it cannot be read.
    """
    try:
        with (
            httpx.Client(timeout=timeout_s, follow_redirects=False) as http,
            http.stream("GET", url) as r,
        ):
            if r.status_code != 200:
                raise OSError(f"HTTP {r.status_code}")
            body = bytearray()
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_METRICS_BYTES:
                    raise OSError(f"answer larger than {MAX_METRICS_BYTES} bytes")
    except httpx.HTTPError as exc:
        raise OSError(f"{type(exc).__name__}: {exc}") from exc
    return _decode(bytes(body))


def read_file(path: Path) -> str:
    """Read a saved metrics file (at most :data:`MAX_METRICS_BYTES`)."""
    with path.open("rb") as f:
        data = f.read(MAX_METRICS_BYTES + 1)
    if len(data) > MAX_METRICS_BYTES:
        raise OSError(f"file larger than {MAX_METRICS_BYTES} bytes")
    return _decode(data)


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OSError("not UTF-8 text") from exc


def build_report(
    sources: Iterable[SourceStatus],
    unreachable: Sequence[dict[str, str]] = (),
    *,
    min_btauth_share: float | None = None,
) -> StatusReport:
    """Sum the per-source numbers (days remaining: the smallest)."""
    read = list(sources)
    btauth = sum(s.miners_btauth for s in read)
    v10 = sum(s.miners_v10 for s in read)
    days: dict[str, int | None] = {}
    for direction in _DIRECTIONS:
        known = [d for s in read if (d := s.days_remaining.get(direction)) is not None]
        days[direction] = min(known) if known else None
    return StatusReport(
        sources=read,
        unreachable=list(unreachable),
        miners_btauth=btauth,
        miners_v10=v10,
        btauth_share=btauth / (btauth + v10) if btauth + v10 else None,
        inbound_v10_total=sum(s.inbound_v10_total for s in read),
        outbound_v10_total=sum(s.outbound_v10_total for s in read),
        days_remaining=days,
        min_btauth_share=min_btauth_share,
    )


def render(report: StatusReport, fmt: str) -> str:
    """The report as ``text`` or ``json``."""
    if fmt == "json":
        data = asdict(report)
        data["share_met"] = report.share_met
        return json.dumps(data, indent=2, sort_keys=True) + "\n"
    return _render_text(report)


def _pct(share: float | None) -> str:
    return "n/a (no validator round seen)" if share is None else f"{share:.1%}"


def _days(value: int | None) -> str:
    return "not set" if value is None else str(value)


def _render_text(report: StatusReport) -> str:
    lines = [
        f"sources read: {len(report.sources)}, unreachable: {len(report.unreachable)}"
    ]
    lines += [
        f"  unreachable: {u['source']} ({u['error']})" for u in report.unreachable
    ]
    lines += [
        "miners answering in the last validator round: "
        f"btauth/1 {report.miners_btauth}, v10 {report.miners_v10}",
        f"btauth/1 share: {_pct(report.btauth_share)}",
        "legacy v10 requests: "
        f"inbound {report.inbound_v10_total:g}, outbound {report.outbound_v10_total:g}",
        "legacy v10 days remaining: "
        f"inbound {_days(report.days_remaining['inbound'])}, "
        f"outbound {_days(report.days_remaining['outbound'])}",
    ]
    if report.min_btauth_share is not None:
        verdict = "met" if report.share_met else "NOT met"
        lines.append(f"check --min-btauth-share {report.min_btauth_share:g}: {verdict}")
    return "\n".join(lines) + "\n"
