"""Structured JSON logs and request IDs (spec 8.12).

:func:`configure_logging` sends every log line, the kit's (structlog) and the
standard library's (uvicorn, bittensor), to stdout as one JSON object with
``ts``, ``level`` and ``event``. Request lines add ``request_id``, ``route``,
``caller_hotkey`` (shortened by :func:`short_hotkey`; the full hotkey only at
DEBUG), ``status``, ``latency_ms`` and ``code``.

Never log bodies, signatures, or the values of signature headers.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import IO, Any

import structlog

__all__ = ["configure_logging", "new_request_id", "short_hotkey"]

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

_SHARED: list[Any] = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
]


def _from_basic_config(handler: logging.Handler) -> bool:
    """The stderr handler ``logging.basicConfig()`` adds with its defaults."""
    formatter = handler.formatter
    return (
        type(handler) is logging.StreamHandler
        and getattr(handler, "stream", None) is sys.stderr
        and formatter is not None
        and formatter._fmt == logging.BASIC_FORMAT
    )


def configure_logging(level: str = "INFO", *, stream: IO[str] | None = None) -> None:
    """Route structlog and stdlib logging to ``stream`` (stdout) as JSON lines.

    Safe to call more than once; the last call wins. Also removes the
    handler ``logging.basicConfig()`` adds, which a module-level
    ``logging.info(...)`` before this call creates silently (common in
    ported v10 code); it would print every line a second time, unformatted.
    """
    handler = logging.StreamHandler(sys.stdout if stream is None else stream)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=_SHARED,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
        )
    )
    root = logging.getLogger()
    for old in list(root.handlers):
        if getattr(old, "_taowire", False) or _from_basic_config(old):
            root.removeHandler(old)
    handler._taowire = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level)
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *_SHARED,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )


def short_hotkey(hotkey: str | None, *, full: bool = False) -> str | None:
    """A hotkey for logs: first 8 characters + "…", or all of it when ``full``."""
    if hotkey is None or full:
        return hotkey
    return hotkey[:8] + "…"


def new_request_id() -> str:
    """A new ULID: 48-bit millisecond timestamp + 80 random bits, Crockford base32.

    Lexically sortable by creation time; 26 characters.
    """
    value = (time.time_ns() // 1_000_000) << 80 | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        value, digit = divmod(value, 32)
        chars.append(_CROCKFORD[digit])
    return "".join(reversed(chars))
