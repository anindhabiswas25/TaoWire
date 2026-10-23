"""Container health check: GET /healthz on the process's own HTTP port.

Used by the miner, validator and sidecar images (``HEALTHCHECK``). Reads only
``TW_*`` settings the process itself uses, so it probes what actually listens:

- miner:     ``TW_BIND_HOST`` / ``TW_BIND_PORT`` (default 0.0.0.0:8091)
- validator: ``TW_METRICS_BIND`` (default 127.0.0.1:9100)
- sidecar:   127.0.0.1:``TW_SIDECAR_PORT`` (default 9910)

Exit 0 when the endpoint answers 200, 1 otherwise. Standard library only.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

_ANY = {"0.0.0.0", "::", ""}  # noqa: S104 - wildcard binds are probed on loopback


def _target(role: str) -> tuple[str, str]:
    if role == "miner":
        host = os.environ.get("TW_BIND_HOST", "0.0.0.0")  # noqa: S104
        return host, os.environ.get("TW_BIND_PORT", "8091")
    if role == "validator":
        bind = os.environ.get("TW_METRICS_BIND", "127.0.0.1:9100")
        host, _, port = bind.rpartition(":")
        return host.strip("[]"), port
    return "127.0.0.1", os.environ.get("TW_SIDECAR_PORT", "9910")


def main(role: str) -> int:
    host, port = _target(role)
    if host in _ANY:
        host = "127.0.0.1"
    if ":" in host:
        host = f"[{host}]"
    url = f"http://{host}:{port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return 0 if response.status == 200 else 1
    except (OSError, urllib.error.URLError):
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "miner"))
