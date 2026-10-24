"""Check that deploy/proxy/{Caddyfile,nginx.conf} pass target and body unchanged.

Runs each proxy in Docker (host network) in front of a recording upstream on
127.0.0.1:8091, with a P-256 certificate generated now (never committed), and
checks over TLS: the request target and body reach the upstream byte for
byte, X-Forwarded-For ends with the client's address, the served
certificate's key is the one a miner would publish, and SSE events are not
buffered. Needs Docker and free ports 8091 and 8443 on the host.

    cd python && uv run python ../deploy/proxy/proxy_check.py

Last run (2026-10-25, caddy:2.10.2-alpine and nginx:1.29.3-alpine): every
check true for both proxies; see deploy/README.md.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from taowire.testing.tls import make_certificate
from taowire.tls import load_published_certificate, published_key_from_der

DEPLOY = Path(__file__).resolve().parent
TARGET = "/v1//gen/./x/../y?q=%2F&b=a+b"
BODY = b'{ "b": 1,  "a": "\\u00e9" }'
seen: list[dict[str, object]] = []


async def upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    head = await reader.readuntil(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {
        k.lower(): v.strip()
        for k, v in (line.split(":", 1) for line in lines[1:] if ":" in line)
    }
    body = await reader.readexactly(int(headers.get("content-length", "0")))
    target = lines[0].split(" ")[1]
    seen.append(
        {
            "target": target,
            "xff": headers.get("x-forwarded-for"),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )
    if target == "/sse":
        writer.write(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
            b"transfer-encoding: chunked\r\n\r\n"
        )
        for i in range(3):
            event = f'data: {{"i": {i}}}\n\n'.encode()
            writer.write(f"{len(event):x}\r\n".encode() + event + b"\r\n")
            await writer.drain()
            await asyncio.sleep(0.5)
        writer.write(b"0\r\n\r\n")
    else:
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
    await writer.drain()
    writer.close()


def tls_request(
    port: int, target: str, body: bytes
) -> tuple[bytes, bytes, list[float]]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = (
        False,
        ssl.CERT_NONE,
    )  # we compare the key below
    with (
        socket.create_connection(("127.0.0.1", port), timeout=10) as raw,
        ctx.wrap_socket(raw) as s,
    ):
        der = s.getpeercert(binary_form=True)
        s.sendall(
            f"POST {target} HTTP/1.1\r\nHost: miner\r\nX-Forwarded-For: 6.6.6.6\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode()
            + body
        )
        data, arrivals, start = b"", [], time.monotonic()
        while chunk := s.recv(65536):
            data += chunk
            arrivals.append(round(time.monotonic() - start, 2))
    return der, data, arrivals


def run_proxy(name: str, cfg: Path, certs: Path) -> subprocess.Popen[bytes]:
    common = [
        "docker",
        "run",
        "--rm",
        "--name",
        f"tw-proxy-check-{name}",
        "--network",
        "host",
        "-v",
        f"{certs}:/etc/taowire/proxy:ro",
    ]
    if name == "caddy":
        cmd = [
            *common,
            "-v",
            f"{cfg}:/etc/caddy/Caddyfile:ro",
            "caddy:2.10.2-alpine",
            "caddy",
            "run",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ]
    else:
        cmd = [
            *common,
            "-v",
            f"{cfg}:/etc/nginx/conf.d/default.conf:ro",
            "nginx:1.29.3-alpine",
        ]
    return subprocess.Popen(  # noqa: S603 - fixed argv
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )


async def check(
    name: str, cfg: Path, certs: Path, want_key: bytes
) -> dict[str, object]:
    proxy = run_proxy(name, cfg, certs)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", 8443), timeout=0.2).close()
                break
            except OSError:
                await asyncio.sleep(0.1)
        seen.clear()
        der, data, _ = await asyncio.to_thread(tls_request, 8443, TARGET, BODY)
        _, _, arrivals = await asyncio.to_thread(tls_request, 8443, "/sse", b"")
        got = seen[0]
        return {
            "proxy": name,
            "status_line": data.split(b"\r\n", 1)[0].decode(),
            "target_sent": TARGET,
            "target_received": got["target"],
            "target_unchanged": got["target"] == TARGET,
            "body_unchanged": got["body_sha256"] == hashlib.sha256(BODY).hexdigest(),
            "x_forwarded_for": got["xff"],
            "xff_rightmost_is_client": str(got["xff"]).split(",")[-1].strip()
            == "127.0.0.1",
            "served_key_is_published_key": published_key_from_der(der) == want_key,
            "sse_chunk_arrivals_s": arrivals,
            "sse_streamed": len(arrivals) >= 3 and arrivals[-1] - arrivals[0] >= 0.9,
        }
    finally:
        await asyncio.to_thread(
            subprocess.run,
            ["docker", "stop", "-t", "2", f"tw-proxy-check-{name}"],
            capture_output=True,
            check=False,
        )
        proxy.wait(timeout=20)


async def main() -> int:
    server = await asyncio.start_server(upstream, "127.0.0.1", 8091)
    with tempfile.TemporaryDirectory() as tmp:
        certs = Path(tmp) / "certs"
        cert = make_certificate(certs, "cert", kind="p256", ip="127.0.0.1")
        cert.key_file.rename(certs / "key.pem")
        cert.cert_file.rename(certs / "cert.pem")
        (certs / "key.pem").chmod(0o644)  # the proxy container runs as another user
        certs.chmod(0o755)
        want = load_published_certificate(certs / "cert.pem")
        results = [
            await check("caddy", DEPLOY / "Caddyfile", certs, want),
            await check("nginx", DEPLOY / "nginx.conf", certs, want),
        ]
    server.close()
    for r in results:
        sys.stdout.write(json.dumps(r) + "\n")
    keys = (
        "target_unchanged",
        "body_unchanged",
        "xff_rightmost_is_client",
        "served_key_is_published_key",
        "sse_streamed",
    )
    return 0 if all(r[k] for r in results for k in keys) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
