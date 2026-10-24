"""The MCP server's actions: plain functions, testable without MCP.

None of them reads a private key, signs anything or writes to a chain.
``scaffold_project`` and ``migrate_apply`` write files, with the same
refusals as ``taowire init`` and ``taowire migrate apply``.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import math
import time
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal

import anyio

from taowire.auth.nonce_store import MemoryNonceStore
from taowire.auth.verifier import RequestVerifier
from taowire.cli.doctor import Doctor
from taowire.cli.init_cmd import package_name, render_project
from taowire.crypto import btauth_payload
from taowire.errors import AuthFailed
from taowire.extensions.response_sig import (
    ResponseSignatureError,
    body_digest,
    response_payload,
    verify_response,
)
from taowire.mcp_server.knowledge import ERROR_HINTS

__all__ = [
    "decode_body",
    "doctor",
    "inspect_request",
    "inspect_response",
    "migrate_apply",
    "migrate_scan",
    "read_metagraph",
    "scaffold_project",
]

_BTAUTH = "x-bittensor-"


def decode_body(body: str, encoding: Literal["utf-8", "base64"]) -> bytes:
    """The raw body bytes from the tool argument."""
    if encoding == "base64":
        try:
            return base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("body is not valid base64") from None
    return body.encode("utf-8")


def _lower(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _nonce_info(raw: str | None) -> dict[str, Any]:
    if raw is None or not raw.isascii() or not raw.isdigit() or len(raw) > 20:
        return {"nonce": raw, "valid": False}
    ns = int(raw)
    age = (time.time_ns() - ns) / 1e9
    try:
        when = dt.datetime.fromtimestamp(ns / 1e9, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        when = "out of range"
    return {"nonce": raw, "valid": True, "signed_at_utc": when, "age_s": round(age, 3)}


def _hint(code: str) -> dict[str, str]:
    row = ERROR_HINTS.get(code)
    return {} if row is None else {"cause": row[1], "fix": row[2]}


def inspect_request(
    *,
    method: str,
    target: str,
    headers: Mapping[str, str],
    body: bytes,
    receiver: str | None = None,
    check_freshness: bool = True,
    max_age_s: float = 10.0,
    allowed_skew_s: float = 2.0,
) -> dict[str, Any]:
    """Explain a captured btauth/1 request and verify it.

    The check uses a fresh, empty replay store, so a request is never
    reported as replayed. With ``check_freshness=False`` the clock is set to
    the request's own nonce, so an old capture can still be checked for its
    signature. ``receiver`` defaults to the request's ``X-Bittensor-Receiver``.
    """
    h = _lower(headers)
    sender = h.get(f"{_BTAUTH}hotkey")
    rcv = receiver or h.get(f"{_BTAUTH}receiver")
    scheme = h.get(f"{_BTAUTH}crypto", "sr25519")
    nonce = _nonce_info(h.get(f"{_BTAUTH}nonce"))
    report: dict[str, Any] = {
        "headers": {
            "version": h.get(f"{_BTAUTH}version"),
            "sender": sender,
            "receiver_header": h.get(f"{_BTAUTH}receiver"),
            "checked_receiver": rcv,
            "crypto": scheme,
            **nonce,
            "signature_present": f"{_BTAUTH}signature" in h,
        },
        "body_sha256": body_digest(body),
        "body_bytes": len(body),
    }
    if sender and nonce["valid"] and scheme in ("sr25519", "ed25519"):
        try:
            payload = btauth_payload(
                scheme=scheme,
                method=method,
                target=target,
                body=body,
                nonce_ns=int(nonce["nonce"]),
                sender_ss58=sender,
                receiver_ss58=h.get(f"{_BTAUTH}receiver"),
            )
            report["signed_payload_lines"] = payload.decode("utf-8").split("\n")
        except (ValueError, UnicodeDecodeError) as exc:
            report["signed_payload_lines"] = None
            report["payload_error"] = str(exc)
    if rcv is None:
        report["result"] = {
            "ok": False,
            "code": "tw.auth_malformed",
            "message": "no receiver: pass `receiver` or include X-Bittensor-Receiver",
            **_hint("tw.auth_malformed"),
        }
        return report
    now = int(nonce["nonce"]) if not check_freshness and nonce["valid"] else None
    try:
        verifier = RequestVerifier(
            rcv,
            MemoryNonceStore(retention=max(60.0, 3 * (max_age_s + allowed_skew_s))),
            max_age=max_age_s,
            allowed_skew=allowed_skew_s,
            now_ns=None if now is None else (lambda: now),
        )
    except ValueError as exc:
        report["result"] = {"ok": False, "code": "invalid_input", "message": str(exc)}
        return report
    try:
        caller = verifier.verify_sync(
            headers.items(), body, method=method, target=target
        )
    except AuthFailed as exc:
        report["result"] = {
            "ok": False,
            "code": exc.code,
            "message": str(exc),
            **_hint(exc.code),
        }
        return report
    report["result"] = {
        "ok": True,
        "caller": caller.hotkey_ss58,
        "scheme": caller.scheme,
        "freshness_checked": check_freshness,
        "note": "replay is not checked here (fresh store)",
    }
    return report


def inspect_response(
    *,
    headers: Mapping[str, str],
    body: bytes,
    status: int,
    expected_responder: str,
    request_nonce: int,
    sender: str,
) -> dict[str, Any]:
    """Explain and verify a miner's ``twresp/1``-signed response."""
    h = _lower(headers)
    scheme = h.get("x-tw-resp-crypto", "sr25519")
    digest = body_digest(body)
    report: dict[str, Any] = {
        "headers": {
            "version": h.get("x-tw-resp-version"),
            "responder": h.get("x-tw-resp-hotkey"),
            "crypto": scheme,
            "signature_present": "x-tw-resp-signature" in h,
        },
        "body_sha256": digest,
    }
    try:
        payload = response_payload(
            scheme=scheme,
            request_nonce=request_nonce,
            sender_ss58=sender,
            responder_ss58=expected_responder,
            status=status,
            digest=digest,
        )
        report["signed_payload_lines"] = payload.decode("utf-8").split("\n")
    except ValueError as exc:
        report["payload_error"] = str(exc)
    try:
        used = verify_response(
            headers,
            expected_responder=expected_responder,
            request_nonce=request_nonce,
            sender_ss58=sender,
            status=status,
            body=body,
        )
    except (ResponseSignatureError, ValueError) as exc:
        report["result"] = {
            "ok": False,
            "code": "tw.bad_response_signature",
            "message": str(exc),
            **_hint("tw.bad_response_signature"),
        }
        return report
    report["result"] = {"ok": True, "scheme": used}
    return report


def scaffold_project(
    directory: Path, *, name: str | None = None, package: str | None = None
) -> dict[str, Any]:
    """``taowire init``: write the text-ops example subnet into an empty directory."""
    directory = directory.expanduser()
    project = name or directory.resolve().name
    files = render_project(project, "text-ops", package)
    package = package or package_name(project)
    if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
        raise FileExistsError(f"{directory} exists and is not empty; nothing written")
    for rel, content in files.items():
        target = directory / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return {
        "directory": str(directory.resolve()),
        "project": project,
        "package": package,
        "files": sorted(files),
        "next_steps": [
            f"cd {directory} && pip install -e '.[dev]' && pytest -q",
            "start a local chain: scripts/localnet_up.sh from the TaoWire repository",
            f"run the miner: python -m {package}.miner (TW_* settings: .env.example)",
            f"run the validator: python -m {package}.validator",
            "read_doc('quickstart') walks through every step",
        ],
    }


def _migrate_module(name: Literal["scan", "apply"]) -> Any:
    try:
        if name == "scan":
            from taowire.migrate import scan  # noqa: PLC0415 - optional extra

            return scan
        from taowire.migrate import apply  # noqa: PLC0415 - optional extra
    except ImportError:
        raise RuntimeError(
            "taowire migrate needs libcst: pip install 'taowire[mcp]'"
        ) from None
    return apply


def migrate_scan(repo: Path) -> dict[str, Any]:
    """``taowire migrate scan``: every v10 symbol and pattern, with its replacement."""
    repo = repo.expanduser()
    if not repo.is_dir():
        raise NotADirectoryError(f"not a directory: {repo}")
    scanner = _migrate_module("scan")
    report = scanner.scan_repo(repo)
    data: dict[str, Any] = json.loads(scanner.render(report, "json"))
    data["all_auto"] = report.exit_code == 0
    return data


def migrate_apply(repo: Path, *, write: bool, allow_dirty: bool) -> dict[str, Any]:
    """``taowire migrate apply``: the diff (``write=False``) or the rewrite."""
    repo = repo.expanduser()
    if not repo.is_dir():
        raise NotADirectoryError(f"not a directory: {repo}")
    codemod = _migrate_module("apply")
    if write and not allow_dirty:
        state = codemod.git_state(repo)
        if state != "clean":
            reason = (
                "has uncommitted changes"
                if state == "dirty"
                else "is not in a git repository"
            )
            raise PermissionError(
                f"{repo} {reason}: commit first so `git diff` shows what apply "
                "changed (or pass allow_dirty=true)"
            )
    report = codemod.plan_repo(repo)
    out: dict[str, Any] = {
        "written": False,
        "summary": report.summary(),
        "parse_errors": list(report.parse_errors),
    }
    if write:
        codemod.write_changes(report)
        out["written"] = True
    else:
        out["diff"] = report.diff()
    return out


async def doctor(
    role: Literal["miner", "validator"], env_file: Path | None
) -> dict[str, Any]:
    """``taowire doctor``: check a miner's or validator's setup (prints no secrets)."""
    path = None if env_file is None else await anyio.Path(env_file).expanduser()
    if path is not None and not await path.is_file():
        raise FileNotFoundError(f"no such env file: {path}")
    doc = Doctor(role, env_file=None if path is None else Path(path))
    checks = await doc.run()
    return {
        "role": role,
        "failed": doc.failed,
        "checks": [asdict(c) for c in checks],
    }


def _finite(value: float) -> float | None:
    return round(value, 6) if math.isfinite(value) else None


async def read_metagraph(
    network: str, netuid: int, *, limit: int = 64, timeout_s: float = 30.0
) -> dict[str, Any]:
    """A read-only snapshot of one subnet: UIDs, hotkeys, permits, stake, axons."""
    from taowire.chain.gateway import (  # noqa: PLC0415 - heavy import
        BittensorGateway,
        GatewayError,
    )

    gateway = BittensorGateway(network, timeout_s=timeout_s, allow_private_axons=True)
    try:
        await gateway.connect()
        mg = await gateway.metagraph(netuid)
    except GatewayError as exc:
        raise RuntimeError(f"chain read failed: {exc}") from None
    finally:
        await gateway.close()
    neurons = [
        {
            "uid": n.uid,
            "hotkey": n.hotkey,
            "validator_permit": n.validator_permit,
            "total_stake_tao": _finite(n.total_stake_tao),
            "axon": None if n.axon is None else str(n.axon),
            "incentive": _finite(n.incentive),
            "dividends": _finite(n.dividends),
            "last_update": n.last_update,
        }
        for n in mg.neurons[: max(0, limit)]
    ]
    return {
        "network": network,
        "netuid": mg.netuid,
        "block": mg.block,
        "tempo": mg.tempo,
        "n_neurons": len(mg.neurons),
        "n_validator_permits": sum(1 for n in mg.neurons if n.validator_permit),
        "neurons": neurons,
        "truncated": len(mg.neurons) > len(neurons),
    }
