"""``tensorwire conformance``: run the Python implementation against the vectors.

Spec 11.7 and 11.2 rule 12: every implementation passes every vector in
``conformance/vectors/`` before release. This command is the Python one
(``just conformance`` runs it next to the Go, Rust and TypeScript runners)::

    tensorwire conformance --vectors ../conformance/vectors

Each file has a checker; a ``*.json`` file without one is a failure, so a new
vector file cannot be skipped silently. A vector whose ``python_reference``
declares a known divergence (spec 11.7: ``<Bytes>``-wrapped signatures) must
give exactly that answer and is listed in the report. Exit 0 when every vector
passes, 1 on any failure, 2 when the folder or a file cannot be read.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

import typer

from tensorwire import crypto
from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.auth.verifier import RequestVerifier
from tensorwire.errors import AuthFailed
from tensorwire.extensions import response_sig
from tensorwire.extensions.legacy_v10 import wire

__all__ = ["conformance", "run_vectors"]

Vector = dict[str, Any]

#: Files every vector folder must hold (spec 11.7).
REQUIRED_FILES = (
    "payload.json",
    "ed25519.json",
    "sr25519_verify.json",
    "negative.json",
    "twresp.json",
    "legacy_v10.json",
)


@dataclass
class FileResult:
    """The outcome of one vector file."""

    name: str
    passed: int = 0
    failures: list[str] = field(default_factory=list)
    divergences: list[str] = field(default_factory=list)


def _b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _verify_request(i: Vector) -> tuple[bool, str | None, str | None]:
    """One btauth/1 verify case through ``RequestVerifier``: (valid, code, caller)."""
    verifier = RequestVerifier(
        i["self_hotkey"],
        MemoryNonceStore(),
        max_age=i["max_age_s"],
        allowed_skew=i["allowed_skew_s"],
        now_ns=lambda: int(i["now_ns"]),
    )

    def one(r: Vector) -> str:
        caller = verifier.verify_sync(
            [(n, v) for n, v in r["headers"]],
            _b64(r["body_base64"]),
            method=r["method"],
            target=r["target"],
        )
        return caller.hotkey_ss58

    if i.get("prior") is not None:
        try:
            one(i["prior"])
        except AuthFailed as exc:
            return False, f"prior request refused ({exc.code})", None
    try:
        return True, None, one(i)
    except AuthFailed as exc:
        return False, exc.code, None


def _check_verify(v: Vector) -> Iterator[str]:
    want = v.get("python_reference") or v["expected"]
    valid, code, caller = _verify_request(v["inputs"])
    if (valid, code) != (want["valid"], want["code"]):
        yield (
            f"got valid={valid} code={code}, "
            f"want valid={want['valid']} code={want['code']}"
        )
    elif (
        valid and "python_reference" not in v and caller != v["expected"]["caller_ss58"]
    ):
        yield f"caller {caller}, want {v['expected']['caller_ss58']}"


def _check_payload(v: Vector) -> Iterator[str]:
    i, e = v["inputs"], v["expected"]
    body = _b64(i["body_base64"])
    if hashlib.sha256(body).hexdigest() != e["body_sha256"]:
        yield "body sha256 differs"
    built = crypto.btauth_payload(
        scheme=i["scheme"],
        method=i["method"],
        target=i["target"],
        body=body,
        nonce_ns=int(i["nonce"]),
        sender_ss58=i["sender_ss58"],
        receiver_ss58=i["receiver_ss58"],
    )
    if built != _b64(e["payload_base64"]):
        yield "payload differs"


def _check_ed25519(v: Vector, keys: Vector) -> Iterator[str]:
    key = keys[v["inputs"]["key"]]
    signer = crypto.keypair_from_seed(
        bytes.fromhex(key["secret_seed_hex"]), crypto_type=crypto.CRYPTO_ED25519
    )
    signed = signer.sign(v["inputs"]["signed_payload_utf8"].encode())
    if crypto.signature_to_hex(bytes(signed)) != v["expected"]["signature"]:
        yield "signature differs"
    yield from _check_verify(v)


def _check_twresp(v: Vector) -> Iterator[str]:
    i, e = v["inputs"], v["expected"]
    if v["kind"] == "verify":
        headers = i["headers"]
        pairs = headers if isinstance(headers, dict) else [tuple(p) for p in headers]
        try:
            response_sig.verify_response(
                pairs,
                expected_responder=i["expected_responder"],
                request_nonce=int(i["request_nonce"]),
                sender_ss58=i["sender_ss58"],
                status=i["status"],
                body=_b64(i["body_base64"]),
            )
        except response_sig.ResponseSignatureError as exc:
            if e["valid"] or exc.code != e["error_code"]:
                yield f"refused ({exc.code}), want valid={e['valid']}"
            return
        if not e["valid"]:
            yield "accepted, want refused"
        return
    if v["kind"] == "stream_ed25519":
        chunks = b"".join(_b64(c) for c in i["chunks_base64"])
        digest = hashlib.sha256(chunks).hexdigest()
        status, signature = 200, e["signature"]
    else:
        digest = response_sig.body_digest(_b64(i["body_base64"]))
        status, signature = i["status"], e["headers"]["X-TW-Resp-Signature"]
    payload = response_sig.response_payload(
        scheme=i["scheme"],
        request_nonce=int(i["request_nonce"]),
        sender_ss58=i["sender_ss58"],
        responder_ss58=i["responder_ss58"],
        status=status,
        digest=digest,
    )
    if payload.decode() != e["payload_utf8"]:
        yield "payload differs"
    ctype = crypto.crypto_type_from_scheme(i["scheme"])
    sig = crypto.signature_from_hex(signature)
    if not crypto.verify(payload, sig, i["responder_ss58"], ctype):
        yield "signature does not verify"


def _check_legacy(v: Vector) -> Iterator[str]:
    request, e = v["request"], v["request_expected"]
    body = _b64(request["body_base64"])
    if hashlib.sha256(body).hexdigest() != request["body_sha256"]:
        yield "recorded body sha256 differs"
    values = [h["str_value"] for h in e.get("hash_inputs") or []]
    computed = wire.hash_values(values) if values else wire.EMPTY_BODY_HASH
    if "computed_body_hash" in e and computed != e["computed_body_hash"]:
        yield "computed_body_hash differs"
    headers = {k.lower(): val for k, val in request["headers"]}
    message, verifies = e.get("signed_message"), e.get("signature_verifies")
    signature, sender = (
        headers.get("bt_header_dendrite_signature"),
        headers.get("bt_header_dendrite_hotkey"),
    )
    if message is None or verifies is None or not signature or not sender:
        return
    try:
        ok = crypto.verify(
            message.encode(),
            crypto.signature_from_hex(signature),
            sender,
            crypto.CRYPTO_SR25519,
        )
    except ValueError:
        ok = False
    if ok is not verifies:
        yield f"v10 signature verifies={ok}, want {verifies}"


def _checkers(data: Vector) -> dict[str, Callable[[Vector], Iterator[str]]]:
    keys = data.get("keys", {})
    return {
        "payload.json": _check_payload,
        "ed25519.json": lambda v: _check_ed25519(v, keys),
        "sr25519_verify.json": _check_verify,
        "negative.json": _check_verify,
        "twresp.json": _check_twresp,
        "legacy_v10.json": _check_legacy,
    }


def run_file(path: Path) -> FileResult:
    """Check every vector of one file. ``OSError``/``ValueError`` if unreadable."""
    data: Vector = json.loads(path.read_text(encoding="utf-8"))
    result = FileResult(path.name)
    check = _checkers(data).get(path.name)
    if check is None:
        result.failures.append("no checker for this file")
        return result
    if data.get("schema_version") != 1:
        result.failures.append(f"unknown schema_version {data.get('schema_version')!r}")
        return result
    vectors = data.get("vectors") or []
    if not vectors:
        result.failures.append("no vectors")
    for v in vectors:
        try:
            problems = list(check(v))
        except (KeyError, TypeError, ValueError) as exc:
            problems = [f"vector could not be run: {type(exc).__name__}: {exc}"]
        if problems:
            result.failures.extend(f"{v.get('id', '?')}: {p}" for p in problems)
        else:
            result.passed += 1
            if "python_reference" in v:
                result.divergences.append(f"{v['id']}: {v['python_reference']['note']}")
    return result


def run_vectors(folder: Path) -> list[FileResult]:
    """Check every ``*.json`` in ``folder``; a required file that is missing fails."""
    present = {p.name: p for p in sorted(folder.glob("*.json"))}
    results = [run_file(p) for p in present.values()]
    for name in REQUIRED_FILES:
        if name not in present:
            results.append(FileResult(name, failures=["file missing"]))
    return results


def conformance(
    vectors: Annotated[
        Path,
        typer.Option("--vectors", help="Folder with the conformance vector files."),
    ] = Path("conformance/vectors"),
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Also list the known divergences.")
    ] = False,
) -> None:
    """Run the Python implementation against every conformance vector (spec 11.7)."""
    if not vectors.is_dir():
        typer.echo(f"error: {vectors} is not a folder", err=True)
        raise typer.Exit(2)
    try:
        results = run_vectors(vectors)
    except (OSError, ValueError) as exc:
        typer.echo(f"error: cannot read the vectors: {exc}", err=True)
        raise typer.Exit(2) from None
    failed = 0
    for r in results:
        total = r.passed + len({f.split(":", 1)[0] for f in r.failures})
        mark = "ok  " if not r.failures else "FAIL"
        note = f", {len(r.divergences)} known divergence(s)" if r.divergences else ""
        typer.echo(f"{mark} {r.name}: {r.passed}/{total} passed{note}")
        for f in r.failures:
            typer.echo(f"     {f}")
        if verbose:
            for d in r.divergences:
                typer.echo(f"     divergence {d}")
        failed += bool(r.failures)
    passed = sum(r.passed for r in results)
    typer.echo(
        f"{'FAIL' if failed else 'PASS'}: {passed} vectors passed, "
        f"{failed} file(s) failed"
    )
    if failed:
        raise typer.Exit(1)


def main() -> None:
    """Run the command on its own: ``python -m tensorwire.cli.conformance_cmd``."""
    typer.run(conformance)


if __name__ == "__main__":
    main()
