# ADR-0004: Responses are signed with a kit extension, `twresp/1`

- Status: accepted (upstream proposal pending, spec 1.7)
- Date: 2026-10-23 (Phase 2 implementation)
- Owner: Engineer A
- Spec: Section 7 (ADR-0004), 9.1, 8.8, Appendix A ("Response signed?")

## Context

btauth/1 authenticates requests only. A validator scores what a miner
answered; it needs to know the answer came from that miner, unchanged, and
for this request (not replayed from an earlier request or copied from
another validator's).

## Decision

1. Miners sign responses with four headers that do not reuse the reserved
   `X-Bittensor-*` names: `X-TW-Resp-Version: 1`, `X-TW-Resp-Hotkey`,
   `X-TW-Resp-Crypto` (`ed25519`; omitted for sr25519) and
   `X-TW-Resp-Signature` (`0x` + lowercase hex).
2. The signed payload is the UTF-8, `\n`-joined lines `twresp/1`, scheme,
   the request's nonce, the request's sender, the responder, the HTTP status,
   and the sha256 of the raw body. Binding nonce and sender stops replays of
   older answers and answers to other validators. The raw payload is signed
   (no `<Bytes>` wrapping), as in btauth/1.
3. **What is signed:** every 200 from a protected route, and every error
   raised after the caller was authenticated (403, 422, 429 per-hotkey, 500,
   504). Errors before authentication (401, 413, per-IP 429, 503) are never
   signed: the miner does not yet know whom it would be signing for, and
   signing attacker-chosen input would make it an oracle.
4. **Verification** (validator): responder equals the hotkey the request was
   bound to, version `1`, signature valid under the declared scheme only,
   nonce and sender equal to what this validator sent; duplicate
   `X-TW-Resp-*` headers are rejected. A 200 without a valid signature is
   `ok=False, error_code="tw.bad_response_signature"`. A response that
   verifies sets `MinerResult.response_verified`.
5. On by default on both sides (`TW_SIGN_RESPONSES=1`,
   `TW_VERIFY_RESPONSES=1`); turning either off is a weakening setting
   (logged at WARNING, `tw_unsafe_settings_active`).
6. Implementation: `taowire.extensions.response_sig` (`response_payload`,
   `sign_response`, `verify_response`), using `taowire.crypto` only.
   Cross-language vectors: `conformance/vectors/twresp.json` (Engineer B).

## Consequences

- Validators can treat a verified answer as the miner's own statement. The
  legacy v10 path has no equivalent (v10 Dendrites check no response
  signature), so v10 results always have `response_verified=False`.
- A validator's "no downgrade" rule for v10 (8.11.3) keys on a *verified*
  btauth/1 answer, so an unverified 200 cannot pin a miner to btauth/1.
- Upstream: if the core team adopts an official response extension, the kit
  switches to it in a minor release and keeps accepting `X-TW-Resp-*` for at
  least one more (spec 1.7).
