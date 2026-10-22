# `twresp/1`: signed responses

btauth/1 authenticates requests only. `twresp/1` is the TensorWire extension
that lets a validator check that an answer came from the miner it queried,
unchanged, and for **this** request (spec 9.1,
[ADR-0004](../adr/0004-response-signing.md)). It is versioned separately from
btauth/1 and uses its own `X-TW-Resp-*` headers, never the reserved
`X-Bittensor-*` names.

Implementation: `tensorwire.extensions.response_sig` (`response_payload`,
`sign_response`, `verify_response`, `body_digest`). Cross-language vectors:
[`conformance/vectors/twresp.json`](../../conformance/vectors/twresp.json).

## Headers

Set by the miner on the response:

| Header | Value |
|---|---|
| `X-TW-Resp-Version` | `1` |
| `X-TW-Resp-Hotkey` | the miner's hotkey (SS58, prefix 42) |
| `X-TW-Resp-Crypto` | `ed25519`; omitted for sr25519 |
| `X-TW-Resp-Signature` | `0x` + 128 lowercase hex characters (64 bytes) |

Header names are compared case-insensitively. Verifiers accept an explicit
`X-TW-Resp-Crypto: sr25519` as well as the omitted header.

## Signed payload

Seven lines, UTF-8, joined with `\n`, **no trailing newline**:

```
twresp/1
<scheme>                       sr25519 | ed25519
<request nonce>                decimal, from the request's X-Bittensor-Nonce
<request sender>               the validator's SS58 (X-Bittensor-Hotkey)
<responder>                    the miner's SS58
<HTTP status>                  decimal, 100-599
<body digest>                  sha256 of the raw response body, lowercase hex
```

- The body digest covers the exact bytes on the wire (after any encoding the
  handler chose), not a re-serialization.
- For a streamed response (spec 9.2) the status line is `200` and the digest
  line is the stream digest (sha256 over each chunk's `data` bytes, in order);
  the signature travels in the final `tw-end` event, not in a header.
- Signing rules are btauth/1's: sr25519 with the substrate signing context,
  ed25519 plain, over the **raw** payload. A signature over the
  `<Bytes>…</Bytes>` wrapping is rejected.
- `response_payload` refuses inputs that could make the payload ambiguous: an
  unknown scheme, a negative nonce, a status outside 100–599, a digest that is
  not 64 lowercase hex, an empty sender or responder, or one containing `\n`.

Binding the request's nonce and sender means a miner cannot replay an older
answer, and one validator's answer cannot be passed off to another.

## What the miner signs

With `TW_SIGN_RESPONSES=1` (the default):

| Response | Signed? |
|---|---|
| 200 from a protected route | yes |
| Errors after authentication: 403, 422, per-hotkey 429, 500, 504 | yes |
| Errors before authentication: 401, 413, per-IP 429, 503 | **no** |
| Answers to legacy v10 requests ([legacy-v10.md](legacy-v10.md)) | no (v10 Dendrites do not read it) |

Before authentication the miner does not know whom it would be signing for, and
signing attacker-chosen input would make it a signing oracle. The column
"Response signed?" in spec Appendix A lists every error code.

## What the validator checks

With `TW_VERIFY_RESPONSES=1` (the default), `verify_response` checks, in order:

1. No `X-TW-Resp-*` header appears twice (any case).
2. `X-TW-Resp-Version` is present and equals `1`.
3. `X-TW-Resp-Hotkey` equals the hotkey the request was addressed to.
4. The scheme is `sr25519` (header absent or `sr25519`) or `ed25519`; anything
   else is rejected.
5. `X-TW-Resp-Signature` is `0x` + 128 hex characters.
6. The signature verifies over the payload rebuilt from **what this validator
   sent** (nonce, sender) and what it received (status, body), under the
   declared scheme only. There is no fallback to the other scheme.

Any failure raises `ResponseSignatureError` (`code = "tw.bad_response_signature"`;
its `reason` is safe to log). `ValidatorClient` turns it into
`MinerResult(ok=False, error_code="tw.bad_response_signature")`, and a
response that verifies sets `MinerResult.response_verified=True`. Scoring code
must treat a failed check as a failed response (spec 8.8).

Turning either setting off is a weakening setting: it is logged at WARNING and
counted in `tw_unsafe_settings_active`.

## Worked example

Vector `B1` of `twresp.json`: `//Bob` (sr25519) answers `//Alice` with
status 200 and body `{"result":"HELLO"}` to the request with nonce
`1752076800000000000`.

```
body sha256 = 80954376cd070acaef248d40209cc03ca21aa691ca4a4b58fac4783a3c36727f

payload =
twresp/1
sr25519
1752076800000000000
5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
200
80954376cd070acaef248d40209cc03ca21aa691ca4a4b58fac4783a3c36727f

X-TW-Resp-Version: 1
X-TW-Resp-Hotkey: 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
X-TW-Resp-Signature: 0xb0fd62bf…d5578b   (sr25519: randomized, verify only)
```

The ed25519 vectors (`E1`–`E5`, `S1`) are deterministic: an implementation must
produce exactly the listed signature. For sr25519 (`B1`–`B4`) it must verify the
listed signature and produce its own that the Python verifier accepts.

## Conformance vectors

`conformance/vectors/twresp.json` is generated by
`conformance/generate.py twresp` from `response_sig` and has four kinds:

| Kind | Ids | Checks |
|---|---|---|
| `build_sr25519` | B1–B4 | body digest, payload bytes, header set; the signature verifies (B4: nonce at the u64 maximum, handled as a string) |
| `sign_ed25519` | E1–E5 | the same, plus the exact signature (unicode body, raw bytes, 504 error body, swapped keys) |
| `stream_ed25519` | S1 | the 9.2 stream digest over 3 chunks and the `tw-end` signature |
| `verify` | V1–V2, X1–X13 | accept: valid ed25519 / sr25519. Reject (`tw.bad_response_signature`): body, status, nonce or sender changed; another responder; version 2; ed25519 signature without `X-TW-Resp-Crypto` (no fallback); sr25519 signature declared ed25519; `<Bytes>`-wrapped signature; unknown scheme; non-hex signature; duplicate signature header; no headers |

Nonces are JSON strings so every language reads them without precision loss.
Keys are `//Alice` and `//Bob`, sr25519 and ed25519 (`keys` in the file).

## Testing

- `tests/unit/test_twresp_vectors.py`: every vector re-derived from this page
  with only `hashlib` and `tensorwire.crypto`, and `response_sig` checked
  against all of them.
- `tests/unit/test_response_sig.py`: unit tests of the module.
- `tests/integration/test_miner_requests.py`: the miner signs 200s and
  post-authentication errors and leaves pre-authentication errors unsigned.
- `tests/localnet/test_mixed_fleet_localnet.py`: TensorWire → TensorWire
  traffic on localnet is `response_verified`.

## Upstream

If the Bittensor core team adopts an official response extension, the kit
switches to it in a minor release and keeps accepting `X-TW-Resp-*` for at
least one more (spec 1.7).
