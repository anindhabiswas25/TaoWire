# ADR-0008: The v10 wire format is re-implemented; the kit never depends on bittensor v10

- Status: accepted (implementation in Phase 2: `extensions/legacy_v10/`)
- Date: 2026-10-22
- Owner: Engineer B
- Spec: Section 7 (ADR-0008), 8.11, 10b.6. PM decision D3

## Context

The two-way legacy bridge (spec 8.11) lets TaoWire miners serve v10 validators and TaoWire validators query v10 miners during a migration. The obvious shortcut would be to import the v10 SDK's `Synapse`/`Axon`/`Dendrite`, but that does not work:

- `bittensor==10.x` and `bittensor==11.x` are the same distribution name, so they cannot be installed together.
- v10 gets no more releases, so pinning it would freeze its security fixes and its dependency tree inside the kit.
- The wire format is small: headers, a sha3-256 body hash, and one sr25519 signature over a dotted string.

## Decision

1. `extensions/legacy_v10/wire.py` re-implements the v10 wire format with the kit's `crypto.py` (sr25519 sign/verify, SS58) and the standard library (sha3-256, base64, JSON). No v10 code is imported at runtime, and no v10 package is a dependency of any extra.
2. **The format is defined by captured bytes, not by memory or docs.**
   - `scripts/legacy_venv.sh` builds a separate venv (`~/.taowire/venvs/bittensor-10.5.0`) from a hash-locked requirements file (`scripts/legacy_v10.requirements.txt`).
   - `scripts/capture_v10_vectors.py` runs a real 10.5.0 `Axon` on loopback behind a recording TCP proxy and drives it with a real 10.5.0 `Dendrite`. It writes `conformance/vectors/legacy_v10.json`: 13 vectors, accepted cases V1–V5 and edge/failure cases N1–N8.
   - `python/tests/migration/test_legacy_v10_vectors.py` (64 tests) re-derives every hash, signed message and signature from those bytes with the v11 SDK. It is the reference the Phase 2 implementation must pass.
3. Spec 8.11.1 was rewritten from the captured bytes (2026-10-22). The earlier draft was wrong on several points:
   - The body is the whole Synapse.
   - `bt_header_input_obj_*` carries a default instance of the field type.
   - Successful (200) responses are unsigned.
   - Blacklisting runs before the signature check.
   - Nonce freshness has no upper bound.
4. **v10 marker (D3).** A v10 Axon answers a btauth/1 request with HTTP 500 carrying a `bt_header_axon_status_code` header (vector N7). Spec 8.11.3 step 2 uses that as the "this miner is v10" signal. The published axon `protocol` byte (ADR-0001, D1) is the first hint.

## Consequences

- The kit installs with v11 only. Users never need two SDKs, and the legacy path inherits the kit's security defaults (8.11.2: end dates of at most 180 days, D4).
- Correctness depends on the vectors. Any change to `wire.py` must keep `test_legacy_v10_vectors.py` and the Phase 2 mixed-fleet localnet test (spec 13.8) green. If a v10 behaviour is found that the vectors do not cover, capture a new vector first, then change the code.
- The capture script is the only kit code that imports v10 symbols. It runs only inside the legacy venv, and the lint config exempts it explicitly (`scripts/ruff.toml`).
- Trade-off accepted: a v10 bug that the vectors do not exercise can differ between the real v10 stack and the kit. The mixed-fleet localnet test (Phase 2) runs real v10 neurons against the kit to catch that.
