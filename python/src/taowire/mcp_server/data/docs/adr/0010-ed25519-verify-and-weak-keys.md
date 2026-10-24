# ADR-0010: ed25519 uses RFC 8032 `verify`; weak public keys are refused in every language

- Status: accepted (PM decision D20, spec v1.6; first proposed on `eng-b/lang`)
- Date: 2026-10-23
- Spec: 11.5 (ed25519 edge cases, "document the choice in an ADR"), 4.3 step 4, 11.7, 16.1

## Context

ed25519 libraries disagree on rare inputs. `ed25519-dalek` 2 offers `verify` (RFC 8032, cofactorless,
canonical S required) and `verify_strict` (also refuses small-order R and A). Go's `crypto/ed25519` is
cofactorless RFC 8032. Polkadot's `sp_core` (which `bittensor.http_auth` uses) is ZIP-215-style.
For sr25519, `go-schnorrkel` refuses the identity public key while `schnorrkel` (Rust, `sp_core`) accepts it.

Probing the Python reference while building `negative.json` showed what matters in practice:

- A **weak public key** has a signature that verifies for every message. For the ed25519 identity
  point (`0100…00`), R = identity and S = 0 verify under cofactorless and cofactored rules alike; the
  same holds for the other seven small-order points. For sr25519, the ristretto identity (32 zero
  bytes) with R = identity, s = 0 verifies in schnorrkel. `bittensor.http_auth.verify` accepts both.
- Anyone can produce such a request "from" that address. `burned_register` is signed by the coldkey
  and takes the hotkey as an argument, so registering a weak address looks possible without its
  secret key (not tried on localnet). It would then sit in the metagraph, and the kit's caller policy
  would admit forged requests for it.
- Non-canonical S (S ≥ L), the cleared schnorrkel marker bit and non-point keys are already refused
  by every implementation (`negative.json` N53–N56).

## Decision

1. Rust uses `ed25519-dalek` 2 **`verify`**, not `verify_strict` (spec 11.5). Go uses
   `crypto/ed25519.Verify`. Both refuse non-canonical S, so they agree with each other and with the
   Python reference on every vector.
2. **Every TaoWire verifier refuses weak public keys** as `tw.auth_bad_signature`, as part of step 4,
   before the replay store is consulted: the sr25519 identity, and ed25519 keys whose point has order
   1, 2, 4 or 8. Python: `crypto.is_weak_public_key` (checked inside `RequestVerifier` after the SDK's
   signature check, through a store wrapper, so the replay store is never written). Go:
   `btauth.IsWeakPublicKey` (`filippo.io/edwards25519` cofactor multiplication). Rust:
   `is_weak_public_key` (`VerifyingKey::is_weak`). twresp/1 verification applies the same rule
   (Python: `crypto.verify(strict=True)`, which twresp/1 and the v10 wire use, refuses weak keys).
3. Vectors N63 (ed25519 identity) and N64 (sr25519 identity) pin the answer.
4. (D22, spec v1.6.) The Python request verifier is also strict on `<Bytes>`-wrapped signatures
   (A10): after the SDK's check it refuses a signature over `<Bytes>payload</Bytes>` as
   `tw.auth_bad_signature` (`crypto.is_bytes_wrapped_signature`, the strict half of
   `crypto.verify(strict=True)`), so no documented difference between Python and the strict
   implementations remains (N19, N20; spec 11.7).

## Consequences

- One rule in every language; no implementation-specific acceptance set to keep track of.
- The kit is stricter than `bittensor.http_auth` here, like the other stricter rules of spec 4.3 step 1.
  A real hotkey is never weak (its key is a hash output), so no honest caller is affected.
- If the SDK later refuses weak keys itself, the Python check becomes redundant but harmless.
