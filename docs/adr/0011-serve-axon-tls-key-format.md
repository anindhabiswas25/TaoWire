# ADR-0011: the `ServeAxonTls` certificate format and how validators pin it

- Status: accepted (Engineer, Phase 4, with the evidence below; spec 16.3 and decision D31 require this ADR
  before `https-if-tls-published` is enabled)
- Date: 2026-10-24
- Spec: 8.7.2 (scheme policies), 12.2 (`TW_TLS_*`), 16.3 (TLS), D31

## Context

A miner can publish a "neuron certificate" with its axon (`ServeAxonTls`). Spec 16.3 asks validators in
`https-if-tls-published` (and `https`) mode to pin the miner's TLS public key against the published one, and
asks this ADR to confirm the exact format and the meaning of the algorithm byte from the chain source, from
what the installed SDK sends, and from a localnet publish and read-back.

### Evidence

**Chain source.** `RaoFoundation/subtensor` at commit `8cf229f8ef969389d054a4c161b53ffd164a041f` (the
revision label of the `ghcr.io/raofoundation/subtensor-localnet:devnet` image the localnet runs; fetched
read-only for this ADR):

- `pallets/subtensor/src/macros/dispatches.rs` `serve_axon_tls` (call index 40) passes
  `certificate: Vec<u8>` to `do_serve_axon(..., Some(certificate))`.
- `pallets/subtensor/src/subnets/serving.rs` `do_serve_axon`:
  `if let Some(certificate) = certificate && let Ok(certificate) = NeuronCertificateOf::try_from(certificate)
  { NeuronCertificates::<T>::insert(netuid, hotkey_id, certificate) }`, then the axon is updated
  **whatever happened to the certificate**.
- `pallets/subtensor/src/lib.rs` `NeuronCertificate { public_key: BoundedVec<u8, ConstU32<64>>, algorithm: u8 }`
  and `TryFrom<Vec<u8>>`: more than 65 bytes → `Err`; empty → `Err`; otherwise the first byte is
  `algorithm` and the rest (0–64 bytes) is `public_key`. **The chain gives the algorithm byte no meaning**
  and never parses the key.
- Storage: `NeuronCertificates: (netuid, hotkey) -> NeuronCertificate`.

**Installed SDK (bittensor 11.3.0).** `intents/serving.py` `ServeAxonTls(certificate: str)` sends
`bytes.fromhex(certificate.removeprefix("0x"))` unchanged ("1 algorithm byte followed by up to 64 bytes of
public key. Not an X.509 certificate"). The SDK has no reader for certificates and defines no algorithm
values. The subtensor repository's generated doc `docs/tx/serve-axon-tls.mdx` says the same. The v10 SDK
(10.5.0) read certificates with `query_map(NeuronCertificates)` and concatenated `chr(algorithm) + public_key`,
also without an algorithm table; the docs page it cites (`docs.learnbittensor.org/subnets/neuron-tls-certificates`)
now redirects to the general docs index. **No algorithm convention exists in the ecosystem.**

**Localnet** (`reports/phase-4/wp6/serve-axon-tls-localnet.jsonl`; dev wallet `miner_go`, netuid 2, SDK 11.3.0):

| Sent (`certificate`) | Extrinsic | Read back (`NeuronCertificates`) |
|---|---|---|
| `0x01` + 32 bytes | success | `{algorithm: 1, public_key: <the 32 bytes>}` |
| `0x02` + 64 bytes | success | `{algorithm: 2, public_key: <the 64 bytes>}` |
| `0x02` + 65 bytes (66 total) | **success** | **unchanged: still the previous certificate** |
| empty | **success** | **unchanged** |
| `0x07` (algorithm byte only) | success | `{algorithm: 7, public_key: ""}` |

The SDK decodes the `public_key` bytes as **text when they happen to be valid UTF-8** and as `0x`-hex
otherwise (the 0..63 test key came back as control characters).

## Decision

1. **TensorWire's algorithm bytes.** Only these two are published or accepted:

   | Byte | Key | `public_key` (bytes) | TLS certificate key type |
   |---|---|---|---|
   | `0x01` | Ed25519 | 32: the raw key (RFC 8032) | Ed25519 |
   | `0x02` | ECDSA P-256 | 64: `X ‖ Y`, big-endian, the uncompressed point without its `0x04` prefix | EC, curve secp256r1 |

   RSA keys do not fit in 64 bytes and other curves are not supported. A miner whose certificate holds any
   other key gets a `StartupError` naming the supported types. A validator treats any other published value
   (unknown byte, wrong length, empty key) as **published but unusable**: a WARNING once per hotkey, and that
   miner is never reached over plain HTTP (point 4).
2. **What is pinned.** The leaf certificate's public key (from its SubjectPublicKeyInfo) must equal the
   published key byte for byte, after converting it to the form above. Nothing else of the certificate is
   checked: no CA chain, no hostname, no validity dates (the on-chain key is the trust anchor; a miner rotates
   by publishing a new key). The check happens **right after the TLS handshake, before any request byte is
   sent**, so the body never reaches a wrong peer.
3. **Publishing (miner).** The miner derives the compact form from its certificate (`TW_TLS_CERT_FILE`, or
   `TW_TLS_PUBLISHED_CERT_FILE` behind a TLS-terminating proxy), publishes it with `ServeAxonTls`, and then
   **reads `NeuronCertificates` back and compares** it with what it sent: the chain accepts the extrinsic even
   when it stores nothing (table above), and the SDK's text-or-hex decoding could in principle misread a key.
   A mismatch is a `StartupError`. A new key is published **before** it is served: if `ServeAxonTls` is
   rate-limited at startup, startup waits out the subnet's `serving_rate_limit` (once) before the server opens
   its port. The axon drift check (every 30 minutes) compares the stored key with the certificate and
   re-publishes when they differ; in proxy mode it re-reads `TW_TLS_PUBLISHED_CERT_FILE`, so a certificate the
   proxy renewed is published (uvicorn keeps its certificate until the miner restarts).
4. **Modes (D31).**
   - `http`: plain HTTP to every miner; published keys are ignored.
   - `https`: HTTPS to every miner. A usable published key → pinned (point 2, no CA trust). No published key →
     normal CA verification. Published but unusable → the miner fails (`tw.tls_pin_mismatch`), never HTTP.
   - `https-if-tls-published`: a usable published key → pinned HTTPS; published but unusable →
     `tw.tls_pin_mismatch`, never HTTP; nothing published → plain HTTP.
   - A pin mismatch is `tw.tls_pin_mismatch` and counts in `tw_tls_pin_failures_total`; it is never retried
     over HTTP, and the v10 fallback is not used for a miner that published a key in the HTTPS modes.
   - A miner that rotates its certificate without re-publishing is refused (`tw.tls_pin_mismatch`) until its
     new key is on chain.
5. **Reading.** The gateway reads `NeuronCertificates` for the subnet with the metagraph
   (`NeuronView.tls_key` = algorithm byte + key, or `None`) and turns the SDK's value into bytes: a string
   that is `0x` + an even number of hex digits (nothing else) is hex, any other string is its UTF-8 bytes, a
   byte list is the bytes. A value that cannot be read is `b""` (published, unusable); a row that cannot be
   tied to a hotkey fails the whole read (`SdkSurfaceError`), so nothing ever reads as "not published" by
   mistake. A real
   Ed25519 or P-256 key cannot be valid UTF-8 text that starts with `0x` and hex digits in practice, and if it
   ever were, the miner's own read-back check (point 3) refuses to start, so a misread key can only fail
   closed.

## Consequences

- Pinning works without any CA and without hostnames (axons are IPs).
- Two key types only; RSA certificates must be replaced by EC (P-256) or Ed25519 ones for pinning.
- A publisher that sends a malformed certificate keeps its old key on chain; TensorWire miners detect it at
  startup. Non-TensorWire miners that publish other formats are reached in the HTTPS modes only if they publish
  nothing (CA mode / HTTP), never pinned against a format this ADR does not define.
- If the ecosystem later standardises algorithm bytes, this table is amended in a new ADR; `0x01`/`0x02` stay
  readable.
