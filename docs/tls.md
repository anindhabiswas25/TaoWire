# TLS: the `taowire.tls` API

Behaviour, modes and deployment are in [security.md](security.md#tls-spec-163-d31-adr-0011); the key format is
[ADR-0011](adr/0011-serve-axon-tls-key-format.md). This page lists the public functions for code that works with
published TLS keys directly (the miner and `ValidatorClient` already use them).

| Name | What it does |
|---|---|
| `ALG_ED25519` (`0x01`), `ALG_P256` (`0x02`), `MAX_PUBLISHED_BYTES` (65) | The algorithm bytes TaoWire publishes and accepts, and the chain's size limit |
| `published_key_from_der(der) -> bytes` | The compact key (algorithm byte + key) of a DER certificate; `UnsupportedKey` for anything that is not an Ed25519 or P-256 certificate |
| `parse_published(raw) -> bytes \| None` | `raw` (what the chain stores, untrusted) if it can be pinned, else `None` ("published but unusable": refuse the miner, never use plain HTTP) |
| `pinned_context(expected) -> ssl.SSLContext` | A client context (TLS ≥ 1.2, no renegotiation) that accepts only a leaf certificate whose key is `expected`. The check runs when the handshake completes, before any request byte, for asyncio/anyio streams and blocking sockets alike. Works with `httpx.AsyncHTTPTransport(verify=...)` |
| `TlsPinMismatch` | The `ssl.SSLCertVerificationError` raised by a pinned context; `validator.client.is_pin_mismatch(exc)` finds it under an httpx error |
| `load_server_identity(cert_file, key_file) -> bytes` | The miner's startup check for `TW_TLS_CERT_FILE` / `TW_TLS_KEY_FILE` (readable, key `chmod 600`, unencrypted, matching, supported type); returns the key to publish; `StartupError` otherwise |
| `load_published_certificate(cert_file) -> bytes` | The same for `TW_TLS_PUBLISHED_CERT_FILE` (proxy mode: certificate only) |
| `chain.gateway.neuron_certificates(rows)` | `NeuronCertificates` rows from the SDK as `{hotkey: algorithm byte + key}` (`NeuronView.tls_key`); rows of an unexpected shape raise `SdkSurfaceError` (fail closed) |
| `testing.tls.make_certificate(dir, kind=..., ca=...)`, `make_ca(dir)` | Certificates for tests, generated at test time (`ed25519`, `p256`, and the refused `p384`, `rsa`) |

```python
import httpx
from taowire.tls import parse_published, pinned_context

key = parse_published(neuron.tls_key or b"")
if key is not None:
    transport = httpx.AsyncHTTPTransport(verify=pinned_context(key), retries=0)
```
