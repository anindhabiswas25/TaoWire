# Security policy

TensorWire is security software: it decides which requests a miner accepts and whether a
validator trusts a response. We take reports seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's
"Report a vulnerability" (private security advisories) on the TensorWire repository.

Please include: affected version or commit, a description, steps to reproduce, and the impact you
see. We will acknowledge the report, agree a disclosure date with you, and credit you unless you
prefer otherwise. Response-time commitments are set in spec Section 20.2 and will be published
here before the first release.

## Supported versions

| Version | Supported |
|---|---|
| 0.x (pre-release) | development only; no security support yet |

## Scope

In scope: everything in this repository (Python package, TypeScript/Go/Rust btauth packages,
sidecar, conformance vectors). Out of scope: the Bittensor SDK and chain (report those upstream),
and host hardening (see `docs/security.md`).
