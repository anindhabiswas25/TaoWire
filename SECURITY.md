# Security policy

TaoWire is security software: it decides which requests a miner accepts and whether a
validator trusts a response. We take reports seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub private vulnerability reporting:
<https://github.com/anindhabiswas25/TaoWire/security/advisories/new> (the repository's Security tab,
"Report a vulnerability").

Please include: affected version or commit, a description, steps to reproduce, and the impact you
see. We will acknowledge the report, agree a disclosure date with you, and credit you unless you
prefer otherwise. During the alpha, reports are handled on a best-effort basis with no
response-time commitment; the commitments of spec Section 20.2 will be published here before 1.0.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.0a1 and later alphas (pre-release) | alpha: **not security-reviewed**, for localnet and testnet only, not for mainnet value; fixes go into the next alpha, with no backports |

## Scope

In scope: everything in this repository (Python package, TypeScript/Go/Rust btauth packages,
sidecar, conformance vectors). Out of scope: the Bittensor SDK and chain (report those upstream),
and host hardening (see `docs/security.md`).
