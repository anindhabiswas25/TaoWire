# TaoWire — Build Specification

**A production-grade networking starter kit for Bittensor v11 subnets, and the migration path for existing v10 subnets**
Python core · btauth/1 native · v10 → v11 migration (compat layer, two-way bridge, `taowire migrate`) · TypeScript, Go and Rust support · testnet end-to-end

| Field | Value |
|---|---|
| Document version | 1.10 |
| Changes in 1.1 | Migration of existing v10 subnets is a first-class goal: new Section 10b, two-way legacy bridge (8.11), `taowire migrate` CLI, migration rollout runbook, success criterion S6, phase plan updated |
| Changes in 1.2 | SDK version range instead of an exact pin (3, 18); staged metagraph staleness instead of a 15-minute hard stop (8.5.1); product metrics (1.6); relationship with the core team (1.7); sustainability and maintenance (Section 20) |
| Changes in 1.3 | Phase 0–1 findings: protocol tag is a u8, default 87 (D1); stake units and `total_stake_tao` (D2, 2, 8.3); v10 marker (D3, 8.11.3); write retries and `set_weights` meaning (8.3); stricter shape rules (4.3); localnet facts (14.2, 14.5); 8.11.1 rewritten from captured vectors (by Engineer B) |
| Changes in 1.4 | Phase 2 findings: component dependencies without a cycle (5.2); one time budget per query incl. the v10 fallback (8.8); v10 end-date wording, axon-signature scope, non-finite floats in v10 answers (8.11.2-8.11.3); `https-if-tls-published` refused until TLS ships (8.6); days-remaining gauge kept current (8.11); compat additions (10b.2); how S6 is counted (1.5, 13.8); `tw.legacy_auth_failed` covers unparseable bodies (Appendix A) |
| Changes in 1.5 | Phase 3 finding F1 (Engineer B, rollout walk-through): no-downgrade vs the stage 2 rollback. A signed on-chain protocol-tag change away from `TW_PROTOCOL_TAG` clears the hotkey's protocol memory (D16; 8.11.3 step 5, 10b.5 stage 2 rollback, integration test 13) |
| Changes in 1.6 | Phase 3 gate: benchmarks count with Redis reached directly (D17, 13.7); S6 counts hand-written changes in customised template bases (D18, 1.5); sender must be 48 characters before base58 decoding (D19, 4.3); weak public keys refused, ADR-0010 accepted (D20, 4.3); nonce-store expiry vs wall-clock steps, fail-closed window (D21, 8.4.3-8.4.4); Python verifier strict on `<Bytes>` too (D22, A10, 11.7); Go toolchain, module path and dalek v2 (D23, 11.4-11.5) |
| Changes in 1.7 | Phase 3 re-gate and Phase 4 set-up: one partner subnet closes S6 for Phase 3 (D24, 17); D22's cost accepted (D25); `go 1.22` + x/crypto until 1.0 (D26, 18.4); retention ≥ 2 × window in the config table and `tw_clock_step_seconds` (D27, 12.2, Appendix B); `required_hash_fields` changes break a mixed fleet (D28, 10b.5); streaming rules and settings (D29, 9.2, 12.1, 13.4, 13.6); timelock behind the gateway, settings and `tw.timelock_unavailable` (D30, 8.10, 12.3, Appendix A); TLS modes, pinning and `tw.tls_pin_mismatch` (D31, 8.7.2, 12.2, 16.3); expired timelocked commits are re-planned (D32, 8.9); `StreamingSynapse` over the v10 wire not supported (D33, 10b.3); `compat.Subtensor` facade (D34, 10b.2.6); Phase 4 tasks and exit criteria (17) |
| Changes in 1.8 | Phase 4 gate: stream chunks are JSON objects or arrays (D35, 9.2); `TW_STREAM_MAX_PER_CALLER` (D36, 9.2, 12.1); TLS with the v10 inbound bridge warns, never refused (D37, 16.3); `WeightsVersionKey` preflight before a timelocked commit (D38, 8.9); pinned cargo/npm tools before 1.0 (D39, 18.4); ADR-0001 exception for `bittensor_core` in the gateway (D40, 8.10); Phase 4 process (D41); the shared limiter fails closed and an attacker's 503 is a valid refusal (D42, 8.6.2, 13.6); Phase 5 carry-overs G6-1..G6-5 (17) |
| Changes in 1.9 | Phase 5 gate: stream chunks nest at most 128 levels, the `tw-end` count is a plain non-negative integer and trailer strings hold no lone surrogates, in every language (D43, 9.2); `tw.sidecar_unauthorized` and the `/v1/serve-axon` refusal shapes (D44, 11.6, Appendix A); the 13.6 flood CPU bound is measured on a quiet host (D45, 13.6); Phase 6 carry-overs G7-1..G7-3 (17) |
| Changes in 1.10 | The product is renamed **TaoWire** (was TensorWire; the name is taken by an unrelated project): package, CLI, module paths, state directory; every wire and operator name (`TW_*`, `tw.*`, `twresp/1`, `X-TW-Resp-*`, `tw-end`, `tw_*` metrics, `TWM*` rules) is unchanged (D46, 3.1, 6); a labelled alpha pre-release before Phase 6 so builders can try the kit and review it (D47, 18.5) |
| Date | 24 October 2026 |
| Target SDK | `bittensor>=11.3.0,<12` (baseline verified against 11.3.0, stable, released 7 Oct 2026; see Section 18.3) |
| Target protocol | `btauth/1` (hotkey-signed HTTP, defined by the Bittensor v11 docs) |
| Audience | Backend engineers and blockchain engineers building the kit |
| Out of scope for this version | CI/CD workflows (`.github/`, pipelines), hosted services, a GUI |

> **Product name.** "TaoWire" / `taowire` is a working name. Check that the name is free on PyPI, npm, crates.io and GitHub before Phase 0 ends, and rename everywhere with one search-and-replace if it is not.

---

## How to use this document

This file is meant to be enough on its own. An engineer who has never used Bittensor should be able to read it top to bottom and build the product.

- **Section 1** says what we are building and why.
- **Section 2** is a Bittensor primer: the concepts you need, and nothing else.
- **Section 3** is the exact v11 SDK surface the kit uses. It was checked against the `bittensor==11.3.0` source code.
- **Section 4** is the full `btauth/1` wire protocol, copied so you do not need the external docs to implement it.
- **Sections 5–7** cover the architecture, the repository skeleton and the design decisions.
- **Sections 8–12** are the detailed build specification for every component, in every language. **Section 10b** covers migrating existing v10 subnets.
- **Sections 13–15** cover testing, local development and the testnet end-to-end runbook.
- **Sections 16–18** cover security, the phase plan with acceptance criteria, and release. **Section 19** lists risks; **Section 20** covers funding and maintenance.
- **Appendices** hold reference tables, test vectors and links.

Rules for the build team:

1. **The v11 SDK is the only way the Python code talks to the chain.** Never call a chain RPC directly from kit code, and never copy SDK logic into the kit.
2. **All v11 calls go through one module** (`taowire/chain/gateway.py`). If v11 changes, you fix one file.
3. **Secure by default.** No setting may be needed to be safe. Settings that are unsafe must have names that say so (for example `unsafe_allow_unbound_receiver`).
4. **The Python implementation is the reference.** Other languages must pass the shared conformance vectors (Section 11) before they can be released.
5. When this document and the live v11 docs disagree, **the live docs win**. Update this document in the same pull request.

---

## Table of contents

1. [Product definition](#1-product-definition)
2. [Bittensor primer for this project](#2-bittensor-primer-for-this-project)
3. [The v11 SDK surface the kit uses (verified)](#3-the-v11-sdk-surface-the-kit-uses-verified)
4. [The btauth/1 protocol (normative copy)](#4-the-btauth1-protocol-normative-copy)
5. [Architecture](#5-architecture)
6. [Repository skeleton](#6-repository-skeleton)
7. [Design decisions](#7-design-decisions)
8. [Python core: component specifications](#8-python-core-component-specifications)
9. [Kit protocol extensions (response signing, streaming)](#9-kit-protocol-extensions-response-signing-streaming)
10. [The example subnet](#10-the-example-subnet)
10b. [Migrating existing v10 subnets](#10b-migrating-existing-v10-subnets)
11. [Multi-language support: TypeScript, Go, Rust](#11-multi-language-support-typescript-go-rust)
12. [Configuration reference](#12-configuration-reference)
13. [Testing strategy](#13-testing-strategy)
14. [Local development runbook](#14-local-development-runbook)
15. [Testnet end-to-end runbook](#15-testnet-end-to-end-runbook)
16. [Security specification](#16-security-specification)
17. [Phase plan and acceptance criteria](#17-phase-plan-and-acceptance-criteria)
18. [Versioning and manual release process](#18-versioning-and-manual-release-process)
19. [Risks and open questions](#19-risks-and-open-questions)
20. [Sustainability and maintenance](#20-sustainability-and-maintenance)
- [Appendix A — Error codes and HTTP status mapping](#appendix-a--error-codes-and-http-status-mapping)
- [Appendix B — Metrics catalogue](#appendix-b--metrics-catalogue)
- [Appendix C — Golden test vectors](#appendix-c--golden-test-vectors)
- [Appendix D — SS58 address decoding](#appendix-d--ss58-address-decoding)
- [Appendix E — Reference links](#appendix-e--reference-links)
- [Appendix F — Glossary](#appendix-f--glossary)

---

## 1. Product definition

### 1.1 The problem

Bittensor v11 (shipped July 2026) removed the old miner/validator networking stack: `Axon`, `Dendrite`, `Synapse`, `StreamingSynapse`, `SubnetsAPI` and `Tensor` no longer exist. What is left is:

- `bittensor.http_auth.sign` / `verify`: pure functions that prove who sent an HTTP request (`btauth/1`),
- `ServeAxon`: publishes `ip:port` on chain,
- the metagraph: who is registered, who is a validator, where they listen.

Everything in between is now each team's job: the miner's HTTP server, the validator's client, replay protection that works across processes, caller filtering, rate and size limits, retries, streaming, tests. The official subnet template is archived and does not work with v11. No general-purpose v11 kit existed as of 22 October 2026.

The problem is worse for **existing subnets** (about 128 on mainnet). Most started as forks of the archived template, so their code is built around `Synapse` subclasses, `axon.attach(forward, blacklist, priority)` and `dendrite(axons, synapse)`. Moving to v11 means rewriting all of that by hand. Miners and validators are run by different people who upgrade at different times, so a subnet cannot switch everyone on one day: for weeks, v10 and v11 nodes must talk to each other in both directions. v10 stays installable and the migration guide sets no end-of-support date, but chain runtime upgrades (about 14 between July and October 2026) can break v10 code at any time.

### 1.2 The product

TaoWire is an open-source kit that fills **only** that gap, securely and simply:

| Deliverable | Language | What it is |
|---|---|---|
| `taowire` | Python | Miner server, validator client, security layer, chain gateway, validator loop, test harness, CLI |
| `taowire.compat` | Python (part of `taowire`) | v10-shaped API (`Synapse`, `StreamingSynapse`, `Axon`, `Dendrite`, `AxonInfo`) on top of the kit, so existing subnets migrate by changing imports (Section 10b) |
| Two-way legacy bridge | Python (part of `taowire`) | v10 validators → TaoWire miners, and TaoWire validators → v10 miners, during a time-boxed transition (Section 8.11) |
| `taowire migrate` | Python CLI | Scans a v10 subnet repo, rewrites what is safe automatically, and reports the rest (Section 10b.4) |
| `taowire-sidecar` | Python (part of `taowire`) | Local service that lets non-Python miners read the metagraph and publish their endpoint |
| `@taowire/btauth` | TypeScript | btauth/1 sign + verify, nonce stores, Fastify plugin, fetch client |
| `taowire/go/btauth` | Go | btauth/1 sign + verify, nonce stores, `net/http` middleware, client |
| `taowire-btauth` | Rust | btauth/1 sign + verify, nonce stores, axum layer, reqwest client |
| `conformance/` | JSON + runners | Shared test vectors every language must pass |
| `examples/text-ops-subnet` | Python (+ miners in TS/Go/Rust) | A working subnet used for local and testnet end-to-end tests |

### 1.3 Goals

1. A new subnet team gets a working miner and validator on a local chain in **under one hour**, writing only their task logic and scoring logic.
2. Every security trap listed in Section 16 is handled by default.
3. Fully compatible with `btauth/1`, so a TaoWire miner can talk to any other correct btauth/1 client and the other way round.
4. Miners can be written in Python, TypeScript, Go or Rust; validators in Python (required) and TypeScript/Go/Rust (client signing only).
5. Proven end to end on **Bittensor testnet**, across all four languages.
6. An **existing template-derived v10 subnet** moves to v11 mostly by changing imports, and keeps working while its v10 and v11 miners and validators run side by side. The subnet owner controls each step of the rollout and can roll each step back (Section 10b.5).

The kit has two audiences with equal priority: **new subnet teams** (goals 1–5) and **existing subnets migrating from v10** (goal 6).

### 1.4 Non-goals

- Re-wrapping v11 features (staking, transfers, EVM, wallets). Users call v11 directly for these. For migration, `taowire migrate` points to the v11 replacement instead of wrapping it; the only exception is a small `compat.weights` helper (Section 10b.2.5).
- Keeping v10 compatibility forever. Every legacy path has a mandatory end date.
- Supporting v10 code that does not follow the template shape (custom Axon subclasses, monkeypatched Dendrite). `taowire migrate scan` flags these for manual work.
- Choosing a subnet's incentive mechanism. The kit gives scoring hooks, not scoring rules.
- Hosting, dashboards or a GUI.
- CI/CD workflows. Every check in this spec must be runnable by hand with one command (`just ...`), so CI can be added later without changing the code.
- Non-HTTP transports (QUIC, gRPC). These can come later behind the same interfaces.

### 1.5 Success criteria (product level)

| # | Criterion | How it is measured |
|---|---|---|
| S1 | Testnet e2e passes for the language matrix in Section 15.7 | Runbook evidence: logs, block numbers, weights read back from chain |
| S2 | All conformance vectors pass in all four languages | `just conformance` exits 0 |
| S3 | No high or critical findings open from the security review | Review report |
| S4 | Quickstart works on a clean Ubuntu 24.04 and macOS machine | Timed walkthrough under 60 minutes |
| S5 | Miner sustains ≥ 500 verified requests/second on 4 vCPU with p99 auth overhead ≤ 5 ms | `just bench` report (Section 13.7) |
| S6 | A template-derived v10 subnet migrates with ≤ 50 changed lines (excluding import lines and every change `migrate apply` makes on its own, e.g. `bt.logging` → `logging` and the `template/base` → `TemplateValidatorAdapter` swap), and a mixed fleet runs on localnet. Counted as `git diff --stat` between `migrate apply` output and the final port, subnet code only. "Subnet code" includes the subnet's own customised copies of the template's base classes and config modules (for example `<pkg>/base/*`, `utils/config.py`): hand-written changes there count, and only changes `migrate apply` makes on its own are excluded (D18). If a common customisation pattern costs many lines, the answer is a `migrate` rule or compat helper, not a narrower count | Migration case studies (Section 13.8): lines changed, hours spent, mixed-fleet matrix green |
| S7 | At least 2 real v10 subnets (design partners) ported, plus the archived template | Case-study reports in `docs/migrations/` |

S1–S7 decide when 1.0 is **done**. They do not say whether the product **works for users**; Section 1.6 does.

### 1.6 Product metrics (after release)

Engineering criteria can all pass while nobody uses the kit. These metrics tell us whether TaoWire is succeeding. The PM reviews them monthly and publishes them in `docs/metrics.md`.

| # | Metric | How it is measured | Target (3 months after 1.0) | Target (6 months) |
|---|---|---|---|---|
| M1 | Mainnet subnets running TaoWire | On-chain axons advertising `TW_PROTOCOL_TAG` (8.7.2; depends on the Phase 0 check that the protocol field is readable, 8.11.3), counted per subnet with a script over all metagraphs; cross-checked with public repos that depend on `taowire` | 5 | 15 |
| M2 | Subnets migrated from v10 with the kit | Case studies, `migrate` users who report back, M1 subnets that were on v10 before | 3 | 8 |
| M3 | Time from `pip install` to first weights on localnet | Timed sessions with new users (at least 5 per quarter), not the team | ≤ 60 min median | ≤ 45 min median |
| M4 | Time from `migrate scan` to a running mixed fleet | Same, with teams of existing subnets | ≤ 1 working day | ≤ 4 hours |
| M5 | Usage trend | PyPI / npm / crates.io downloads per month; GitHub issues and PRs from people outside the team | Rising month over month | Rising |
| M6 | Support health | Median time to first reply on issues; open security reports past their deadline (20.2) | ≤ 3 days; 0 | ≤ 2 days; 0 |

Rules:

- **No telemetry in the kit.** A security library that phones home will not be trusted. All metrics come from public data (chain, registries, GitHub) or from users who talk to us.
- **Decision point at 6 months:** if M1 < 5 and M2 < 3, stop adding features and find out why (interviews with subnet teams that chose not to adopt), then decide with stakeholders whether to change direction, hand the project to the core team (1.7), or wind it down.

### 1.7 Relationship with the Bittensor core team

The core team owns btauth/1, publishes FastAPI and httpx recipes in the official docs, and archived the old template with no successor. Shipping an official server/client or a new template is a natural next step for them. If they do it without us, most teams will choose the official option. They also have to help every existing subnet move off v10, which is what Section 10b does. So the core team is our most important **partner**, not a competitor to work around.

Plan:

1. **Phase 0: first contact.** Share this spec with the core team (through the subtensor GitHub repo and the official community channels). Ask three things: are they planning an official kit or template; would they link TaoWire from the migration and signed-requests guides if it meets their bar; what would that bar be.
2. **Upstream, don't fork.** Anything that belongs in the protocol goes upstream first:
   - `twresp/1` (Section 9.1) is proposed as an official btauth response extension in Phase 1 (ADR-0004).
   - Bugs or gaps found in `bittensor.http_auth` are reported and fixed upstream, never patched around silently in the kit.
   - The conformance vectors (Section 11.7) are offered to the core team as shared vectors for all btauth/1 implementations.
3. **Agree on boundaries.** Write down who owns what (for example: the SDK owns sign/verify and chain access; TaoWire owns servers, clients, policy, migration tooling) in `docs/adr/0009-core-team-boundaries.md`, and revisit it every quarter.
4. **If they build an official kit anyway:** make TaoWire interoperate with it fully, offer our migration tooling and tests to it, and decide (1.6 decision point) whether to merge into it rather than compete.

Owner: the PM. Progress is reported in the monthly metrics review.

---

## 2. Bittensor primer for this project

Only what you need to build the kit.

**Chain.** Bittensor's chain is called **subtensor**. It produces a block every 12 seconds on mainnet and testnet. A local development chain can run "fast blocks" (0.25 seconds).

**Networks.** The v11 SDK knows these names (from `bittensor/settings.py` in 11.3.0):

| Name | Endpoint | Use |
|---|---|---|
| `finney` | `wss://entrypoint-finney.opentensor.ai:443` | Mainnet |
| `test` | `wss://test.finney.opentensor.ai:443` | Public testnet |
| `local` | `ws://127.0.0.1:9944` (override with `BT_CHAIN_ENDPOINT`) | Local Docker chain |

Public endpoints are rate-limited to roughly 1 request per second per IP. Long-running validators should run their own node.

**Subnet.** A numbered (`netuid`) competition. **Miners** do the work, **validators** score the miners, and the chain pays both in proportion to scores. Each subnet has a fixed number of slots (**UIDs**, default 256).

**Keys.** Every participant has two keypairs:

- **Coldkey**: holds money, password-encrypted, should never be on a server.
- **Hotkey**: the operational identity. It signs requests, weights and axon publishing. **Hotkey files are unencrypted on disk by default.** It is the only key that lives on a miner or validator machine.

Keys are sr25519 by default. Addresses are SS58 strings with prefix 42 (they start with `5`).

**Registration.** A hotkey gets a UID on a subnet with `BurnedRegister` (it pays a floating burn price from the coldkey). When the subnet is full, each new registration evicts the lowest-scoring neuron that is not immune. A fresh UID is immune for `immunity_period` blocks (default 4,096).

**Axon (endpoint).** In v11, "axon" just means the `ip:port` a hotkey published on chain with the `ServeAxon` intent. Publishing does **not** start a server; the kit does that. Re-publishing is rate-limited (`serving_rate_limit`, default 50 blocks).

**Metagraph.** A snapshot of a subnet: every UID's hotkey, coldkey, stake, validator permit, axon and scores. Validators read it to find miners. Miners read it to decide which callers are real validators.

**Validator permit.** Each epoch, the top `MaxAllowedValidators` (default 128) neurons by stake weight get a permit. On mainnet, a stake weight below roughly 1,000 (`StakeThreshold`) counts as zero; the runtime default is 0. Stake weight is `alpha stake + TaoWeight × root TAO stake`, in the subnet's alpha units (verified on localnet, ADR-0001), not TAO. Only permit holders with enough stake can set weights.

**Weights.** A validator's scores for miners, submitted with the `SetWeights` intent. Rate-limited by `weights_rate_limit` (default 100 blocks). On subnets with commit-reveal enabled (the default), weights are timelock-encrypted and revealed automatically later; `SetWeights` handles this.

**Tempo / epoch.** Every `tempo` blocks (default 360, about 72 minutes) the chain runs consensus (Yuma Consensus by default) and pays out.

**Consensus modes.** Subnets run Yuma (default) or the newer opt-in **Null** consensus (only the highest-stake validator holds a permit). The kit must not assume either.

**Timelock / drand.** Data can be encrypted so nobody can open it before a chosen time, using the drand randomness beacon. v11 exposes this as `bittensor.timelock`.

---

## 3. The v11 SDK surface the kit uses (verified)

`scripts/check_sdk_surface.py` re-checks this section (45 checks; passing on 11.3.0 and 11.3.1rc73 in Phase 0). Everything below was checked against the source of `bittensor==11.3.0`, and the key behaviours were executed against an installed copy on 22 October 2026: the golden vectors in Appendix C (including the exact ed25519 signature), the nonce-store retention check, `resolve_signer` + `sp_core.verify` for response signing, the removed symbols in 3.8, and the intent constructors in 3.5. 11.3.0 is the **baseline**, not an exact pin. The kit is a library that lives inside subnet projects, which also depend on `bittensor`; an exact pin would block them from taking SDK bug fixes. So the kit accepts `bittensor>=11.3.0,<12`, and safety comes from checks instead of the pin: `scripts/check_sdk_surface.py` re-checks every item in this section, each new SDK release is tested before it is listed as supported (Section 18.3), and the kit runs a light version of the surface check at startup (Section 8.7.3).

### 3.1 Package facts

- Install: `pip install "bittensor>=11.3.0,<12"` (the kit's own dependency; the lock file pins an exact tested version for development). Python `>=3.10,<3.15`. Linux and macOS wheels; Windows is unsupported (use WSL).
- One package provides the SDK, `btcli` and the wallet. Do **not** install `bittensor-cli` or `bittensor-wallet` alongside it (both conflict).
- The SDK has **no** HTTP server or client dependency. The kit brings FastAPI, uvicorn and httpx.
- Logging uses the standard library under the `bittensor.*` logger namespace.
- The SDK never reads `sys.argv`. The kit owns its own configuration.

### 3.2 `bittensor.http_auth` (exact API)

```python
# Constants
PROTOCOL = "btauth/1"
VERSION = "1"
HEADER_VERSION   = "X-Bittensor-Version"
HEADER_HOTKEY    = "X-Bittensor-Hotkey"
HEADER_RECEIVER  = "X-Bittensor-Receiver"
HEADER_NONCE     = "X-Bittensor-Nonce"
HEADER_CRYPTO    = "X-Bittensor-Crypto"
HEADER_SIGNATURE = "X-Bittensor-Signature"
DEFAULT_MAX_AGE = 10.0        # seconds
DEFAULT_ALLOWED_SKEW = 2.0    # seconds

# Errors (all subclass AuthError, itself a BittensorError).
# Messages never echo the signature or payload; safe to return to callers.
class AuthError: ...
class MalformedAuth(AuthError): ...
class WrongReceiver(AuthError): ...
class StaleRequest(AuthError): ...
class ReplayedRequest(AuthError): ...
class BadSignature(AuthError): ...

@dataclass(frozen=True)
class Caller:
    hotkey_ss58: str
    nonce_ns: int
    crypto_type: int

class NonceStore(Protocol):
    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool: ...
    # True = never seen (and now recorded). False = replay.

class InMemoryNonceStore:
    def __init__(self, retention: float = 60.0): ...   # per process only

def build_payload(*, scheme, method, path, body, nonce_ns, sender_ss58, receiver_ss58) -> bytes

def sign(wallet, *, method, path, body=b"", receiver_ss58=None, nonce_ns=None) -> dict[str, str]

def verify(headers, body, *, method, path, self_hotkey_ss58,
           max_age=10.0, allowed_skew=2.0, require_receiver=True,
           nonce_store=None, now_ns=None) -> Caller
```

Behaviour that matters for the kit (read from the source, not just the docs):

| # | Fact | Consequence for the kit |
|---|---|---|
| A1 | `verify` and `NonceStore.check_and_store` are **synchronous**. | Call `verify` in a worker thread (`anyio.to_thread.run_sync`). The Redis nonce store must use a **sync** Redis client. |
| A2 | If no `nonce_store` is passed, a **module-level global** `InMemoryNonceStore` is used. | The kit always passes its own store explicitly. |
| A3 | `verify` raises `ValueError` if the store has a `retention` attribute smaller than `max_age + allowed_skew`. | Every kit nonce store exposes `retention` and validates it at startup. |
| A4 | The nonce store is written **only after** the signature verifies. | Unauthenticated traffic cannot fill the store with junk. Keep this ordering if you ever wrap verify. |
| A5 | `sign` uses `time.time_ns()` for the nonce unless `nonce_ns` is given. Two signatures in the same nanosecond tick (coarse clocks, VMs) collide, and the second is rejected as a replay. | The kit signer passes a strictly increasing nonce (Section 8.4.1). |
| A6 | `sign` needs a **synchronous** signer. Ledger, Vault and browser-extension signers are not usable for btauth. | Hotkeys on servers are local keyfiles. Document this. |
| A7 | Only `sr25519` and `ed25519` are valid schemes (`CRYPTO_TYPE_NAMES`). The `X-Bittensor-Crypto` header is sent only for ed25519. | Other-language implementations must use the same rule. |
| A8 | `verify` lower-cases header names itself and accepts a `Mapping[str, str]`. | Pass Starlette's headers directly or convert to `dict`. |
| A9 | `now_ns` is injectable. | Tests can freeze time without monkeypatching. |
| A10 | The SDK's verifier (via `sp_core`) also accepts signatures over the `<Bytes>…</Bytes>`-wrapped payload (Polkadot-JS `signRaw` compatibility). Other implementations are not required to accept it and must never produce it. | Kit verifiers in **every** language, Python included, **reject** it (strict mode; decision D22). The Python request verifier checks with `crypto.verify(strict=True)` after the SDK's own checks. The conformance vector expects `tw.auth_bad_signature` everywhere. |
| A11 | `sp_core.verify` (and so `verify`) accepts the sender's address in **any** SS58 format, not only prefix 42 (checked in Phase 0). | Other implementations accept prefix 42 only (Appendix D); add a negative conformance vector. Python stays safe: the address string is signed, and policy looks callers up by their prefix-42 address, so such a caller fails closed. `taowire.crypto` accepts prefix 42 only. |

### 3.3 Client and reads

```python
import bittensor as bt

# Async (the kit always uses async):
async with bt.Subtensor("test") as client:          # "finney" | "test" | "local" | "ws://..."
    block = await client.block()
    mg = await client.subnets.metagraph(netuid, commitments=False)   # Optional[Metagraph]
    uid = await client.neurons.uid(hotkey_ss58=hk, netuid=netuid)    # Optional[int]
    wrl = await client.hyperparameters.weights_rate_limit(netuid=netuid)
    since = await client.epochs.blocks_since_last_update(netuid=netuid, uid=uid)
    nxt = await client.epochs.blocks_until_next_epoch(netuid=netuid)
```

`bt.Subtensor(...)` also accepts `fallback_endpoints=`, `archive_endpoints=`, `retry_forever=` and `policy=`.

### 3.4 Metagraph types

`bt.Metagraph` fields: `netuid, mechid, name, symbol, block, tempo, last_step, blocks_since_last_step, owner_hotkey, owner_coldkey, network_registered_at, num_uids, max_uids, price, moving_price, identity, neurons, commitments, unregistered_commitments, raw`.
Helpers: `hotkeys`, `coldkeys`, `validators`, `neuron(uid)`, `by_hotkey(hotkey) -> Optional[MetagraphNeuron]`, `len()`, iteration in UID order.

`bt.MetagraphNeuron` fields: `uid, hotkey, coldkey, active, validator_permit, last_update, block_at_registration, rank, trust, consensus, incentive, dividends, pruning_score, emission, alpha_stake, tao_stake, total_stake, axon, identity, commitment, collateral_locked, collateral_min, collateral_earned`.

`axon` is `Optional[str]`:
- IPv4: `"203.0.113.7:8091"`
- IPv6: `"[2001:db8::1]:8091"` (brackets included)
- `None` when nothing is served (IP 0).

The string has **no scheme**. The kit decides `http://` or `https://` (Section 8.7.2).

Stake fields are `bt.Balance` values. Compare with `bt.tao(x)`, never a bare float (`TypeError`), and never mix TAO with alpha (`bt.UnitMismatchError`).

Units (verified on localnet in Phase 0): `alpha_stake` and `total_stake` are in the subnet's alpha (a `Balance` tagged with the netuid; `.tao` raises `UnitMismatchError`), and `tao_stake` is root TAO. `total_stake` is the chain's stake weight, `alpha_stake + TaoWeight × tao_stake`, not a TAO amount (see 8.3). `Metagraph.raw["axons"][uid]` is a dict `{block, version, ip, port, ip_type, protocol, placeholder1, placeholder2}`, so the published `protocol` byte is readable.

### 3.5 Intents used

```python
bt.ServeAxon(netuid: int, ip: str, port: int, protocol: int = 4, version: int = 1)
bt.ServeAxonTls(netuid: int, ip: str, port: int, certificate: str, protocol: int = 4, version: int = 1)
#   certificate = 0x-hex: 1 algorithm byte + up to 64 bytes public key. NOT an X.509 blob.
bt.SetWeights(netuid: int, uids=None, weights=None, mechid: int = 0,
              version_key: int = 0, raw_u16: bool = False)
#   weights may be a {uid: float} mapping (uids omitted) or parallel lists.
#   Normalises, clips, quantises, and auto-picks plain vs timelocked commit-reveal.
bt.BurnedRegister(netuid: int, hotkey_ss58: Optional[str] = None)   # signed by coldkey
```

On chain, `protocol` is a **u8** (0–255); a larger value fails to encode (`ValueError: integer out of range`). The chain rejects `ip="127.0.0.1"` (`InvalidIpAddress`) but accepts other loopback and private addresses, and it accepts `0.0.0.0`, which reads back as "not served" (`axon=None`). `BurnedRegister` is always submitted MEV-shielded (`mev_shield_required`); `ServeAxon` and `SetWeights` are never shielded.

`ServeAxon` and `SetWeights` are **signed by the hotkey**. `BurnedRegister` and staking are signed by the **coldkey**. The kit never handles coldkeys at runtime; registration and staking are operator steps done with `btcli` on a trusted machine.

Execution:

```python
result = await client.execute(intent, wallet,
                              wait_for_inclusion=True, wait_for_finalization=True)
result.success            # bool
result.error.code         # bt.ErrorCode (see Appendix A)
result.error.remediation  # human hint
result.block_hash, result.explorer_url
plan = await client.plan(intent, wallet)   # fee, effects, warnings; nothing submitted
```

`bt.ErrorCode` values: `insufficient_balance, insufficient_liquidity, rate_limited, not_registered, not_authorized, already_exists, not_found, subnet_not_exists, subtoken_disabled, disabled, too_early, expired, limit_exceeded, unit_mismatch, invalid_argument, policy_violation, internal, unknown`.

### 3.6 Wallet and keys

```python
wallet = bt.Wallet(name="validator", hotkey="default", path="~/.bittensor/wallets")
wallet.hotkey          # Keypair; loads the hotkey file only
wallet.hotkey.ss58_address
```

- Accessing `wallet.hotkey` does not touch the coldkey. The kit must never access `wallet.coldkey`.
- On Python 3.10 and 3.11, `resolve_signer` (and so `http_auth.sign`) runs `isinstance(obj, KeyedWallet)` on wallet-shaped objects that are not a `bt.Wallet` or a `Keypair`. Runtime protocols check members with `hasattr` before 3.12, so this **reads `obj.coldkey`**. `taowire.crypto.HotkeySigner` passes `obj.hotkey` itself to avoid it. A real `bt.Wallet` is not affected.
- For signing arbitrary bytes (used by the kit's response signatures), the kit uses `bittensor.signing.resolve_signer(wallet, role="hotkey").sign(payload)`. For verifying, it uses `bittensor.sp_core.verify(payload, signature, ss58, crypto_type)`. Both are what `http_auth` itself uses. Wrap them in `taowire/crypto.py` so a rename only touches one file.
- Local test keys: `from bittensor.keyfiles import Keypair; Keypair.create_from_uri("//Alice")` (sr25519). For ed25519 test keys: `from bittensor.wallets import CRYPTO_ED25519; Keypair.create_from_uri("//Alice", crypto_type=CRYPTO_ED25519)`. A raw `Keypair` can be passed anywhere the SDK expects a wallet, including `http_auth.sign`.

### 3.7 Timelock

```python
sealed = bt.timelock.encrypt(b"payload", reveal_in="30s")   # also reveal_at= / reveal_round=
sealed.hex(); sealed.reveal_round; sealed.revealed; sealed.reveal_at
bt.Timelocked.parse(hex_or_bytes)
bt.timelock.decrypt(sealed, wait=False, timeout=None)        # raises TimelockNotReady if early
bt.timelock.current_round()
```

`encrypt` is local. **`decrypt` makes an HTTP call to the drand API.** A validator that decrypts many responses must cache round signatures and handle drand outages (Section 8.10).

### 3.8 Removed things the kit must not reference

`bt.Axon, bt.Dendrite, bt.Synapse, bt.StreamingSynapse, bt.SubnetsAPI, bt.Tensor, bt.AsyncSubtensor, MockSubtensor, bt.Config, bt.logging, bittensor.utils.weight_utils, top-level bt.Keypair`. Accessing these in 11.3.0 raises an `AttributeError` that names the replacement.

---

## 4. The btauth/1 protocol (normative copy)

This section restates the protocol so implementations in any language can be written from this document alone. Source: Bittensor v11 "Signed requests" guide and `bittensor/http_auth.py` (11.3.0).

### 4.1 Headers

| Header | Value | Required |
|---|---|---|
| `X-Bittensor-Version` | `1` | yes |
| `X-Bittensor-Hotkey` | sender hotkey, SS58 | yes |
| `X-Bittensor-Receiver` | receiver hotkey, SS58 | yes in TaoWire (the protocol allows omitting it; servers reject by default) |
| `X-Bittensor-Nonce` | Unix time in **nanoseconds**, decimal string | yes |
| `X-Bittensor-Crypto` | `ed25519`; omitted entirely for sr25519 | only for ed25519 |
| `X-Bittensor-Signature` | `0x` + lowercase hex of the signature | yes |

Header names are case-insensitive. Values are exact.

### 4.2 Signed payload

The UTF-8 bytes of exactly eight lines joined by `\n`, with **no trailing newline**:

```
btauth/1
<scheme: "sr25519" or "ed25519">
<HTTP method, uppercase>
<request target: path plus ?query, exactly as sent, percent-encoded form>
<sha256 of the raw body bytes, lowercase hex>
<nonce, decimal>
<sender hotkey ss58>
<receiver hotkey ss58, or "-" if unbound>
```

Rules:

- The request target is the **percent-encoded wire form** on both sides (`/a%20b?q=1`, never `/a b`).
- The body hash is over the **raw bytes received**, before any parsing. An empty body hashes to `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- sr25519 signatures use the substrate signing context `b"substrate"` (schnorrkel). ed25519 is plain RFC 8032.
- Sign the exact payload bytes. Never sign a wrapped form (`<Bytes>…</Bytes>`).

### 4.3 Verification order (normative)

1. **Shape.** All required headers present and parseable; version is `1`; scheme (if present) is known. Signature is hex (an optional `0x` prefix is stripped). Else `MalformedAuth`.
   TaoWire verifiers are **stricter than the SDK** here, in every language, and reject with `tw.auth_malformed`: a sender address that is not SS58 prefix 42 (fact A11); any duplicated `X-Bittensor-*` header; a nonce that is not `[0-9]{1,20}`; an `X-Bittensor-Crypto` value other than exactly `ed25519` or `sr25519`; a sender value that is not exactly **48 characters** (every prefix-42 SS58 address of a 32-byte key has 48), checked **before** any base58 decoding, because base58 decoding is quadratic in the input length and runs before authentication (decision D19); a signature that is not hex digits only (no whitespace or other characters, which some hex decoders skip). Each has a vector in `negative.json`.
2. **Receiver.** `X-Bittensor-Receiver` must equal the server's hotkey. Missing receiver is rejected unless explicitly allowed. Else `WrongReceiver`.
3. **Freshness.** `now - nonce <= max_age` (default 10 s) and `nonce - now <= allowed_skew` (default 2 s). Else `StaleRequest`.
4. **Signature.** Rebuild the payload from the *received* method, target and body (always recompute the body hash). Decode the sender's SS58. Verify under the declared scheme **only**; never try both. Address or signature that cannot be decoded → `MalformedAuth`. Invalid signature → `BadSignature`. TaoWire verifiers also refuse **weak public keys** whose "universal" signature verifies for any payload (the sr25519 identity point, ed25519 small-order points) with `BadSignature`, even where the SDK accepts them (decision D20, ADR-0010).
5. **Replay.** The `(hotkey, nonce)` pair must not have been accepted before within the window. Consult the store only after step 4 succeeds. Else `ReplayedRequest`.

Clients sign a fresh nonce for every attempt, including retries of an identical body.

### 4.4 Reserved

`X-Bittensor-Drand-Round` and `X-Bittensor-Drand-Randomness` are reserved for a future extension. Do not use them.

### 4.5 Golden vectors

See Appendix C. The ed25519 vector has a fixed expected signature. sr25519 signatures are randomized, so the sr25519 vector is checked by sign-then-verify and cross-verify.

---

## 5. Architecture

### 5.1 Layers

```
┌──────────────────────────────────────────────────────────────────────┐
│ L3  Subnet code (user)                                               │
│     task handlers (miner) · challenge generation + scoring (validator)│
├──────────────────────────────────────────────────────────────────────┤
│ L2  TaoWire                                                        │
│  ┌──────────────┐ ┌──────────────────┐ ┌───────────────────────────┐ │
│  │ Miner server │ │ Validator client │ │ Validator loop + scoring  │ │
│  └──────┬───────┘ └────────┬─────────┘ └─────────────┬─────────────┘ │
│  ┌──────┴──────────────────┴─────────────────────────┴─────────────┐ │
│  │ Security: btauth wrapper · nonce stores · caller policy ·        │ │
│  │ size limits · rate limits · clock guard · response signing       │ │
│  └──────────────────────────────┬──────────────────────────────────┘ │
│  ┌──────────────────────────────┴──────────────────────────────────┐ │
│  │ Chain gateway (ONLY module importing bittensor for chain ops)    │ │
│  │ metagraph cache · serve axon · set weights · reads               │ │
│  └──────────────────────────────┬──────────────────────────────────┘ │
├─────────────────────────────────┼────────────────────────────────────┤
│ L1  bittensor>=11.3,<12         │  http_auth · Wallet · Subtensor ·   │
│                                 │  intents · metagraph · timelock     │
└─────────────────────────────────┴────────────────────────────────────┘
        TS / Go / Rust miners use their own btauth library for L2
        security, and the Python sidecar for chain access.
```

### 5.2 Components

| Component | Responsibility | Depends on |
|---|---|---|
| `chain.gateway` | All chain reads/writes through v11; retries; error mapping | `bittensor` |
| `chain.metagraph_cache` | Background refresh, staleness tracking, fail-closed | gateway |
| `auth.signer` | Monotonic nonces, btauth signing | `bittensor.http_auth` |
| `auth.verifier` | Thread-offloaded `verify`, error mapping | `bittensor.http_auth` |
| `auth.nonce_store` | Memory and Redis stores | `redis` (optional) |
| `policy.caller` | Who may call: registered / validator permit / min stake / allow & deny lists | metagraph cache |
| `limits` | Body size cap (ASGI), per-IP and per-hotkey token buckets | `redis` (optional) |
| `miner.app` | FastAPI app factory, route registry, lifecycle, health | all above |
| `validator.client` | Fan-out queries, timeouts, retries with fresh signatures, response verification | `httpx`, signer |
| `validator.loop` | Query → score → persist → set weights schedule | client, gateway, store |
| `validator.scores` | Score persistence (SQLite) and EMA | stdlib `sqlite3` |
| `extensions.response_sig` | `twresp/1` response signing and verification | `crypto` |
| `extensions.streaming` | SSE streaming with signed trailer | `response_sig` |
| `extensions.timelock` | Sealed challenges/responses, drand cache | `bittensor.timelock` |
| `extensions.legacy_v10` | Two-way v10 wire format: verify v10 Dendrite requests and answer in v10 shape (miner); send v10-format requests to v10 Axons (validator). Time-boxed. `wire` depends only on `crypto`; `server` and `client` plug into the miner and validator client through the interfaces in `miner.legacy` and `validator.client` | `crypto` |
| `compat` | v10-shaped API (`Synapse`, `Axon`, `Dendrite`, `AxonInfo`, `Metagraph`, `weights`, `TemplateValidatorAdapter`) over the kit | miner, validator client, `legacy_v10.wire` (one body-hash implementation) |
| `migrate` | Repo scanner and codemods for v10 → v11 | `libcst` (optional extra) |
| `observability` | structlog JSON logs, Prometheus metrics, request IDs | `structlog`, `prometheus_client` |
| `sidecar` | Localhost HTTP API: metagraph snapshot, serve-axon, health | gateway |
| `testing` | `FakeChain`, signed test client, fixtures, time control | — |
| `cli` | `taowire init / doctor / sidecar / conformance / bench` | `typer` |

### 5.3 Request lifecycle: miner side

```
TCP accept (uvicorn)
 │
 ├─[1] Pre-auth per-IP rate limit ............... 429 tw.rate_limited
 ├─[2] Content-Length > limit? ................... 413 tw.payload_too_large
 ├─[3] Stream body with running byte cap ......... 413 tw.payload_too_large
 ├─[4] Route exists? ............................. 404
 ├─[5] Metagraph usable? (stage from 8.5.1; strict mode past max age) 503 tw.metagraph_stale
 ├─[6] btauth verify in worker thread
 │      shape / receiver / freshness / signature / replay(Redis) ..... 401 tw.auth_*
 ├─[7] Caller policy (registered, permit, stake, lists); past max age:
 │      known callers only ......... 403 tw.forbidden_* / 503 tw.metagraph_stale
 ├─[8] Per-hotkey rate limit ..................... 429 tw.rate_limited
 ├─[9] Parse body into the route's request model . 422 tw.invalid_request
 ├─[10] Handler with timeout ..................... 504 tw.handler_timeout / 500 tw.handler_error
 └─[11] Serialize, sign response (twresp/1), send
```

Order rationale: cheap rejects first. Signature verification (~CPU) happens only after size and IP limits. Replay storage happens only after the signature verifies (fact A4). Policy runs after authentication because it needs the verified hotkey.

### 5.4 Request lifecycle: validator side

```
select miners from metagraph (axon != None, policy filters, sampling)
 │
 ├─ serialize body ONCE → bytes
 ├─ for each miner (bounded concurrency):
 │     attempt = 1..max_attempts:
 │       nonce = monotonic_nonce()
 │       headers = sign(method, raw_target, body, receiver=miner.hotkey, nonce)
 │       POST http(s)://miner.axon/route  (per-attempt timeout)
 │       retry only on: connect error, 502/503/504, timeout (if idempotent)
 │     verify twresp/1 signature if required → else mark invalid
 └─ return {uid: MinerResult(status, latency_ms, body|error)}
```

### 5.5 Deployment topology (reference)

```
          ┌──────────── Validator host ────────────┐
          │ validator process (loop + client)      │
          │ SQLite score DB · Redis (optional)     │
          │ own subtensor lite node (recommended)  │
          └──────────────┬─────────────────────────┘
                         │ HTTPS/HTTP + btauth/1
   ┌─────────────────────┴───────────────────────────────┐
   │ Miner host                                          │
   │ reverse proxy (optional TLS)  →  N uvicorn workers  │
   │ Redis (REQUIRED when N > 1)  ·  firewall            │
   │ non-Python miner: app + taowire-sidecar (local)  │
   └─────────────────────────────────────────────────────┘
```

### 5.6 Threat model summary

Attackers and what they can do:

| Actor | Capability | Main defences |
|---|---|---|
| Internet scanner / DDoS | Send arbitrary bytes to the miner's public IP (it is on chain) | IP rate limit, size caps, timeouts, firewall guidance |
| Registered non-validator hotkey | Send validly signed requests | Caller policy (permit + stake) |
| Malicious miner | Forward a validator's request to another miner; replay requests; return forged or copied answers | Receiver binding, replay store, response signing, timelock option |
| Network attacker (on path) | Read or modify plain HTTP traffic | Request signature (integrity of requests), response signature (integrity of responses), optional TLS |
| Malicious validator | Leak a miner's answer to another miner before scoring | Timelocked responses |
| Supply-chain attacker | Poison a kit release or dependency | Pinned deps, hashes, signed releases (Section 18) |
| Local attacker on miner host | Read the hotkey file | Out of scope for code; documented hardening (Section 16.4) |

---

## 6. Repository skeleton

One monorepo. No `.github/` directory in this version.

```
taowire/
├── README.md                          # 60-second pitch, quickstart, links
├── LICENSE                            # Apache-2.0
├── SECURITY.md                        # disclosure policy, supported versions
├── CHANGELOG.md                       # Keep a Changelog format
├── CONTRIBUTING.md                    # dev setup, coding rules, how to run checks
├── justfile                           # every check as one command (no CI yet)
├── .editorconfig
├── .gitignore                         # must ignore wallets/, *.db, .env
├── .env.example                       # all TW_* variables with safe defaults
│
├── docs/
│   ├── quickstart.md
│   ├── concepts.md                    # layers, lifecycle, security model
│   ├── miner-guide.md
│   ├── validator-guide.md
│   ├── security.md                    # traps and defaults (from Section 16)
│   ├── multi-language.md
│   ├── sidecar-api.md                 # OpenAPI-backed reference
│   ├── migration-from-v10.md          # Section 10b as a guide: compat layer, migrate CLI
│   ├── migration-rollout.md           # Section 10b.5: staged rollout runbook for subnet owners
│   ├── migrations/                    # case studies: template + design-partner subnets (S6, S7)
│   ├── testnet-e2e.md                 # Section 15 as a runbook
│   ├── protocol/
│   │   ├── btauth-1.md                # copy of Section 4
│   │   └── twresp-1.md                # Section 9 extensions
│   └── adr/                           # one file per decision in Section 7
│       ├── 0001-v11-only-chain-access.md
│       ├── 0002-fastapi-httpx.md
│       ├── 0003-sidecar-for-non-python.md
│       ├── 0004-response-signing.md
│       ├── 0005-sqlite-scores.md
│       ├── 0007-compat-layer.md
│       ├── 0008-v10-wire-without-v10-sdk.md
│       └── 0009-core-team-boundaries.md
│
├── python/
│   ├── pyproject.toml
│   ├── uv.lock                        # committed
│   ├── src/taowire/
│   │   ├── __init__.py                # public API re-exports, __version__
│   │   ├── py.typed
│   │   ├── version.py
│   │   ├── config.py                  # pydantic-settings models
│   │   ├── errors.py                  # TWError hierarchy + error codes
│   │   ├── crypto.py                  # thin wrapper over bittensor signing/sp_core
│   │   ├── chain/
│   │   │   ├── __init__.py
│   │   │   ├── gateway.py             # THE v11 boundary (Protocol + real impl)
│   │   │   ├── metagraph_cache.py
│   │   │   └── axon.py                # axon string parsing, URL building
│   │   ├── auth/
│   │   │   ├── __init__.py
│   │   │   ├── signer.py              # monotonic nonce signer
│   │   │   ├── verifier.py            # thread-offloaded verify + mapping
│   │   │   ├── nonce_store.py         # MemoryNonceStore, RedisNonceStore
│   │   │   └── clock.py               # NTP offset check
│   │   ├── policy/
│   │   │   ├── __init__.py
│   │   │   └── caller.py
│   │   ├── limits/
│   │   │   ├── __init__.py
│   │   │   ├── body.py                # ASGI body-size middleware
│   │   │   └── ratelimit.py           # token buckets (memory, redis)
│   │   ├── miner/
│   │   │   ├── __init__.py
│   │   │   ├── app.py                 # Miner class + FastAPI factory
│   │   │   ├── routes.py              # route registry, handler contract
│   │   │   ├── lifecycle.py           # startup/shutdown, axon publish
│   │   │   └── health.py
│   │   ├── validator/
│   │   │   ├── __init__.py
│   │   │   ├── client.py              # fan-out client
│   │   │   ├── selection.py           # miner selection & sampling
│   │   │   ├── loop.py                # epoch loop
│   │   │   ├── scores.py              # SQLite score store + EMA
│   │   │   └── weights.py             # set-weights scheduling
│   │   ├── extensions/
│   │   │   ├── __init__.py
│   │   │   ├── response_sig.py        # twresp/1
│   │   │   ├── streaming.py           # SSE + signed trailer
│   │   │   ├── timelock.py            # sealed challenges/responses
│   │   │   └── legacy_v10/            # two-way bridge (Section 8.11)
│   │   │       ├── __init__.py
│   │   │       ├── wire.py            # v10 headers, body hash, signed message
│   │   │       ├── server.py          # v10 Dendrite → TaoWire miner
│   │   │       └── client.py          # TaoWire validator → v10 Axon
│   │   ├── compat/                    # v10-shaped API (Section 10b.2)
│   │   │   ├── __init__.py            # Synapse, StreamingSynapse, TerminalInfo, AxonInfo, Axon, Dendrite
│   │   │   ├── synapse.py
│   │   │   ├── axon.py
│   │   │   ├── dendrite.py
│   │   │   └── weights.py
│   │   ├── migrate/                   # `taowire migrate` (Section 10b.4)
│   │   │   ├── __init__.py
│   │   │   ├── rules.py               # removed-symbol table → replacement + doc link
│   │   │   ├── scan.py                # static scan, report (text/JSON/Markdown)
│   │   │   └── codemods.py            # libcst rewrites for `migrate apply`
│   │   ├── observability/
│   │   │   ├── __init__.py
│   │   │   ├── logging.py
│   │   │   └── metrics.py
│   │   ├── sidecar/
│   │   │   ├── __init__.py
│   │   │   ├── app.py                 # localhost API
│   │   │   └── models.py
│   │   ├── testing/
│   │   │   ├── __init__.py
│   │   │   ├── fake_chain.py
│   │   │   ├── keys.py                # deterministic test keypairs
│   │   │   ├── clock.py               # frozen/advancing time
│   │   │   └── pytest_plugin.py       # fixtures exposed via entry point
│   │   └── cli/
│   │       ├── __init__.py
│   │       ├── main.py                # `taowire` command
│   │       ├── init_cmd.py            # scaffold a new subnet
│   │       ├── doctor.py
│   │       ├── sidecar_cmd.py
│   │       ├── conformance_cmd.py
│   │       ├── migrate_cmd.py
│   │       └── bench_cmd.py
│   └── tests/
│       ├── unit/                      # one file per module
│       ├── property/                  # hypothesis: header parsing, payloads
│       ├── integration/               # in-process ASGI miner + client + FakeChain
│       ├── migration/                 # compat layer, scanner, codemods, legacy wire vectors
│       ├── localnet/                  # @pytest.mark.localnet (Docker chain), incl. mixed v10/v11 fleet
│       └── testnet/                   # @pytest.mark.testnet (manual, costs test TAO)
│
├── typescript/
│   ├── package.json                   # npm workspaces
│   ├── tsconfig.base.json
│   └── packages/
│       ├── btauth/                    # @taowire/btauth
│       │   ├── package.json
│       │   ├── src/{index,payload,sign,verify,ss58,nonce,errors}.ts
│       │   ├── src/stores/{memory,redis}.ts
│       │   ├── src/fastify.ts         # plugin (raw body, raw url)
│       │   ├── src/client.ts          # fetch wrapper with fresh nonces
│       │   └── test/
│       └── miner-example/             # text-ops miner in TS
│
├── go/
│   ├── go.mod                         # module github.com/<org>/taowire/go
│   ├── btauth/{payload,sign,verify,ss58,nonce,errors,middleware,client}.go
│   ├── btauth/stores/{memory,redis}.go
│   ├── btauth/*_test.go
│   └── examples/miner/main.go
│
├── rust/
│   ├── Cargo.toml                     # workspace
│   ├── taowire-btauth/
│   │   ├── Cargo.toml
│   │   └── src/{lib,payload,sign,verify,ss58,nonce,error,axum,client}.rs
│   │   └── tests/
│   └── examples/miner/src/main.rs
│
├── conformance/
│   ├── vectors/
│   │   ├── payload.json               # payload construction cases
│   │   ├── ed25519.json               # deterministic sign vectors
│   │   ├── sr25519_verify.json        # pre-signed, verify-only
│   │   ├── negative.json              # must-reject cases with expected error
│   │   ├── twresp.json                # response-signing vectors
│   │   └── legacy_v10.json            # captured from a real v10.5.0 Dendrite/Axon (Section 10b.6)
│   ├── generate.py                    # regenerates vectors from Python reference
│   ├── interop/                       # live cross-language matrix scripts
│   │   ├── run_matrix.py
│   │   └── README.md
│   └── README.md
│
├── examples/
│   ├── migrations/
│   │   └── template-v10-to-v11/       # the archived template, before and after (diff kept small)
│   │       ├── before/                # pinned copy of the v10 template (licence permitting)
│   │       ├── after/                 # same code on taowire.compat
│   │       └── mixed-fleet.yml        # v10 + v11 miners and validators on localnet
│   └── text-ops-subnet/
│       ├── README.md
│       ├── pyproject.toml
│       ├── text_ops/{protocol,miner,validator,scoring}.py
│       ├── miners/{typescript,go,rust}/ -> links to language examples
│       └── docker-compose.yml         # local: chain + redis + miners + validator
│
├── deploy/
│   ├── docker/
│   │   ├── miner.Dockerfile
│   │   ├── validator.Dockerfile
│   │   └── sidecar.Dockerfile
│   ├── compose/
│   │   ├── localnet.yml               # subtensor-localnet + redis
│   │   └── testnet-node.yml           # optional own testnet lite node
│   └── systemd/
│       ├── taowire-miner.service
│       └── taowire-validator.service
│
└── scripts/
    ├── localnet_up.sh                 # start chain, create wallets, fund, register
    ├── localnet_down.sh
    ├── testnet_preflight.sh           # checks balances, costs, chain health
    ├── legacy_venv.sh                 # separate venv with bittensor==10.5.0 for vectors and mixed-fleet tests
    ├── capture_v10_vectors.py         # runs a real v10 Dendrite/Axon, records wire bytes
    └── gen_conformance.sh
```

### 6.1 `justfile` targets (manual quality gates)

```make
default: check

check: lint typecheck test conformance        # the full local gate

lint:
    cd python && uv run ruff check . && uv run ruff format --check .
    cd typescript && npm run lint
    cd go && go vet ./... && staticcheck ./...
    cd rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings

typecheck:
    cd python && uv run mypy --strict src
    cd typescript && npm run typecheck

test:
    cd python && uv run pytest tests/unit tests/property tests/integration
    cd typescript && npm test
    cd go && go test -race ./...
    cd rust && cargo test

conformance:
    cd python && uv run taowire conformance --vectors ../conformance/vectors
    cd typescript && npm run conformance
    cd go && go test ./btauth -run Conformance
    cd rust && cargo test --test conformance

localnet-up:
    ./scripts/localnet_up.sh
localnet-test:
    cd python && uv run pytest -m localnet tests/localnet
interop:
    cd conformance/interop && uv run python run_matrix.py --network local
migration-test:
    cd python && uv run pytest tests/migration
mixed-fleet:
    ./scripts/legacy_venv.sh && cd python && uv run pytest -m "localnet and mixed_fleet" tests/localnet
bench:
    cd python && uv run taowire bench --duration 60
audit:
    cd python && uv run pip-audit
    cd typescript && npm audit --audit-level=high
    cd go && govulncheck ./...
    cd rust && cargo audit
```

---

## 7. Design decisions

Each decision gets a short ADR file in `docs/adr/`. Summary:

**ADR-0001: The v11 SDK is the only chain client in Python, behind one gateway.**
*Why:* v11 generates its chain layer from runtime metadata, so it cannot drift from the chain; copying it would. One gateway file limits the impact of frequent v11 releases.
*Consequence:* `import bittensor` for chain operations appears only in `chain/gateway.py`. `auth/*` and `crypto.py` import `bittensor.http_auth`, `bittensor.signing` and `bittensor.sp_core`. A lint rule (ruff `banned-api` / import-linter contract) enforces this.

**ADR-0002: FastAPI + uvicorn for the miner, httpx for the validator.**
*Why:* They are what the v11 docs' recipes use, they are well known, and both expose the raw request target and raw body needed by btauth.
*Consequence:* The kit does not hide FastAPI. Users can add normal FastAPI routes, dependencies and middleware.

**ADR-0003: Non-Python miners use a local Python sidecar for chain access.**
*Why:* Re-implementing metagraph decoding and extrinsic submission in three more languages is a large, fast-breaking surface (runtime upgrades arrive every few weeks). The sidecar reuses v11 and exposes a small, stable, versioned local API.
*Consequence:* TS/Go/Rust packages contain btauth + server/client adapters only. They read the caller policy data from the sidecar. The sidecar binds to `127.0.0.1` only.

**ADR-0004: Responses are signed with a kit extension, `twresp/1`.**
*Why:* btauth/1 authenticates requests only. Validators that score miners need to know the response really came from that miner, unmodified, for that request.
*Consequence:* A separate, versioned header set (`X-TW-Resp-*`). It does not reuse reserved `X-Bittensor-*` names. It is on by default in TaoWire and ignored by non-TaoWire clients.
*Upstream:* A TaoWire-only protocol risks splitting the ecosystem. In Phase 1 the spec in Section 9.1 is proposed to the core team as an official btauth response extension (Section 1.7). If they accept it (possibly with changes), the kit switches to the official headers in the next minor release and keeps accepting `X-TW-Resp-*` for at least one more minor release. If they decline, `twresp/1` stays, documented as a TaoWire extension, and the reason is recorded here.

**ADR-0005: SQLite for validator score state.**
*Why:* Validators must survive restarts without losing score history, and SQLite is zero-ops, transactional and in the standard library.
*Consequence:* One writer process per validator. Redis is not required for validators.

**ADR-0006: JSON request/response bodies by default.**
*Why:* Language-neutral and easy to debug. Signatures cover raw bytes, so any format works later (msgpack, protobuf) without protocol changes.
*Consequence:* Route models are Pydantic v2 models in Python and plain schemas in other languages.

**ADR-0007: A v10-shaped compat layer is part of the kit, not a separate package.**
*Why:* Most existing subnets are template forks. If `Synapse`, `axon.attach(...)` and `dendrite(axons, synapse)` keep their shape, migration becomes an import change instead of a rewrite. Keeping it in the main package means it gets the same security defaults and the same release cycle.
*Consequence:* `taowire.compat` is a thin layer over `Miner` and `ValidatorClient`; it adds no security logic of its own. It is supported for the 1.x line. New projects are pointed at the native API; `compat` is documented as "for migrating code".

**ADR-0008: The v10 wire format is re-implemented; the kit never depends on bittensor v10.**
*Why:* `bittensor==10.x` and `bittensor==11.x` cannot be installed together, and the v10 SDK gets no more releases. The legacy wire format is small (headers, a sha3-256 body hash, one sr25519 signature over a dotted string), so the kit implements it in `extensions/legacy_v10/wire.py` using `crypto.py`.
*Consequence:* Correctness is proven only by vectors captured from a real `bittensor==10.5.0` Dendrite and Axon in a separate virtualenv (`scripts/legacy_venv.sh`, `scripts/capture_v10_vectors.py`), and by the mixed-fleet localnet test.

---

## 8. Python core: component specifications

### 8.1 Dependencies (`python/pyproject.toml`)

```toml
[project]
name = "taowire"
requires-python = ">=3.10,<3.15"
dependencies = [
  "bittensor>=11.3.0,<12",    # range, not a pin: users must be able to take SDK fixes (Section 3, 18.3)
  "fastapi>=0.115,<1",
  "uvicorn[standard]>=0.30,<1",
  "httpx>=0.27,<1",
  "pydantic>=2.7,<3",
  "pydantic-settings>=2.3,<3",
  "anyio>=4.4,<5",
  "structlog>=24.1",
  "prometheus-client>=0.20",
  "typer>=0.12",
]
[project.optional-dependencies]
redis = ["redis>=5.0,<6"]
ntp = ["ntplib>=0.4"]
migrate = ["libcst>=1.4"]               # `taowire migrate` codemods
all = ["taowire[redis,ntp,migrate]"]
dev = ["pytest>=8", "pytest-asyncio>=0.23", "hypothesis>=6.100", "respx>=0.21",
       "mypy>=1.10", "ruff>=0.5", "pip-audit>=2.7", "import-linter>=2.0"]

[project.scripts]
taowire = "taowire.cli.main:app"

[project.entry-points.pytest11]
taowire = "taowire.testing.pytest_plugin"
```

Use `uv` for locking. Commit `uv.lock`. Version ranges above are what users get; the lock file pins exact versions for the kit's own development and tests, and those versions are recorded in the compatibility matrix (Section 18.2). Never narrow a published range to an exact `==` pin; if an SDK release breaks the kit, exclude that release (`!=11.4.0`) and ship a fix.

### 8.2 Errors (`errors.py`)

```python
class TWError(Exception):
    code: str = "tw.internal"
    http_status: int = 500
    public_message: str = "internal error"    # safe to send to callers

class AuthFailed(TWError):          http_status = 401   # subcodes from AuthError type
class Forbidden(TWError):           http_status = 403
class PayloadTooLarge(TWError):     http_status = 413; code = "tw.payload_too_large"
class RateLimited(TWError):         http_status = 429; code = "tw.rate_limited"
class MetagraphStale(TWError):      http_status = 503; code = "tw.metagraph_stale"
class HandlerTimeout(TWError):      http_status = 504; code = "tw.handler_timeout"
class ChainError(TWError):          # wraps bt ExtrinsicResult failures; never sent to peers
    def __init__(self, error_code: str, remediation: str): ...
```

Error response body (all languages, all kit endpoints):

```json
{"error": {"code": "tw.auth_stale", "message": "nonce is older than the 10s freshness window", "request_id": "01J..."}}
```

Full mapping in Appendix A. Never include stack traces, signatures, payloads or internal paths.

### 8.3 Chain gateway (`chain/gateway.py`)

The only module that performs chain operations.

```python
class ChainGateway(Protocol):
    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def block(self) -> int: ...
    async def metagraph(self, netuid: int) -> MetagraphView: ...
    async def uid_for_hotkey(self, netuid: int, hotkey: str) -> int | None: ...
    async def weights_rate_limit(self, netuid: int) -> int: ...
    async def blocks_since_last_update(self, netuid: int, uid: int) -> int | None: ...
    async def serve_axon(self, netuid: int, ip: str, port: int, *, tls_cert_hex: str | None,
                         protocol_tag: int) -> TxOutcome: ...
    async def set_weights(self, netuid: int, weights: dict[int, float], *,
                          mechid: int, version_key: int) -> TxOutcome: ...

@dataclass(frozen=True)
class NeuronView:            # kit-owned copy; decouples users from bt types
    uid: int
    hotkey: str
    coldkey: str
    validator_permit: bool
    active: bool
    total_stake_tao: float   # converted at fetch time, for policy thresholds
    alpha_stake: float
    tao_stake: float
    axon: Endpoint | None    # parsed (Section 8.7.2)
    last_update: int
    incentive: float
    dividends: float

@dataclass(frozen=True)
class MetagraphView:
    netuid: int
    block: int
    fetched_at_monotonic: float
    neurons: tuple[NeuronView, ...]
    def by_hotkey(self, hotkey: str) -> NeuronView | None: ...
    def validators(self) -> tuple[NeuronView, ...]: ...

@dataclass(frozen=True)
class TxOutcome:
    ok: bool
    code: str | None          # bt.ErrorCode value
    remediation: str | None
    block_hash: str | None
```

Implementation notes (`BittensorGateway`):

- Hold one `bt.Subtensor(network, fallback_endpoints=...)` client opened with `await bt.Subtensor(...)` and closed on shutdown.
- `metagraph()` calls `client.subnets.metagraph(netuid, commitments=False)`. If it returns `None`, raise `SubnetNotFound`.
- **Stake conversion (decision D2, ADR-0001).** On 11.3.0, `total_stake` is the chain's stake weight in alpha (`.tao` raises `UnitMismatchError`), so it is never used directly. `total_stake_tao = alpha_stake × metagraph.price + tao_stake`: the TAO value at the current spot price, **approximate** (no slippage; a large swap can move the spot price briefly). If `price` is `None` (empty pool), the alpha part counts as 0, so a minimum-stake check fails closed. It is for coarse policy thresholds only.
- **Retries.** Reads: exponential backoff (0.5 s → 8 s, 5 attempts, jitter) on connection errors. Writes: never auto-retry blindly. Each attempt first runs the SDK preflight (`client.plan`); a preflight refusal (for example `rate_limited`) is returned with its own code and nothing is submitted, and the caller schedules. If the pool rejects a submission for fork or era reasons ("signature does not match the extrinsic payload", era expired), build and sign a **new** extrinsic against a fresh block, up to 3 attempts. After a submission has been accepted, a timeout or lost connection returns `unknown` and is never resent.
- **Meaning of `set_weights` success.** On subnets with commit-reveal (the default), `TxOutcome.ok` means the timelocked **commit was included**, not that the weights were applied. The chain accepts a commit even from a hotkey without a permit (verified on localnet); whether the weights count is only known after the reveal.
- Wrap every call with a timeout (`TW_CHAIN_TIMEOUT_S`, default 30 s).
- Log every write with intent summary, block hash and outcome code.

`FakeChain` (Section 8.13) implements the same Protocol for tests.

### 8.4 Auth

#### 8.4.1 Signer (`auth/signer.py`)

```python
class MonotonicNonce:
    """Strictly increasing nanosecond nonces per process.

    btauth replay protection keys on (hotkey, nonce). time.time_ns() can repeat
    on coarse clocks, so take max(now, last + 1).
    """
    def __init__(self) -> None:
        self._last = 0
        self._lock = threading.Lock()
    def next(self) -> int:
        with self._lock:
            n = max(time.time_ns(), self._last + 1)
            self._last = n
            return n

class RequestSigner:
    def __init__(self, wallet: bt.Wallet) -> None:
        self._wallet = wallet
        self._nonce = MonotonicNonce()
        self.hotkey_ss58 = wallet.hotkey.ss58_address    # fail fast if missing
    def sign(self, *, method: str, target: str, body: bytes, receiver_ss58: str) -> dict[str, str]:
        if not receiver_ss58:
            raise ValueError("receiver is required")          # never send unbound requests
        return bt.http_auth.sign(self._wallet, method=method, path=target, body=body,
                                 receiver_ss58=receiver_ss58, nonce_ns=self._nonce.next())
```

Multi-process validators: nonce collisions across processes are impossible only if each process uses a different hotkey, or the nonce clock is shared. **Rule:** one validator hotkey = one signing process. `taowire doctor` warns if it detects two processes with the same hotkey via a lock file (`~/.taowire/locks/<hotkey>.lock`).

#### 8.4.2 Verifier (`auth/verifier.py`)

```python
_AUTH_CODES = {
    bt.http_auth.MalformedAuth: "tw.auth_malformed",
    bt.http_auth.WrongReceiver: "tw.auth_wrong_receiver",
    bt.http_auth.StaleRequest: "tw.auth_stale",
    bt.http_auth.ReplayedRequest: "tw.auth_replayed",
    bt.http_auth.BadSignature: "tw.auth_bad_signature",
}

class RequestVerifier:
    def __init__(self, self_hotkey: str, store: NonceStore, *,
                 max_age: float = 10.0, allowed_skew: float = 2.0,
                 limiter: anyio.CapacityLimiter | None = None) -> None:
        if getattr(store, "retention", 0) < max_age + allowed_skew:
            raise ValueError("nonce store retention too short")     # fact A3, fail at startup
        ...
    async def verify(self, headers: Mapping[str, str], body: bytes, *,
                     method: str, target: str) -> bt.http_auth.Caller:
        try:
            return await anyio.to_thread.run_sync(
                functools.partial(bt.http_auth.verify, dict(headers), body,
                                  method=method, path=target,
                                  self_hotkey_ss58=self._self, max_age=self._max_age,
                                  allowed_skew=self._skew, require_receiver=True,
                                  nonce_store=self._store),
                limiter=self._limiter)
        except bt.http_auth.AuthError as e:
            raise AuthFailed(code=_AUTH_CODES.get(type(e), "tw.auth_failed"),
                             public_message=str(e)) from None
```

- The limiter (default 64 threads) bounds CPU use under flood.
- `require_receiver` is always `True`. There is no setting to change it in the miner.
- `max_age` range allowed by config: 2–60 s. `allowed_skew`: 0.5–10 s.

#### 8.4.3 Nonce stores (`auth/nonce_store.py`)

```python
class MemoryNonceStore:
    """Single-process only. Wraps bt InMemoryNonceStore semantics."""
    def __init__(self, retention: float = 60.0) -> None: ...
    retention: float
    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool: ...

class RedisNonceStore:
    """Shared across processes and hosts. SYNC client (verify is sync, fact A1)."""
    def __init__(self, url: str, *, retention: float = 60.0, prefix: str = "tw:n:") -> None:
        self._r = redis.Redis.from_url(url, socket_timeout=0.25, socket_connect_timeout=0.5)
        self.retention = retention
        self._px = int(retention * 1000)
    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        key = f"{self._prefix}{hotkey_ss58}:{nonce_ns}"
        return bool(self._r.set(key, b"1", nx=True, px=self._px))
```

**Expiry and wall-clock steps (decision D21).** Freshness (4.3 step 3) uses the wall clock, so a backwards wall-clock step on the miner could make a forgotten nonce look fresh again.
- `MemoryNonceStore` forgets a pair only when `retention` has passed on the monotonic clock **and** the nonce is older than `retention` on the wall clock.
- `RedisNonceStore` keeps `SET NX PX retention`. Every store refuses to start when `retention < 2 × (max_age + allowed_skew)`, which gives a margin of `retention − (max_age + allowed_skew)` (48 s with the defaults).
- The clock guard (8.4.4) watches `wall − monotonic`. If it drops by more than that margin (a backwards step), authenticated requests get **503 `tw.replay_store_unavailable`** and `/readyz` returns 503 with reason `clock_step` for `retention` seconds, then normal service resumes. This fails closed instead of reopening nonces.
- The same rules apply to the Go and Rust stores.

Failure policy: if Redis is unreachable, `check_and_store` raises. The verifier maps that to **503 `tw.replay_store_unavailable`** (fail-closed). Never fall back to the memory store silently when more than one worker runs.

Startup check in `miner.lifecycle`: if `workers > 1` (uvicorn) or `TW_INSTANCE_COUNT > 1` and the store is `MemoryNonceStore`, **refuse to start** with a clear message, unless `TW_UNSAFE_ALLOW_MEMORY_NONCE_MULTIWORKER=1`.

#### 8.4.4 Clock guard (`auth/clock.py`)

- At startup and every 10 minutes: query NTP (`TW_NTP_SERVERS`, default `pool.ntp.org,time.cloudflare.com`) with `ntplib` if installed.
- `|offset| > 0.5 s`: log a warning and set metric `tw_clock_offset_seconds`.
- `|offset| > allowed_skew`: log an error. The miner keeps running, because refusing would only make things worse, but `/readyz` returns 503 with reason `clock_skew`.
- If NTP is unreachable, record "unknown"; do not fail.
- **Clock steps:** a check driven by requests and the 10-minute timer compares `time.time() − time.monotonic()` with its last value. A backwards step larger than the nonce store's margin triggers the fail-closed window in 8.4.3 (D21), logs `clock_step_detected` at ERROR (size of the step), and sets `tw_clock_step_seconds`.

### 8.5 Caller policy (`policy/caller.py`)

```python
@dataclass(frozen=True)
class CallerPolicy:
    require_registered: bool = True
    require_validator_permit: bool = True
    min_stake_tao: float = 0.0              # 0 disables; mainnet suggestion ≥ 1000
    allow_hotkeys: frozenset[str] = frozenset()    # always allowed (e.g. owner tooling)
    deny_hotkeys: frozenset[str] = frozenset()     # always denied (checked first)

    def check(self, caller_hotkey: str, mg: MetagraphView) -> None:
        if caller_hotkey in self.deny_hotkeys: raise Forbidden("tw.forbidden_denied")
        if caller_hotkey in self.allow_hotkeys: return
        n = mg.by_hotkey(caller_hotkey)
        if self.require_registered and n is None: raise Forbidden("tw.forbidden_not_registered")
        if self.require_validator_permit and (n is None or not n.validator_permit):
            raise Forbidden("tw.forbidden_not_validator")
        if self.min_stake_tao and (n is None or n.total_stake_tao < self.min_stake_tao):
            raise Forbidden("tw.forbidden_low_stake")
```

Policies can be set per route (`@miner.route(..., policy=...)`). The default for every route is the strict policy above.

#### 8.5.1 Metagraph cache (`chain/metagraph_cache.py`)

- Refresh every `TW_METAGRAPH_REFRESH_S` (default 120 s) in a background task. Use jitter of ±10%.
- On refresh failure: keep the old snapshot, increment `tw_metagraph_refresh_failures_total`, back off, and try every endpoint in `TW_CHAIN_FALLBACKS`.

**Staleness is handled in three stages, not one hard stop.** Why: a hard 503 after 15 minutes means a single outage of a shared chain endpoint makes **every** TaoWire miner stop answering at the same moment, so they all get scored as failed and lose emissions. The data it protects changes slowly (validator permits update once per epoch, about 72 minutes), and operators who get hurt by a too-strict check switch it off entirely, which is worse.

| Stage | Snapshot age | Behaviour | `/readyz` |
|---|---|---|---|
| Fresh | < `TW_METAGRAPH_SOFT_AGE_S` (default 900 s) | Normal | 200 |
| Degraded | soft age … `TW_METAGRAPH_MAX_AGE_S` (default: 2 × the subnet's tempo in seconds, 8,640 s at the default tempo of 360 blocks) | Normal caller policy against the last snapshot. Log WARNING once per 5 minutes; `tw_metagraph_degraded` = 1 | 200 with `"degraded": ["metagraph_stale"]` |
| Known callers only | > max age | Callers that passed policy **and** made a verified request while the snapshot was fresh or degraded are still served. Any other caller gets **503** `tw.metagraph_stale` | 503 with reason `metagraph_stale` |

- The "known callers" set is in memory (hotkey → last accepted time), filled only after full policy checks pass, and cleared as soon as a fresh snapshot arrives (the fresh snapshot then decides).
- Trade-off, documented in `docs/security.md`: a validator that loses its permit or is deregistered during a long chain outage keeps access until the miner can read the chain again. Unknown or newly permitted callers are never let in on stale data.
- `TW_METAGRAPH_STRICT=1` restores a full 503 for everyone past max age, for subnets that prefer it.
- Docs and `taowire doctor` recommend at least one entry in `TW_CHAIN_FALLBACKS` (or an own lite node), because a shared public endpoint is the most likely cause of this situation.
- Build a `dict[hotkey, NeuronView]` index on each refresh (O(1) lookups).
- Startup blocks until the first successful fetch or `TW_STARTUP_TIMEOUT_S` (default 120 s), then exits non-zero.

### 8.6 Limits

#### 8.6.1 Body size (`limits/body.py`)

A pure ASGI middleware, installed first:

```python
class BodySizeLimit:
    def __init__(self, app, max_bytes: int) -> None: ...
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http": return await self.app(scope, receive, send)
        cl = _content_length(scope["headers"])
        if cl is not None and cl > self.max_bytes:
            return await _send_error(send, PayloadTooLarge())
        received = 0
        async def limited_receive():
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_bytes:
                    raise PayloadTooLarge()        # caught by error middleware → 413
            return msg
        await self.app(scope, limited_receive, send)
```

Default `TW_MAX_BODY_BYTES` = 1 MiB; per-route override. Also set uvicorn `--limit-concurrency` and `--timeout-keep-alive 5`, and a header size limit (`h11_max_incomplete_event_size` = 16 KiB).

#### 8.6.2 Rate limiting (`limits/ratelimit.py`)

- Token bucket. Two layers:
  1. **Pre-auth per IP**: default 50 req/s, burst 100. Keyed by client IP. When `TW_TRUSTED_PROXIES` is set, use the right-most untrusted `X-Forwarded-For` entry; otherwise the socket peer.
  2. **Post-auth per hotkey**: default 20 req/s, burst 40, per route.
- Backends: memory (single process) or Redis (Lua script doing an atomic token-bucket update). Same fail-closed rule as the nonce store for multi-worker setups.
- **Shared limiter timeout (decision D42).** The Redis limiter call keeps its 250 ms timeout; on a timeout or Redis error the request is refused with 503 `tw.replay_store_unavailable` (fail closed), never let through.
- Responses: 429 with `Retry-After` seconds.

### 8.7 Miner (`miner/`)

#### 8.7.1 Public API

```python
from taowire import Miner, Caller, RouteContext
from pydantic import BaseModel

class TransformRequest(BaseModel):
    text: str
    op: Literal["upper", "reverse", "sha256"]

class TransformResponse(BaseModel):
    result: str

miner = Miner.from_env()          # or Miner(settings=MinerSettings(...))

@miner.route("/v1/transform", request=TransformRequest, response=TransformResponse,
             timeout_s=5.0, max_body_bytes=64_000)
async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse:
    # ctx.caller.hotkey_ss58, ctx.caller_neuron (NeuronView), ctx.request_id
    ...

if __name__ == "__main__":
    miner.run()        # uvicorn with kit defaults
```

- `miner.app` exposes the underlying FastAPI app for custom routes or ASGI servers.
- Routes are `POST` only by default. Support `GET` with an empty body if needed, but always signed.
- Handlers can be `async def` or `def` (sync handlers run in a thread pool).
- Handlers can return a response model, `bytes`, or a `StreamingReply` (Section 9.2).

#### 8.7.2 Axon parsing (`chain/axon.py`)

```python
@dataclass(frozen=True)
class Endpoint:
    host: str          # "203.0.113.7" or "2001:db8::1"
    port: int
    is_ipv6: bool
    def base_url(self, scheme: Literal["http", "https"]) -> str:
        h = f"[{self.host}]" if self.is_ipv6 else self.host
        return f"{scheme}://{h}:{self.port}"

def parse_axon(s: str | None) -> Endpoint | None: ...
#   accepts "a.b.c.d:port" and "[v6]:port"; rejects 0.0.0.0, port 0,
#   private/loopback ranges unless TW_ALLOW_PRIVATE_AXONS=1 (needed on localnet).
```

Scheme selection: the subnet declares `TW_SCHEME_POLICY` = `http` | `https` | `https-if-tls-published`. In the third mode the validator uses HTTPS for miners that published with `ServeAxonTls`, after checking the published key (Section 16.3). Until TLS support ships (Phase 4), `https-if-tls-published` is **refused at startup** with a `StartupError` naming the setting: a validator that asked for pinned TLS must never run on plain HTTP without knowing it. That refusal is lifted only in the commit that ships tested pinning and the accepted ADR-0011 (16.3, D31).

Per mode (D31): `http` — plain HTTP to every miner. `https` — HTTPS to every miner; the certificate's public key is pinned against the published `ServeAxonTls` key when one exists, otherwise normal CA verification applies; a miner reachable only over HTTP fails with `tw.connect_error`. `https-if-tls-published` — pinned HTTPS for miners with a published key, plain HTTP for miners without one. In every mode a pin mismatch is `tw.tls_pin_mismatch` and the kit **never falls back to HTTP** for a miner that published a key.

**Protocol tag.** `ServeAxon.protocol` is a subnet-defined number stored on chain (default 4). TaoWire publishes `protocol=TW_PROTOCOL_TAG` (default `87`, 0x57 "W"). The on-chain field is a **u8** (0–255; larger values fail to encode), so collisions with other subnets' values are possible; it only weakens the M1 count and the 8.11.3 hint, never security (decision D1). Validators may filter to miners advertising it. Document this; it is advisory, not security.

#### 8.7.3 Lifecycle (`miner/lifecycle.py`)

On startup, in order:

1. Load settings; validate (Section 12). **SDK check:** confirm the symbols from Section 3 that the kit uses exist in the installed `bittensor`. If any is missing, exit with a message naming the symbol and the supported versions. If the installed version is inside the range but not yet in the tested list (18.2), log a WARNING and continue.
2. Load the wallet hotkey only. Refuse to start if `TW_REFUSE_IF_COLDKEY_PRESENT=1` (default) and a readable, unencrypted coldkey file exists in the wallet directory. Warn if an encrypted coldkey file exists.
3. Connect the gateway. Fetch the metagraph (blocking, with timeout).
4. Check that our hotkey is registered on `TW_NETUID`. If not: exit with code 3 and the message "register first: btcli tx burned-register --netuid N -w <coldkey> -H <hotkey>".
5. Build the nonce store and rate limiters; run the multi-worker safety check (8.4.3).
6. Clock check (8.4.4).
7. **Axon publish:** compare our on-chain axon with `TW_EXTERNAL_IP:TW_EXTERNAL_PORT`. If different and `TW_AUTO_SERVE_AXON=1` (default), execute `ServeAxon` (or `ServeAxonTls`). On `rate_limited`, log the remediation and retry after the subnet's `serving_rate_limit` blocks, read from chain through the gateway (not a fixed number). **Never publish from more than one replica:** only the instance with `TW_AXON_PUBLISHER=1` (default 1 when `TW_INSTANCE_COUNT=1`) publishes.
8. Start background tasks: metagraph refresh, clock check, axon drift check (every 30 min).
9. Mark ready.

On shutdown: stop accepting, drain in-flight requests (`TW_DRAIN_S`, default 10 s), close the gateway and Redis.

#### 8.7.4 Health endpoints (`miner/health.py`)

| Path | Auth | Returns |
|---|---|---|
| `GET /healthz` | none | `200 {"status":"ok"}` if the process is alive |
| `GET /readyz` | none | `200` when registered, nonce store reachable, clock OK and the metagraph is fresh or degraded (8.5.1; `"degraded"` lists soft problems); else `503` with reasons |
| `GET /metrics` | none; bound to `TW_METRICS_BIND` (default `127.0.0.1:9100`), **not** on the public port | Prometheus text |

`/healthz` and `/readyz` reveal no hotkey, version or configuration.

### 8.8 Validator client (`validator/client.py`)

```python
class ValidatorClient:
    def __init__(self, signer: RequestSigner, *, timeout_s: float = 12.0,
                 max_concurrency: int = 64, max_attempts: int = 2,
                 verify_responses: bool = True, scheme_policy: str = "http",
                 max_response_bytes: int = 4 * 1024 * 1024) -> None:
        self._http = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(retries=0),   # NEVER resend a signed request
            limits=httpx.Limits(max_connections=max_concurrency * 2,
                                max_keepalive_connections=max_concurrency),
            timeout=httpx.Timeout(timeout_s, connect=3.0),
            follow_redirects=False)                          # redirects would break target binding

    async def query(self, neuron: NeuronView, route: str, body: bytes, *,
                    method: str = "POST", idempotent: bool = True,
                    response_model: type[BaseModel] | None = None) -> MinerResult: ...

    async def query_many(self, neurons: Sequence[NeuronView], route: str, body: bytes,
                         **kw) -> dict[int, MinerResult]:
        # bounded by an asyncio.Semaphore(max_concurrency); never raises for one miner's failure
        ...

@dataclass(frozen=True)
class MinerResult:
    uid: int
    hotkey: str
    ok: bool
    status: int | None
    latency_ms: float | None
    data: Any | None            # parsed response_model, or raw bytes
    error_code: str | None      # tw.* or transport codes: tw.timeout, tw.connect_error,
                                # tw.bad_response_signature, tw.response_too_large, tw.invalid_response
    attempts: int
    protocol: Literal["btauth/1", "v10"] = "btauth/1"   # which wire format answered (Section 8.11.3)
    response_verified: bool = False   # True only for a valid twresp/1 signature; always False for v10
```

Rules:

- Serialize the body **once**; sign per miner, per attempt, with `receiver_ss58=neuron.hotkey` and a fresh nonce.
- `target` = the exact `raw_path` httpx will send. Build the URL with `httpx.URL(base).copy_with(raw_path=target.encode())`, then sign `url.raw_path.decode()`, so both sides agree byte-for-byte.
- Retry only on connect errors, read timeouts (if `idempotent`), and 502/503/504. Never retry 4xx.
- Stream-read the response with a byte cap (`max_response_bytes`); abort → `tw.response_too_large`.
- If `verify_responses`, check `twresp/1` (Section 9.1). Failed check → `ok=False`, `error_code="tw.bad_response_signature"`. **Scoring code must treat this as a failed response.**
- Never send a request to a neuron whose axon is `None` or fails `parse_axon`.
- **One time budget per query:** all attempts for one miner, including the v10 fallback attempt (8.11.3), finish within `max_attempts × timeout_s` (or the per-call `timeout_s` override × `max_attempts`). The v10 attempt gets the time left; if none is left the result is `tw.timeout`. A round's length is therefore bounded no matter how miners answer.
- `query(..., timeout_s=)` overrides the per-attempt deadline for one call (used by `compat.Dendrite(timeout=)`).

### 8.9 Validator loop (`validator/loop.py`, `scores.py`, `weights.py`)

```python
class SubnetValidator(ABC):
    """Users subclass this. The kit runs the schedule."""
    @abstractmethod
    async def make_task(self, round_id: int) -> Task: ...          # route + body + expected info
    @abstractmethod
    async def score(self, task: Task, results: dict[int, MinerResult]) -> dict[int, float]: ...
    def select_miners(self, mg: MetagraphView) -> Sequence[NeuronView]:   # default provided
        ...

runner = ValidatorRunner(MyValidator(), settings=ValidatorSettings.from_env())
runner.run()
```

Schedule:

1. Every `TW_ROUND_INTERVAL_S` (default 60 s): get the metagraph, select miners (default: all non-permit neurons with an axon, random sample of `TW_SAMPLE_SIZE`, default 64), `make_task`, `query_many`, `score`.
2. Update the score store: per-UID EMA, `s = α·new + (1−α)·s`, `α = TW_SCORE_ALPHA` (default 0.1). Reset a UID's score when its hotkey changes (deregistration and re-registration; detect via the `uid → hotkey` map).
3. Weight setting: when `blocks_since_last_update ≥ weights_rate_limit` (read from chain, re-read each tempo) **and** at least `TW_MIN_WEIGHT_INTERVAL_BLOCKS` (default 100) have passed, submit `SetWeights(weights={uid: score})` for UIDs with score > 0, with `version_key=TW_WEIGHTS_VERSION_KEY`. Plan first (`client.plan`); if warnings mention clipping, log them.
4. On `rate_limited`: wait the number of blocks in `remediation` (parse) or one tempo, then retry. On `not_registered` / `not_authorized`: alert and stop setting weights (keep querying).
   **Expired timelocked commits (decision D32).** When a timelocked commit fails with `expired` or `too_early` (including the chain's `InvalidRevealRound`), the scheduler plans again against the current block (`client.plan`, a new extrinsic with a new reveal round) and submits it. At most 3 such attempts per weight window; then log `weights_commit_replan_exhausted`, count it in `tw_validator_weight_submissions_total{ok="false",code=...}` and wait for the next window. The same signed extrinsic is never resent (8.3).

   **Version key preflight (decision D38).** The chain accepts a timelocked commit whose `version_key` is below the subnet's `WeightsVersionKey` and drops it silently at reveal. Before a timelocked commit the scheduler reads `WeightsVersionKey` through the gateway (cached for the window); if the validator's key is lower it does not commit, logs `weights_version_key_stale` at ERROR (both keys), counts `tw_validator_weight_submissions_total{ok="false",code="version_key_stale"}` and retries in the next window. This is how stage 3 (10b.5) reaches upgraded validators with a stale key at commit time instead of at reveal.
5. If all scores are zero, do not submit (avoid burning weights); log `tw.no_scores`.

Score store (`scores.py`): SQLite file `TW_STATE_DIR/scores.db`, WAL mode.

```sql
CREATE TABLE IF NOT EXISTS scores (
  netuid INTEGER NOT NULL, uid INTEGER NOT NULL, hotkey TEXT NOT NULL,
  score REAL NOT NULL, updated_block INTEGER NOT NULL,
  PRIMARY KEY (netuid, uid));
CREATE TABLE IF NOT EXISTS rounds (
  id INTEGER PRIMARY KEY, netuid INTEGER, started_at REAL, n_queried INTEGER,
  n_ok INTEGER, p50_ms REAL, p95_ms REAL);
CREATE TABLE IF NOT EXISTS weight_submissions (
  id INTEGER PRIMARY KEY, netuid INTEGER, block INTEGER, ok INTEGER,
  code TEXT, n_uids INTEGER, block_hash TEXT);
```

Validators also expose `/healthz`, `/readyz`, `/metrics` on `TW_METRICS_BIND`.

### 8.10 Timelock extension (`extensions/timelock.py`)

Two opt-in patterns (from the v11 signed-requests guide):

- **Sealed challenge.** The validator sends `{"sealed": sealed.hex()}` with `reveal_in` (default 30 s) to all miners ahead of time. Miners call `bt.timelock.decrypt(..., wait=True, timeout=...)`. Nobody gets a head start from network placement.
- **Sealed response.** The miner returns its answer sealed to a short reveal (default 12 s). The validator has the ciphertext (and the response signature) before it can read it, so a colluding validator cannot leak answers before scoring.

Implementation:
- `seal(data: bytes, reveal_in: str) -> str` (hex) and `open(hex: str, *, wait: bool, timeout: float) -> bytes`.
- **drand cache:** `decrypt` hits the drand HTTP API. Wrap it with a process-wide limiter (default 8 concurrent) and retries (3, backoff). Decrypt in a worker thread (blocking call).
- Response models gain a `sealed: bool` flag. Scoring receives decrypted data or a `tw.timelock_unavailable` error.
- **Boundary (decision D30).** `bt.timelock` is called only from `chain/gateway.py` (`ChainGateway.timelock_seal` / `timelock_open`; `FakeChain` implements both with a fake round clock). ADR-0001 stays as it is: no new module imports `bittensor`. `extensions/timelock.py` owns the limiter, retries, worker thread and the API above.
- **ADR-0001 exception (decision D40).** `chain/gateway.py` may also import the SDK's compiled core `bittensor_core` (`get_signature_for_round`, `decrypt_with_signature`, `encrypt_at_round`), so each drand round's signature is fetched once, checked against a probe sealed locally to that round, cached, and every ciphertext decrypted locally. The gateway's timelock surface is `timelock_seal`, `timelock_parse`, `timelock_signature`, `timelock_decrypt` (ADR-0001 note). The import-linter contract forbids `bittensor_core` in every other module. Any SDK upgrade re-checks these three functions in `scripts/check_sdk_surface.py`.
- Settings: `TW_TIMELOCK_CONCURRENCY` (default 8), `TW_TIMELOCK_RETRIES` (default 3), `TW_TIMELOCK_TIMEOUT_S` (default 30). drand HTTP 429 / 5xx / timeouts after the retries → `tw.timelock_unavailable` with a WARNING and `tw_timelock_open_total{result="unavailable"}`; never an unbounded wait.
- Tests use the fake backend. Tests that call the real drand API carry the pytest marker `drand` and are not part of `just test`; keep such runs short (the localnet chain shares the same public endpoint and already gets HTTP 429).

### 8.11 Two-way legacy v10 bridge (`extensions/legacy_v10/`)

During a migration, miners and validators upgrade at different times. Every pairing must work until the subnet owner ends the transition:

| | v10 miner (old Axon) | TaoWire miner |
|---|---|---|
| **v10 validator (old Dendrite)** | works today, untouched | **server side** (8.11.2) |
| **TaoWire validator** | **client side** (8.11.3) | btauth/1 |

Both sides are opt-in and time-boxed. Neither side imports bittensor v10 (ADR-0008).

#### 8.11.1 The v10 wire format (`wire.py`)

Confirmed byte for byte against a real `bittensor==10.5.0` Dendrite and Axon (`conformance/vectors/legacy_v10.json`, captured by `scripts/capture_v10_vectors.py` in Phase 0). `tests/migration/test_legacy_v10_vectors.py` re-derives every value below from the captured bytes with the v11 SDK.

**Request (v10 Dendrite → Axon).**

- `POST http://{ip}:{port}/{SynapseName}`. The path is the Synapse class name. v10 Dendrites always use `http`.
- Headers, in this order: `name`, `timeout` (seconds as a Python float string, `12.0`), `bt_header_axon_{ip,port,hotkey}`, `bt_header_dendrite_{ip,version,nonce,uuid,hotkey,signature}`, one `bt_header_input_obj_{field}` per required Synapse field (a field with no default), `header_size`, `total_size`, `computed_body_hash`, then the HTTP client's own headers and `Content-Type: application/json`. Only non-null values are sent. `version` is the v10 SDK version as an integer (`10005000`). Header names are lower-case with underscores; a reverse proxy that drops underscore headers (nginx's default) breaks v10 traffic.
- `bt_header_input_obj_{field}` is base64 of the JSON of a **default instance of the field's type** (`int` → `0` → `MA==`), not the field's value. The Axon needs these headers to build a Synapse from the headers; without them it answers 500.
- `header_size` and `total_size` come from `sys.getsizeof`. The Axon never checks them.
- Body: the **whole Synapse** as JSON, serialised with `json.dumps` defaults (`", "` and `": "` separators, non-ASCII escaped as `\uXXXX`): `name`, `timeout`, `total_size`, `header_size` (`0`), the `dendrite` and `axon` objects (every TerminalInfo field including nulls; `dendrite.signature` is set), `"computed_body_hash": ""`, then the Synapse's own fields.
- `dendrite.nonce` is `time.time_ns()`. `dendrite.uuid` is a uuid1 fixed per Dendrite instance.

**`computed_body_hash`.** `sha3_256_hex(concat(sha3_256_hex(str(value)) for each hash field))`, all strings UTF-8.

- `str(value)` is Python's `str()` of the field's value in `model_dump()`: `True`, `None`, `0.1`, `1e-07`, `['a', 'b c']`, `{'x': 1.0, 'y': 1e-07}`. The kit hashes the parsed model values the same way, never the JSON text.
- Hash fields: the `required_hash_fields` ClassVar, in **declared** order. A Synapse that still declares `required_hash_fields` as a pydantic field (deprecated in v10) is hashed in **model (body) order**, whatever order its list has.
- With no hash fields (the default, `()`), the hash is `sha3_256("")` = `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`.
- The Axon recomputes the hash from the parsed body and compares it with the header. A mismatch is answered **500**, not 401.

**Request signature.** sr25519 by the dendrite hotkey over the UTF-8 string `f"{nonce}.{dendrite_hotkey}.{axon_hotkey}.{dendrite_uuid}.{computed_body_hash}"`, sent as `0x` + lowercase hex. The raw string is signed (no `<Bytes>` wrapping), so `crypto.verify` accepts it in strict mode. The Axon rebuilds the message with **its own hotkey**, not `bt_header_axon_hotkey`, so a request signed for another axon fails with 401.

**Axon processing order.** Parse headers (unknown Synapse → 404; unparseable, e.g. no `input_obj` headers → 500) → `blacklist_fn` (403) → signature and nonce check (401) → `priority_fn` (503 when full) → body hash check (500) → forward (408 on timeout) → response.

- `blacklist_fn` runs **before** the signature check, on a Synapse built from the headers only: body fields hold placeholder values (`dummy_input == 0` whatever was sent).
- Freshness is keyed by `(dendrite_hotkey, dendrite_uuid)`. The first nonce seen for a key must be newer than `now − 4 s − timeout` (16 s for `timeout=12`). Later nonces must be strictly greater than the last accepted one. There is no upper bound, so future nonces pass. These rules apply only when `bt_header_dendrite_version ≥ 7002000`.

**Response (Axon → Dendrite).**

- The HTTP status equals `bt_header_axon_status_code`. On success the body is the full Synapse with output fields filled, as compact JSON (`","` and `":"`, UTF-8). On error it is `{"message": "..."}`.
- Headers: `name`, `timeout`, `bt_header_axon_{status_code,status_message,process_time,ip,port,hotkey}`, the request's `bt_header_dendrite_*` echoed, `bt_header_input_obj_*`, `header_size`, `total_size`, `computed_body_hash`.
- **A successful (200) response carries no axon nonce, uuid, version or signature.** Rejections raised after the headers parsed (401, 403, 500 on a hash mismatch) add `bt_header_axon_{version,nonce,uuid,signature}`. That signature is sr25519 by the axon hotkey over `f"{axon_nonce}.{dendrite_hotkey}.{axon_hotkey}.{axon_uuid}"`, where `axon_hotkey` is the request's `bt_header_axon_hotkey`. It covers neither body nor status, and v10 Dendrites do not check it.
- A btauth/1 request sent to a v10 Axon gets **500** with `bt_header_axon_status_code: 500` and body `{"message": "Internal Server Error #<uuid>"}`. The `bt_header_axon_status_code` header is the reliable marker of a v10 Axon (8.11.3).

**For the kit.** The v10 client sends the full Synapse body and the `input_obj` headers. The server side computes the hash from the `compat.Synapse` model values. The kit's own freshness window and replay store (8.11.2) apply on top of the v10 rules, which allow future nonces and accept any nonce for a new uuid. The kit's v10 responses use the v10 shape; adding an axon signature to successful responses is harmless, because v10 Dendrites ignore it.

**What the v10 scheme does and does not protect** (document in `docs/security.md`):
- It binds the receiver (the axon checks against its own hotkey), the sender and the nonce.
- It does **not** cover the HTTP method, the path, or any body field outside `required_hash_fields`. Those fields can be changed on the wire without breaking the signature (vector N8). Fields that matter for scoring must be in `required_hash_fields`; `migrate scan` warns when a Synapse has an empty or partial list.
- Successful responses are not signed at all; error-response signatures cover neither body nor status. There is no response signature that v10 Dendrites check.

#### 8.11.2 Server side: v10 validators → TaoWire miner (`server.py`)

- Enabled with `TW_LEGACY_V10_UNTIL=<ISO date>`. v10 requests are accepted **through the day before `<date>` (UTC)**; from `<date>` on they get 410 `tw.legacy_disabled`, in a running process and after a restart alike. The miner refuses to start if `<date>` is today or earlier, or more than 180 days away. There is no "forever" option.
- Mounted automatically for routes declared through `compat.Synapse` (Section 10b.2): the kit has the Synapse class, so it computes `computed_body_hash` itself from `required_hash_fields`. Native routes may still supply `legacy_synapse=MySynapse` or `legacy_body_hash(raw_body) -> str`; without either, legacy calls to that route are rejected.
- Same pipeline as Section 5.3, with the legacy verifier at step [6]: IP limit → size cap → v10 signature check → the kit's own freshness window (default 10 s) and replay store on `(sender, nonce)` → caller policy → hotkey rate limit → handler.
- Answers in v10 shape (Synapse JSON + `bt_header_axon_*` headers), so an unmodified v10 Dendrite parses it. Answers to **verified** requests (200 and the post-auth 403/429/422/500/504) carry an axon signature over the v10 response message, made with the miner's own hotkey; 401, 410 and pre-auth 503 answers are unsigned, so the miner never signs for unauthenticated input. (v10 Dendrites check neither; the signature is for parity and audit.)
- Non-finite floats (`inf`, `nan`) in an answer are **not** silently changed: if the handler's Synapse holds one in a field the JSON encoder would turn into `null`, the answer is 500 `tw.handler_error` and the log names the field. (A real v10 Axon also fails here.) Requests keep them as `Infinity`/`NaN`, as a v10 Dendrite sends them, so the body hash matches.
- Every legacy call is counted (`tw_legacy_v10_requests_total{direction="inbound"}`) and logged at INFO with the sender prefix; at WARNING once per sender per hour.
- `tw_legacy_v10_days_remaining{direction}` is **current at every scrape** (computed from the end date, not set once at startup), for both directions; alert at < 14 days.

#### 8.11.3 Client side: TaoWire validator → v10 miners (`client.py`)

- Enabled with `TW_LEGACY_V10_CLIENT=auto|off` (default `off`) and `TW_LEGACY_V10_CLIENT_UNTIL=<ISO date>` (required when `auto`; same end-date rule as 8.11.2). v10 Axons verify sr25519 only: `auto` with an ed25519 validator hotkey is refused at startup with a `StartupError` naming both settings.
- **Protocol choice per miner** (`auto`):
  1. If the on-chain axon `protocol` field is readable through the gateway and equals `TW_PROTOCOL_TAG`, use btauth/1. (Confirmed in Phase 0: the field is readable through `Metagraph.raw["axons"][uid]["protocol"]` and exposed as `NeuronView.axon_protocol`.)
  2. Otherwise try btauth/1 first. If the answer has the v10 shape (an HTTP 500 carrying a `bt_header_axon_status_code` header, which every v10 Axon response has; vector N7), retry once immediately with a fresh v10 request and remember `v10` for that hotkey.
  3. Re-probe v10 miners with btauth/1 once per tempo, so upgraded miners switch over without a restart.
  4. **No downgrade:** once a hotkey has answered with btauth/1, never send it v10 again until the hotkey changes **or its on-chain protocol tag moves away from `TW_PROTOCOL_TAG`** (below). This stops an on-path attacker from forcing the weaker format.
  5. **Signed rollback (decision D16):** when a metagraph refresh shows that a hotkey whose `axon_protocol` was `TW_PROTOCOL_TAG` in the previous snapshot now has a different value, the validator forgets that hotkey's protocol memory (the same `forget()` used on a hotkey change) and logs `legacy_v10_protocol_tag_changed` at INFO (hotkey prefix, old and new tag). The next query follows steps 1–2 again, so a miner that rolled back to its v10 release is reached over v10 without restarting the validator. This keeps the security goal of step 4: the tag is set by a `ServeAxon` extrinsic signed by the miner's own hotkey, so an on-path attacker cannot change it. A v10 shape answer on its own, without the tag change, still never causes a downgrade. Limits: only the transition *from* `TW_PROTOCOL_TAG` counts (a miner that never published the kit's tag stays btauth-only until the validator restarts, as before), and the switch happens at the first refresh after the new axon info is on chain (the miner's `ServeAxon` is subject to the subnet's `serving_rate_limit`).
- v10 results come back as `MinerResult(protocol="v10", response_verified=False)`. Scoring code decides whether unverified answers count; the default `SubnetValidator` treats them as valid answers but exposes the flag.
- Counted as `tw_legacy_v10_requests_total{direction="outbound"}` and summarised per round: `n_btauth`, `n_v10`. This is the number the subnet owner watches to decide when to end the transition (Section 10b.5).

### 8.12 Observability

**Logs** (`structlog`, JSON to stdout): `ts, level, event, request_id, route, caller_hotkey (first 8 chars + "…"), status, latency_ms, code`. Full hotkeys only at DEBUG. Never log bodies, signatures or headers' signature values.

**Request IDs:** ULID per request, returned in `X-TW-Request-Id`.

**Metrics:** see Appendix B.

### 8.13 Testing package (`testing/`)

- `FakeChain(ChainGateway)`: in-memory subnets, neurons, axons, weights. Methods to register neurons, set permits and stakes, advance blocks, inject failures (`fail_next("metagraph", times=2)`), and inspect submitted weights.
- `keys.py`: deterministic keypairs from `//Alice`, `//Bob`, `//Charlie`, `//Dave`, `//Eve` (sr25519) and ed25519 variants, wrapped as wallet-like signers. Never write them to `~/.bittensor`.
- `clock.py`: a controllable `now_ns` provider passed into the verifier for freshness tests.
- `pytest_plugin.py` fixtures: `fake_chain`, `miner_app` (ASGI app with FakeChain), `signed_client` (httpx client signing as a chosen key against the ASGI app via `httpx.ASGITransport`), `validator_client`.

### 8.14 CLI (`cli/`)

| Command | Purpose |
|---|---|
| `taowire init <dir> [--template text-ops]` | Scaffold a subnet project: protocol, miner, validator, tests, `.env.example`, compose file |
| `taowire doctor [--role miner|validator]` | Checks: Python/SDK versions, wallet hotkey readable, coldkey absence, chain reachable, registered, axon on chain matches config, port reachable from outside (optional external probe URL), clock offset, Redis reachable, multi-worker safety |
| `taowire sidecar` | Run the localhost sidecar (Section 11.6) |
| `taowire conformance --vectors DIR` | Run Python reference against vectors; `--generate` rewrites them |
| `taowire bench --duration S` | Local load test: in-process signer + real uvicorn miner |
| `taowire sign-request ...` | Debug helper: print curl with btauth headers for a route (uses a hotkey) |
| `taowire migrate scan <repo> [--format text\|json\|md]` | List every v10 symbol and pattern with its replacement (Section 10b.4) |
| `taowire migrate apply <repo> [--dry-run]` | Apply safe rewrites; mark the rest with `# TW-MIGRATE:` comments |
| `taowire migrate status` | Live view for subnet owners: btauth/1 vs v10 share of traffic, from a running validator's metrics |

---

## 9. Kit protocol extensions (response signing, streaming)

These are TaoWire extensions. They are separate from btauth/1 and versioned on their own.

### 9.1 `twresp/1`: signed responses

**Headers** (set by the miner on every non-streaming response from a protected route, including error responses produced after authentication):

| Header | Value |
|---|---|
| `X-TW-Resp-Version` | `1` |
| `X-TW-Resp-Hotkey` | miner hotkey SS58 |
| `X-TW-Resp-Crypto` | `ed25519`, omitted for sr25519 |
| `X-TW-Resp-Signature` | `0x` + lowercase hex |

**Signed payload** (UTF-8, `\n`-joined, no trailing newline):

```
twresp/1
<scheme>
<request nonce, decimal (from X-Bittensor-Nonce of the request)>
<request sender ss58 (validator)>
<responder ss58 (miner)>
<HTTP status code, decimal>
<sha256 of the raw response body, lowercase hex>
```

Binding the response to the request's nonce and sender stops a miner from replaying an older answer or another validator's answer. Same signing rules as btauth (substrate context for sr25519, raw bytes, no wrapping).

**Validator verification:** `responder == expected miner hotkey`, `X-TW-Resp-Version == 1`, signature valid under the declared scheme only, and nonce/sender equal to what this validator sent. Otherwise `tw.bad_response_signature`.

Requests that fail *before* authentication (413, 429, 401) are not signed (the miner does not yet know the request is genuine).

### 9.2 Streaming (SSE)

For token-by-token responses:

- Response `Content-Type: text/event-stream`. Events: `event: chunk` with `data: <json>`; final `event: tw-end` with `data: {"digest": "<sha256 hex>", "count": N, "signature": "0x..."}`.
- `digest` = sha256 over the concatenation of each chunk's exact `data` bytes (UTF-8, without the `data: ` prefix or trailing newlines), in order.
- **Chunks are JSON objects or arrays (decision D35).** The digest is over plainly concatenated chunks, so it does not fix the chunk boundaries by itself; objects and arrays are self-delimiting, so a stream re-split at other boundaries no longer parses. The miner refuses to emit any other chunk (the stream ends without `tw-end`); the validator rejects one as `tw.invalid_response`. Every language follows this rule (11.1). The digest format and the 11.7 streaming vector do not change.
- **Chunk depth and trailer form (decision D43).** A chunk nests at most 128 levels (arrays and objects counted together); the miner never emits a deeper one and the validator rejects one as `tw.invalid_response`. In `tw-end`, `count` is a plain non-negative JSON integer (`-0`, a fraction or an exponent is refused) and no string holds a lone UTF-16 surrogate escape. Every language, Python included, applies the same rules.
- The `tw-end` signature uses the `twresp/1` payload with the status line set to `200` and the body-hash line set to `digest`. Headers `X-TW-Resp-Hotkey` / `X-TW-Resp-Crypto` are sent at stream start.
- The validator accumulates the digest while consuming. A missing or invalid `tw-end` → the whole stream is `tw.bad_response_signature`.
- Limits: `max_stream_s` (default 60), `max_stream_bytes` (default 4 MiB), idle timeout between events (default 10 s). Settings `TW_STREAM_MAX_S` (1–600), `TW_STREAM_MAX_BYTES` (1 KiB–64 MiB), `TW_STREAM_IDLE_S` (1–120), per-route overrides allowed; both the miner and the validator enforce them (D29).
- **Open streams per caller (decision D36).** A miner process holds at most `TW_STREAM_MAX_PER_CALLER` (default 16, range 1–256) open streams per caller hotkey across all routes; beyond that it answers 429 `tw.rate_limited` with `Retry-After` before any byte is streamed. This stops one permitted validator holding streams up to `max_stream_s` to fill the server's connections.

Rules (decision D29):
- **Miner.** The whole 5.3 pipeline (body cap, rate limits, verify, replay, policy, per-hotkey limit) runs before the first byte; failures there are ordinary signed or unsigned JSON errors (Appendix A), not streams. A handler exception, a limit hit or a drain during the stream ends it **without** `tw-end` (never a trailer over partial data), logs `stream_aborted` (route, reason) and counts `tw_stream_aborted_total{reason}`.
- **Validator.** Rejected as `tw.bad_response_signature` for the whole stream: missing, invalid or duplicate `tw-end`; any event after `tw-end`; `count` ≠ chunks received; digest mismatch; `X-TW-Resp-*` headers missing at stream start. Time limits → `tw.timeout`; byte limit → `tw.response_too_large`; a chunk whose `data` is not JSON → `tw.invalid_response`. Unknown event names and SSE comments are ignored (they are not part of the digest).
- **Unverified until the end.** The client may hand chunks to the caller as they arrive, but marked unverified; only the final result says `response_verified=True`. Scoring must use the final result. The 8.8 time budget covers the whole stream.
- The SSE parser reads untrusted bytes: Hypothesis property tests (13.3) and stream abuse tests (13.6) are required.

---

## 10. The example subnet

`examples/text-ops-subnet` is used for docs, local tests and the testnet e2e. It is deliberately deterministic, so correctness can be checked automatically.

- **Task:** the validator sends `{"text": <random 64–512 chars>, "op": "upper"|"reverse"|"sha256"}` to `POST /v1/transform`.
- **Miner:** returns `{"result": ...}`.
- **Score:** `1.0` if the result is correct, else `0`; multiplied by a latency factor `max(0.2, 1 - latency_ms / timeout_ms)`. Failed signature or error → 0.
- **Weights:** EMA of scores, set by the kit's schedule.
- Miners in TS, Go and Rust implement the same route and must produce byte-identical results.

Files:

```python
# text_ops/protocol.py
class TransformRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4096)
    op: Literal["upper", "reverse", "sha256"]
class TransformResponse(BaseModel):
    result: str

def expected(req: TransformRequest) -> str:
    if req.op == "upper": return req.text.upper()
    if req.op == "reverse": return req.text[::-1]
    return hashlib.sha256(req.text.encode()).hexdigest()
```

Note for other languages: `upper` and `reverse` must use the same Unicode rules as Python. To keep cross-language results identical, the validator generates **ASCII-only** text (`[A-Za-z0-9 ]`).

---

## 10b. Migrating existing v10 subnets

### 10b.1 Who this is for and the target experience

An existing subnet whose code follows the archived template's shape: `protocol.py` with `Synapse` subclasses, a miner that attaches `forward` / `blacklist` / `priority` functions to an Axon, and a validator that calls a Dendrite and then scores and sets weights.

Target experience for the subnet team:

1. Run `taowire migrate scan .` and get a report of everything that needs changing.
2. Run `taowire migrate apply .`, which rewrites imports and the Axon/Dendrite setup.
3. Fix the `# TW-MIGRATE:` items by hand. For a template-derived subnet that is mostly config, logging and chain calls, and the result should stay within S6 (≤ 50 changed lines).
4. Release the new version. Old and new nodes keep working together (Section 8.11).
5. Follow the rollout runbook (10b.5) to end the transition.

Their `forward`, `blacklist`, `priority`, `reward` and scoring logic should not need changes beyond imports.

### 10b.2 The compat layer (`taowire.compat`)

A v10-shaped API over the native kit. It adds no security logic of its own: every request still goes through the full pipeline in Section 5.3.

#### 10b.2.1 `Synapse`, `StreamingSynapse`, `TerminalInfo`

```python
from taowire.compat import Synapse   # was: import bittensor as bt; bt.Synapse

class Dummy(Synapse):
    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)
    def deserialize(self) -> int | None:
        return self.dummy_output
```

- A Pydantic v2 model with the v10 public fields and methods that template code uses: `dendrite: TerminalInfo`, `axon: TerminalInfo`, `name`, `timeout`, `total_size`, `header_size`, `computed_body_hash`, `required_hash_fields`, `deserialize()`, `get_total_size()`, `body_hash`.
- `TerminalInfo` has the v10 fields: `status_code`, `status_message`, `process_time`, `ip`, `port`, `version`, `nonce`, `uuid`, `hotkey`, `signature`. The kit fills them so code like `response.dendrite.status_code == 200` and `response.dendrite.process_time` keeps working.
- On the btauth/1 path, `dendrite` and `axon` are **not sent** on the wire. They are filled locally from the verified caller (miner side) or from the HTTP result (validator side). On the v10 path they are encoded as v10 headers (8.11.1).
- `StreamingSynapse` keeps the v10 shape (`process_streaming_response`, `extract_response_json`) and maps to the kit's SSE streaming (Section 9.2). Phase 4.
- v10 `bt.Tensor` fields are not supported. `migrate scan` flags them; the fix is to serialize with the ML library (as the v11 migration guide says).

#### 10b.2.2 `Axon` (miner side)

```python
from taowire.compat import Axon

axon = Axon(miner=Miner.from_env())             # was: bt.axon(wallet=..., config=...)
axon.attach(forward_fn=self.forward,
            blacklist_fn=self.blacklist,
            priority_fn=self.priority)
axon.serve(netuid=...)                           # no-op beyond config check: the kit publishes on startup
axon.start()                                     # runs the miner
```

- Each attached Synapse class becomes `POST /<SynapseName>` (the same path v10 used), served over btauth/1 and, when `TW_LEGACY_V10_UNTIL` is set, also over v10 (8.11.2).
- `blacklist_fn(synapse) -> (bool, str)` runs **after** the kit's caller policy, with `synapse.dendrite.hotkey` set to the verified caller. A team's own blacklist can only narrow access, never widen it. A `True` result returns 403 `tw.forbidden_blacklisted`.
- `priority_fn(synapse) -> float` orders admission when a route's concurrency limit is reached (bounded priority queue, `TW_COMPAT_MAX_QUEUE`, default 256). It no longer controls a thread pool.
- `verify_fn` is accepted only if it is `None`; a custom one is rejected at startup with a message pointing to the caller policy and blacklist hooks. Signature checking is the kit's job.
- The v10 `forward_fn` signature (`async def forward(synapse) -> synapse`) is kept. Sync functions run in a worker thread.

#### 10b.2.3 `Dendrite` (validator side)

```python
from taowire.compat import Dendrite, axons_from

dendrite = Dendrite(signer=RequestSigner(wallet))          # was: bt.dendrite(wallet=wallet)
axons = axons_from(metagraph_view, uids=miner_uids)        # was: [self.metagraph.axons[uid] for uid in miner_uids]
responses = await dendrite(axons=axons, synapse=Dummy(dummy_input=step),
                           timeout=12, deserialize=True)
```

- Same call shape and return shape as v10: a list in the same order as `axons`, each item either the deserialized value or the filled Synapse.
- Underneath it is `ValidatorClient.query_many`: fresh nonce per attempt, no transport retries, response size cap, twresp/1 checks, and the v10 fallback when `TW_LEGACY_V10_CLIENT=auto` (8.11.3).
- Failures do not raise. As in v10, the item comes back with `dendrite.status_code` set (408 for timeout, 503 for connect error, 401/403 passed through) and `dendrite.status_message` set to the `tw.*` code.
- `AxonInfo` is a small dataclass (`ip`, `port`, `hotkey`, `is_serving`) built from `NeuronView`, so code that filters on `axon.is_serving` keeps working.
- `compat.Metagraph` is a read-only view over the kit's `MetagraphView` with the v10 attribute names template code reads (`uids`, `hotkeys`, `axons`, `S`, `validator_permit`, `n`, `block`; `Metagraph.of_miner(...)` for miner code). No `sync()`: the kit's cache refreshes it.

#### 10b.2.4 Validator loop

The template's `BaseValidatorNeuron` loop (forward → reward → `update_scores` → `set_weights`) maps onto `SubnetValidator` (Section 8.9). `taowire.compat` ships `TemplateValidatorAdapter`, which wraps a team's existing `forward()` and `reward()` functions so the kit runs the schedule, score store and weight setting. Teams with heavily customised loops keep their own loop and use only `compat.Dendrite` and the gateway.

#### 10b.2.5 `compat.weights`

v11 `SetWeights` already normalises, clips and quantises (Section 3.5), so `process_weights_for_netuid` and `convert_weights_and_uids_for_emit` are no longer needed. `compat.weights.to_mapping(uids, weights) -> dict[int, float]` converts the template's parallel arrays (numpy or lists) into the mapping `SetWeights` accepts. That is the only re-wrapped v10 helper.

#### 10b.2.6 `compat.Subtensor` (decision D34)

A v10-shaped facade for the `subtensor` calls that template-derived and non-template subnets make, so they don't hand-write a chain helper (data-universe: ~49 lines). Everything goes through the gateway (ADR-0001). Reads: `metagraph(netuid)` (the pinned compat `Metagraph`), `block`, `get_current_block()`, `get_block_hash(block)`, `get_uid_for_hotkey_on_subnet(hotkey, netuid)`, `is_hotkey_registered(...)`, `get_commitment(netuid, uid)` and the other read calls the case studies show are needed. Writes: only `commit(...)` (commitments) and the writes the kit already performs (`set_weights`, `serve_axon` go to the kit scheduler / lifecycle). Any other write raises `NotImplementedError` naming the v11 replacement; `migrate scan` flags those calls. Hotkey-signed only; never a coldkey.

### 10b.3 What the compat layer does not cover

Handled by `migrate scan` reports and the v11 migration guide, not by wrappers:

| v10 usage | Replacement |
|---|---|
| `bt.config`, argparse via `bt.subtensor.add_args` etc. | Kit settings (`TW_*`, Section 12) or the team's own config |
| `bt.logging` | Standard `logging` / kit structlog setup |
| `bt.subtensor(...)`, `bt.metagraph(...)`, `metagraph.sync()` | Kit `MetagraphCache` / gateway, or `bt.Subtensor` directly |
| `subtensor.set_weights(...)` | Kit weight scheduler, or `bt.SetWeights` |
| Other `subtensor` reads and commitments | `compat.Subtensor` (10b.2.6) |
| `subtensor.serve_axon(...)` | Kit lifecycle (automatic) |
| `bt.Tensor` fields | Serialize with the ML library |
| Custom `Axon` subclasses, monkeypatched `Dendrite` | Manual port |
| `StreamingSynapse` between a v10 peer and a TaoWire peer (v10 wire) | Not supported (D33). Streaming works TaoWire ↔ TaoWire over 9.2 only. A v10 Dendrite streaming to a TaoWire miner gets the v10-shaped `tw.invalid_request` answer; `migrate scan` flags `StreamingSynapse` use with this mixed-fleet limit. Move streaming routes after stage 2 of the rollout |

### 10b.4 `taowire migrate`

#### 10b.4.1 `scan`

- Static analysis with `libcst` (optional extra `taowire[migrate]`). It does not import or run the team's code.
- Rules live in `migrate/rules.py`: each rule has an id (`TWM001`…), a pattern, a severity (`auto` = `apply` can rewrite it, `manual` = needs a person, `risk` = security-relevant), the replacement, and a doc link. Start from the removed-symbol list in Section 3.8 plus the table in 10b.3.
- Detects the template shape (`template/base/neuron.py`, `BaseMinerNeuron`, `BaseValidatorNeuron`) and says so at the top of the report.
- Security checks (`risk`): Synapses with empty or partial `required_hash_fields` (8.11.1); blacklist functions that allow unregistered callers; `allow_non_registered=True`; `force_validator_permit=False`.
- Output: text (default), JSON (for tooling) and Markdown (to paste into a migration PR). Exit code 0 when nothing is left that `apply` cannot handle, 1 otherwise.

#### 10b.4.2 `apply`

- Only `auto` rules. Rewrites imports (`bt.Synapse` → `compat.Synapse`), Axon/Dendrite construction and `attach`, the metagraph-axons list, and the weights helpers.
- Everything else gets a `# TW-MIGRATE: TWMxxx <one-line instruction>` comment at the exact line.
- `--dry-run` prints a unified diff. Without it, refuses to run on a dirty git tree unless `--allow-dirty`.
- Never edits files outside the given repo, never touches wallets or `.env` files.

### 10b.5 Rollout runbook for subnet owners (`docs/migration-rollout.md`)

Each stage has an entry check, an exit check and a rollback. The owner decides when to move on; the kit gives the numbers.

| Stage | What happens | Exit check | Rollback |
|---|---|---|---|
| 0. Prepare | Port the code with `migrate`; run the mixed-fleet localnet test (13.8) on the `testnet` image tag | Mixed-fleet matrix green | — |
| 1. Validators first | Validators upgrade with `TW_LEGACY_V10_CLIENT=auto`. They reach v10 and v11 miners alike | All validators upgraded; per-round `n_ok` unchanged vs before | Validators go back to the v10 release |
| 2. Miners upgrade | Miners release with `TW_LEGACY_V10_UNTIL=<date>` so any v10 validator still works | `migrate status`: ≥ 95% of queried miners answer over btauth/1 | Miners go back to the v10 release, which re-publishes the axon without the kit's protocol tag; upgraded validators reach them over v10 again at their next metagraph refresh after that `ServeAxon` lands (8.11.3 step 5), with no validator restart |
| 3. Push stragglers | Upgraded validators already send a higher `TW_WEIGHTS_VERSION_KEY` (set in the stage 1 release). The owner now raises the subnet's weights-version hyperparameter to that value, so v10 validators can no longer set weights | No v10 inbound traffic for one tempo (`tw_legacy_v10_requests_total{direction="inbound"}` flat) | Lower the version key again |
| 4. End the transition | Remove `TW_LEGACY_V10_UNTIL` and set `TW_LEGACY_V10_CLIENT=off` | Legacy counters at zero | Re-enable with a new end date |

Rules: validators always move first; the legacy end dates should fall within roughly 4–6 weeks of stage 1; miners that never upgrade are simply scored as failures once stage 4 ends. **Changing a Synapse's `required_hash_fields`** (for example the `TWM100` fix) changes the v10 body hash, so it breaks a mixed fleet: ship that change to all peers at once, or after stage 4 (D28).

### 10b.6 Proving it

- **Captured vectors.** In Phase 0, `scripts/capture_v10_vectors.py` runs a real `bittensor==10.5.0` Dendrite and Axon in a separate virtualenv and records exact request and response bytes (headers, bodies, signatures) for several Synapses, including one with an empty `required_hash_fields`. These become `conformance/vectors/legacy_v10.json`. Section 8.11.1 is updated to match them.
- **Case studies.** Port the archived template (`examples/migrations/template-v10-to-v11/`) and at least two real design-partner subnets. Record lines changed, time spent and anything `migrate` missed in `docs/migrations/<name>.md` (criteria S6, S7). Every miss becomes a new rule or a compat fix.
- **Mixed fleet.** Section 13.8.

---

## 11. Multi-language support: TypeScript, Go, Rust

### 11.1 Scope per language

| Capability | Python | TypeScript | Go | Rust |
|---|---|---|---|---|
| btauth/1 sign | ✅ (v11) | ✅ | ✅ | ✅ |
| btauth/1 verify | ✅ (v11) | ✅ | ✅ | ✅ |
| Monotonic nonce | ✅ | ✅ (BigInt) | ✅ | ✅ |
| Memory + Redis nonce store | ✅ | ✅ | ✅ | ✅ |
| Server adapter | FastAPI | Fastify | `net/http` | axum |
| Client (validator side) | httpx | fetch/undici | `net/http` | reqwest |
| twresp/1 sign + verify | ✅ | ✅ | ✅ | ✅ |
| SSE streaming with signed trailer | ✅ | ✅ | ✅ | ✅ |
| Caller policy | ✅ (native) | via sidecar snapshot | via sidecar | via sidecar |
| Chain writes (serve axon, set weights) | ✅ (v11) | via sidecar | via sidecar | via sidecar |
| Full validator loop | ✅ | ❌ (not in scope) | ❌ | ❌ |

### 11.2 Common rules for all implementations

1. Build the payload byte-for-byte as in Section 4.2 (and 9.1 for twresp).
2. Hash the **raw body bytes**, before any parsing.
3. Use the **raw request target** as received (percent-encoded path + `?` + query). Do not use the router's decoded path.
4. Nonces are 64-bit unsigned integers held as **BigInt / u64 / uint64**, never as floating-point numbers. In JavaScript, `Number` loses precision above 2^53, and nanosecond Unix times are ~1.7×10^18.
5. Strictly increasing nonces per process: `max(now_ns, last + 1)`.
6. Verify under the declared scheme only. Absent `X-Bittensor-Crypto` means sr25519.
7. sr25519 uses signing context `b"substrate"`.
8. **Strict mode:** never accept a signature over `<Bytes>…</Bytes>`-wrapped data.
9. Check freshness before signature (cheap first), and store the nonce only after the signature verifies.
10. Nonce store `retention ≥ max_age + allowed_skew`; refuse to start otherwise.
11. Same error codes and HTTP statuses as Appendix A.
12. Pass every vector in `conformance/vectors/` before release.

### 11.3 TypeScript (`@taowire/btauth`)

**Runtime:** Node.js ≥ 20 (LTS). ESM + CJS builds. No browser target in v1.

**Dependencies:** `@polkadot/util-crypto` and `@polkadot/util` (sr25519/ed25519 via WASM, SS58 decode), `fastify` (peer, optional), `ioredis` (optional). Node's built-in `crypto` for sha256.

```ts
// payload.ts
import { createHash } from "node:crypto";
export type Scheme = "sr25519" | "ed25519";
export interface PayloadInput {
  scheme: Scheme; method: string; target: string; body: Uint8Array;
  nonceNs: bigint; sender: string; receiver: string | null;
}
export function buildPayload(p: PayloadInput): Uint8Array {
  const lines = [
    "btauth/1", p.scheme, p.method.toUpperCase(), p.target,
    createHash("sha256").update(p.body).digest("hex"),
    p.nonceNs.toString(10), p.sender, p.receiver ?? "-",
  ];
  return new TextEncoder().encode(lines.join("\n"));
}

// nonce.ts
let last = 0n;
export function nextNonce(): bigint {
  // Date.now() gives ms; scale to ns and add a sub-ms counter for uniqueness.
  const now = BigInt(Date.now()) * 1_000_000n;
  last = now > last ? now : last + 1n;
  return last;
}

// verify.ts (core)
import { cryptoWaitReady, decodeAddress, sr25519Verify, ed25519Verify } from "@polkadot/util-crypto";
import { hexToU8a } from "@polkadot/util";
export async function initCrypto() { await cryptoWaitReady(); }   // call once at startup

export function verifyRequest(opts: {
  headers: Record<string, string | string[] | undefined>; body: Uint8Array;
  method: string; target: string; selfHotkey: string; store: NonceStore;
  maxAgeS?: number; allowedSkewS?: number; nowNs?: bigint;
}): Caller {
  // 1 shape → 2 receiver → 3 freshness → 4 signature → 5 replay (Section 4.3)
  // signature: sr25519Verify(payload, sig, decodeAddress(sender)) — NOT signatureVerify(),
  // which also tries wrapped forms (breaks strict mode).
}
```

Notes:
- `sr25519Verify` uses the substrate context internally (Polkadot convention). Confirm with the conformance vectors in Phase 5; if a vector fails, this is the first thing to check.
- Signing: `new Keyring({ type: "sr25519" }).addFromUri(seedOrMnemonic).sign(payload)` signs raw bytes without wrapping. Hotkey material comes from the Bittensor hotkey JSON file (`secretPhrase` / `secretSeed` fields) or an env-injected seed; document both and never log them.
- **Fastify adapter:** register a content-type parser with `parseAs: "buffer"` for all types on protected routes; use `request.raw.url` (the target exactly as sent) as `target`; set `bodyLimit`. Add a pre-handler hook running verify → policy → per-hotkey rate limit.
- `verifyRequest` is CPU-bound but fast (WASM); no worker threads in v1. Benchmark in Phase 5.

### 11.4 Go (`github.com/<org>/taowire/go/btauth`)

**Go:** the module keeps the `go 1.22` directive (the minimum for users). Development, release builds and `just audit` use a **supported** Go release (currently the 1.25 or 1.26 line), so `govulncheck` judges a patched standard library (decision D23). **Module path:** working name `github.com/taowire/taowire/go` (package `.../go/btauth`) until package names are reserved (Phase 0 item); rename with one search-and-replace. **Dependencies:** `github.com/ChainSafe/go-schnorrkel` (sr25519), stdlib `crypto/ed25519`, `crypto/sha256`, `golang.org/x/crypto/blake2b` (SS58 checksum), `github.com/mr-tron/base58`, `github.com/redis/go-redis/v9` (optional).

```go
func BuildPayload(scheme, method, target string, body []byte, nonce uint64, sender, receiver string) []byte {
    sum := sha256.Sum256(body)
    if receiver == "" { receiver = "-" }
    lines := []string{"btauth/1", scheme, strings.ToUpper(method), target,
        hex.EncodeToString(sum[:]), strconv.FormatUint(nonce, 10), sender, receiver}
    return []byte(strings.Join(lines, "\n"))
}

func verifySr25519(pub [32]byte, payload []byte, sig [64]byte) (bool, error) {
    pk, err := schnorrkel.NewPublicKey(pub)       // check exact constructor for the pinned version
    if err != nil { return false, err }
    var s schnorrkel.Signature
    if err := s.Decode(sig); err != nil { return false, err }
    t := schnorrkel.NewSigningContext([]byte("substrate"), payload)
    return pk.Verify(&s, t)
}
```

Notes:
- **Target:** use `r.RequestURI` (the unmodified request target from the request line), not `r.URL.Path` (decoded). Reject absolute-form targets (`http://...`) on protected routes.
- **Body:** wrap with `http.MaxBytesReader`, read fully into `[]byte`, verify, then hand the bytes to the handler via context.
- **Nonce:** `uint64(time.Now().UnixNano())` with an atomic `max(now, last+1)` loop (`sync/atomic` CAS).
- ed25519: `ed25519.Verify(pub, payload, sig)` from the standard library.
- Middleware signature: `func Middleware(cfg Config) func(http.Handler) http.Handler`; the verified caller is available with `btauth.CallerFrom(ctx)`.
- go-schnorrkel API names differ between versions. Pin one version and wrap it in `sr25519.go` so changes stay local.

### 11.5 Rust (`taowire-btauth`)

**Rust:** stable ≥ 1.80, edition 2021. **Dependencies:** `schnorrkel` (sr25519), `ed25519-dalek` v2 (stay on v2 for 1.0, even though v3 is out; revisit after 1.0, D23), `sha2`, `blake2`, `bs58`, `hex`, `thiserror`; features `axum` (`axum`, `tower`), `client` (`reqwest`), `redis` (`redis` crate with tokio).

```rust
pub fn build_payload(scheme: Scheme, method: &str, target: &str, body: &[u8],
                     nonce_ns: u64, sender: &str, receiver: Option<&str>) -> Vec<u8> {
    let hash = hex::encode(Sha256::digest(body));
    [ "btauth/1", scheme.as_str(), &method.to_ascii_uppercase(), target, &hash,
      &nonce_ns.to_string(), sender, receiver.unwrap_or("-") ].join("\n").into_bytes()
}

fn verify_sr25519(pk: &[u8; 32], payload: &[u8], sig: &[u8; 64]) -> Result<bool, Error> {
    let pk = schnorrkel::PublicKey::from_bytes(pk).map_err(|_| Error::Malformed)?;
    let sig = schnorrkel::Signature::from_bytes(sig).map_err(|_| Error::Malformed)?;
    Ok(pk.verify_simple(b"substrate", payload, &sig).is_ok())
}

fn verify_ed25519(pk: &[u8; 32], payload: &[u8], sig: &[u8; 64]) -> Result<bool, Error> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk).map_err(|_| Error::Malformed)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    Ok(vk.verify(payload, &sig).is_ok())
}
```

Notes:
- **ed25519 edge cases.** `ed25519-dalek` `verify` vs `verify_strict` and Polkadot's ed25519 implementation can disagree on rare non-canonical inputs. Use `verify` (RFC 8032 behaviour) and add any disagreement found by the conformance vectors to `negative.json` with a note. Document the choice in an ADR.
- **axum layer:** use `OriginalUri` and take `uri.path_and_query()` as the target (axum keeps percent-encoding). Read the body with `axum::body::to_bytes(body, limit)`. Put the `Caller` into request extensions.
- **Nonce:** `AtomicU64` with a `fetch_update` loop for `max(now, last+1)`.
- `#![forbid(unsafe_code)]`.

### 11.6 Sidecar (for non-Python miners)

`taowire sidecar` runs a small FastAPI app on `127.0.0.1:${TW_SIDECAR_PORT}` (default 9910). It uses the miner's own hotkey (for `ServeAxon`) and the Python chain gateway.

| Method & path | Purpose | Response |
|---|---|---|
| `GET /v1/health` | liveness + chain status | `{"ok":true,"block":123,"metagraph_age_s":42}` |
| `GET /v1/metagraph?netuid=N` | snapshot used for caller policy | `{"netuid":N,"block":B,"neurons":[{"uid","hotkey","validator_permit","total_stake_tao","axon"}...]}` |
| `GET /v1/caller/{hotkey}?netuid=N` | single policy decision | `{"allowed":true}` or `{"allowed":false,"code":"tw.forbidden_not_validator"}` |
| `POST /v1/serve-axon` | publish `{netuid, ip, port, tls_cert_hex?}` | `{"ok":true,"block_hash":"0x..."}`; chain refused → 409 `{"ok":false,"code","error_name","remediation"}` (`bt.ErrorCode` values); chain unreachable → 503 `{"ok":false,"code":"chain_unavailable",...}`; a bad body → 422 `tw.invalid_request` (decision D44) |

Security:
- Binds **only** to loopback (`127.0.0.1` / `::1`). Refuses other addresses unless `TW_SIDECAR_UNSAFE_BIND=1`.
- Every request needs `Authorization: Bearer <token>`, where the token is read from `TW_SIDECAR_TOKEN_FILE` (file mode 0600, generated on first run). A missing, repeated or wrong token → 401 `tw.sidecar_unauthorized` before routing (decision D44).
- `POST /v1/serve-axon` only accepts the netuid configured at startup.
- No weight setting through the sidecar in v1 (non-Python validators are out of scope).

Language packages ship a small sidecar client that caches `/v1/metagraph` (refresh 60 s, same three staleness stages as Section 8.5.1; the sidecar reports the snapshot's age and the subnet's tempo) and implements the same `CallerPolicy` logic locally.

### 11.7 Conformance vectors

Files in `conformance/vectors/` (JSON, UTF-8). Each vector has an `id`, a `description`, inputs and expected outputs. Generated by `conformance/generate.py` using the Python reference (v11 `build_payload`, `sign`, `verify`), then reviewed and committed. Generated files never change silently: the generator refuses to overwrite unless `--force`.

**`payload.json`** (build only). At least:

| id | Case |
|---|---|
| P1 | The golden request from Appendix C |
| P2 | Empty body |
| P3 | Lower-case method `post` → `POST` |
| P4 | Target with percent-encoding `/a%20b?x=%2F` (kept as-is) |
| P5 | Target with no query vs with empty query (`/p` vs `/p?`): both kept exactly |
| P6 | Unicode JSON body (UTF-8 bytes hashed, not code points) |
| P7 | Unbound receiver (`-`) |
| P8 | Nonce at u64 boundary-ish `18446744073709551615` (string handling) |
| P9 | ed25519 scheme line |

**`ed25519.json`** (deterministic): the Appendix C vector plus 5 more with seeds `//Alice`, `//Bob` and different bodies, expected signature hex.

**`sr25519_verify.json`**: 10 payloads pre-signed by Python with `//Alice` and `//Bob`; each implementation must verify all as valid, and must verify its own fresh signatures with the Python verifier (live interop, Section 13.5).

**`negative.json`** (each with expected `tw.*` code): missing each header; version `2`; unknown crypto `ecdsa`; non-hex signature; wrong-length signature; bad SS58 checksum; receiver mismatch; receiver missing; nonce 11 s old; nonce 3 s in future; body changed by one byte; target decoded (`/a b` instead of `/a%20b`); method changed; ed25519 signature presented without `X-Bittensor-Crypto` (must fail as sr25519, not fall back); sr25519 signature with `X-Bittensor-Crypto: ed25519`; `<Bytes>`-wrapped signature (every implementation, Python included, rejects with `tw.auth_bad_signature`, D22); sender not 48 characters, incl. a very long one (D19); weak public keys (D20); replay of an accepted request.

**`twresp.json`**: build + ed25519 deterministic vectors for response signing, including a streaming digest vector with 3 chunks.

**`legacy_v10.json`** (Python only): requests and responses captured from a real `bittensor==10.5.0` Dendrite and Axon (Section 10b.6). Each vector has the exact headers, body, expected `computed_body_hash`, the signed message string and whether the signature verifies. Captured once, reviewed, committed; never regenerated without `--force`.

All freshness vectors carry `now_ns` so results are deterministic.

---

## 12. Configuration reference

All settings are environment variables with the prefix `TW_` (Pydantic Settings; `.env` supported). CLI flags mirror them. Unknown `TW_*` variables cause a startup error (typo protection).

### 12.1 Common

| Variable | Default | Notes |
|---|---|---|
| `TW_NETWORK` | `test` | `finney` \| `test` \| `local` \| `ws(s)://...` |
| `TW_CHAIN_FALLBACKS` | empty | comma-separated extra endpoints |
| `TW_NETUID` | required | |
| `TW_WALLET_NAME` | required | coldkey wallet directory name (only hotkey is read) |
| `TW_WALLET_HOTKEY` | `default` | |
| `TW_WALLET_PATH` | `~/.bittensor/wallets` | |
| `TW_REFUSE_IF_COLDKEY_PRESENT` | `1` | refuse to start if an unencrypted coldkey file is readable |
| `TW_STATE_DIR` | `~/.taowire` | locks, scores DB, sidecar token |
| `TW_LOG_LEVEL` | `INFO` | |
| `TW_METRICS_BIND` | `127.0.0.1:9100` | never the public interface by default |
| `TW_CHAIN_TIMEOUT_S` | `30` | |
| `TW_METAGRAPH_REFRESH_S` | `120` | |
| `TW_METAGRAPH_SOFT_AGE_S` | `900` | degraded (warning only) after this (8.5.1) |
| `TW_METAGRAPH_MAX_AGE_S` | 2 × tempo in seconds (`8640` at tempo 360) | known-callers-only after this (8.5.1) |
| `TW_METAGRAPH_STRICT` | `0` | `1` = 503 for everyone past max age |
| `TW_STARTUP_TIMEOUT_S` | `120` | |
| `TW_NTP_SERVERS` | `pool.ntp.org,time.cloudflare.com` | empty disables |
| `TW_REDIS_URL` | empty | required when instances/workers > 1 |
| `TW_PROTOCOL_TAG` | `87` | stored in `ServeAxon.protocol`; 0–255 (u8 on chain) |
| `TW_SCHEME_POLICY` | `http` | `http` \| `https` \| `https-if-tls-published` |
| `TW_ALLOW_PRIVATE_AXONS` | `0` | set `1` on localnet only |
| `TW_STREAM_MAX_S` | `60` | 1–600; whole-stream limit (9.2) |
| `TW_STREAM_MAX_BYTES` | `4194304` | 1 KiB–64 MiB (9.2) |
| `TW_STREAM_IDLE_S` | `10` | 1–120; gap between events (9.2) |
| `TW_STREAM_MAX_PER_CALLER` | `16` | 1–256; open streams per caller hotkey per process (9.2, D36) |

### 12.2 Miner

| Variable | Default | Notes |
|---|---|---|
| `TW_BIND_HOST` | `0.0.0.0` | |
| `TW_BIND_PORT` | `8091` | |
| `TW_EXTERNAL_IP` | required | published on chain |
| `TW_EXTERNAL_PORT` | `TW_BIND_PORT` | |
| `TW_AUTO_SERVE_AXON` | `1` | |
| `TW_AXON_PUBLISHER` | `1` | set `0` on all but one replica |
| `TW_INSTANCE_COUNT` | `1` | for safety checks |
| `TW_WORKERS` | `1` | uvicorn workers |
| `TW_AUTH_MAX_AGE_S` | `10` | 2–60 |
| `TW_AUTH_ALLOWED_SKEW_S` | `2` | 0.5–10 |
| `TW_NONCE_RETENTION_S` | `60` | must be ≥ 2 × (max_age + skew); refused at startup otherwise (D21, D27) |
| `TW_MAX_BODY_BYTES` | `1048576` | per-route override |
| `TW_RATE_IP_PER_S` / `TW_RATE_IP_BURST` | `50` / `100` | |
| `TW_RATE_HOTKEY_PER_S` / `TW_RATE_HOTKEY_BURST` | `20` / `40` | |
| `TW_TRUSTED_PROXIES` | empty | CIDRs |
| `TW_REQUIRE_PERMIT` | `1` | |
| `TW_MIN_CALLER_STAKE_TAO` | `0` | TAO value of the caller's stake at spot price, approximate (8.3, D2); suggest ≥ 1000 on mainnet |
| `TW_ALLOW_HOTKEYS` / `TW_DENY_HOTKEYS` | empty | comma-separated SS58 |
| `TW_HANDLER_TIMEOUT_S` | `10` | per-route override |
| `TW_SIGN_RESPONSES` | `1` | twresp/1 |
| `TW_DRAIN_S` | `10` | |
| `TW_LEGACY_V10_UNTIL` | empty | ISO date; accepts v10 Dendrite requests until then (8.11.2) |
| `TW_COMPAT_MAX_QUEUE` | `256` | admission queue per route when `priority_fn` is used (10b.2.2) |
| `TW_TLS_CERT_FILE` / `TW_TLS_KEY_FILE` | empty | HTTPS directly from uvicorn; both or neither; the key file must not be group/world readable; the miner publishes the certificate's public key with `ServeAxonTls` (16.3) |
| `TW_TLS_PUBLISHED_CERT_FILE` | empty | proxy mode: the public certificate the reverse proxy presents, published with `ServeAxonTls`; mutually exclusive with `TW_TLS_CERT_FILE` |
| `TW_UNSAFE_ALLOW_MEMORY_NONCE_MULTIWORKER` | `0` | do not use in production |

### 12.3 Validator

| Variable | Default | Notes |
|---|---|---|
| `TW_ROUND_INTERVAL_S` | `60` | |
| `TW_SAMPLE_SIZE` | `64` | |
| `TW_QUERY_TIMEOUT_S` | `12` | |
| `TW_MAX_CONCURRENCY` | `64` | |
| `TW_MAX_ATTEMPTS` | `2` | |
| `TW_VERIFY_RESPONSES` | `1` | |
| `TW_MAX_RESPONSE_BYTES` | `4194304` | |
| `TW_SCORE_ALPHA` | `0.1` | EMA |
| `TW_MIN_WEIGHT_INTERVAL_BLOCKS` | `100` | |
| `TW_WEIGHTS_VERSION_KEY` | `0` | must be ≥ subnet's stored key |
| `TW_MECHID` | `0` | |
| `TW_QUERY_VALIDATORS` | `0` | include permit holders in selection |
| `TW_LEGACY_V10_CLIENT` | `off` | `auto` = reach v10 miners too (8.11.3) |
| `TW_LEGACY_V10_CLIENT_UNTIL` | empty | ISO date; required when `auto`; refuse to start if in the past |
| `TW_TIMELOCK_CONCURRENCY` | `8` | 1–64; process-wide drand limiter (8.10) |
| `TW_TIMELOCK_RETRIES` | `3` | 0–10 |
| `TW_TIMELOCK_TIMEOUT_S` | `30` | 1–300 |

### 12.4 Sidecar

| Variable | Default |
|---|---|
| `TW_SIDECAR_PORT` | `9910` |
| `TW_SIDECAR_TOKEN_FILE` | `$TW_STATE_DIR/sidecar.token` |
| `TW_SIDECAR_UNSAFE_BIND` | `0` |

---

## 13. Testing strategy

### 13.1 Layers

| Layer | Location | Chain | Run with | Required to pass for |
|---|---|---|---|---|
| Unit | `tests/unit` | none | `just test` | every change |
| Property | `tests/property` | none | `just test` | every change |
| Integration (in-process) | `tests/integration` | `FakeChain` | `just test` | every change |
| Conformance | `conformance/` | none | `just conformance` | every change touching auth |
| Localnet e2e | `tests/localnet` | Docker localnet | `just localnet-up && just localnet-test` | every phase exit |
| Cross-language interop | `conformance/interop` | localnet | `just interop` | Phase 5–6 exit |
| Migration (compat, scanner, codemods, v10 vectors) | `tests/migration` | none | `just migration-test` | every change touching `compat/`, `migrate/`, `legacy_v10/` |
| Mixed v10/v11 fleet | `tests/localnet` (`mixed_fleet` mark) | Docker localnet + v10 venv | `just mixed-fleet` | Phase 2–3 exit, each release |
| Testnet e2e | `tests/testnet` + runbook | public testnet | manual (Section 15) | Phase 6 exit, each release |
| Load | `taowire bench` | none | `just bench` | Phase 3 exit, each release |

### 13.2 Unit tests (minimum list)

- Signer: nonces strictly increase under 8 threads × 100k calls; receiver required.
- Verifier: each `AuthError` maps to the right code and status; retention check fails at construction; thread offload works.
- Nonce stores: memory expiry; Redis `SET NX PX` behaviour (use a real Redis in Docker for integration, `fakeredis` only for unit); Redis outage → fail-closed 503.
- Policy: deny > allow > registered > permit > stake ordering.
- Body limit: Content-Length rejection; chunked body exceeding the cap mid-stream.
- Rate limit: bucket refill math; `Retry-After`.
- Axon parsing: IPv4, IPv6 bracketed, `None`, `0.0.0.0`, port 0, private ranges.
- twresp/1: sign/verify, mismatched nonce/sender/status/body, wrong responder.
- SSE digest accumulation.
- Score EMA and hotkey-change reset.
- Weight scheduler: respects rate limit; skips all-zero; handles `rate_limited`.

### 13.3 Property tests (hypothesis)

- `verify` never raises anything except `AuthError`/`TWError` for arbitrary header maps and bodies.
- Payload round trip: for random method/target/body/nonce, `sign` then `verify` succeeds; changing any one input fails.
- Target handling: random percent-encoded paths survive client build → server rebuild unchanged.

### 13.4 Integration tests (in-process, no network)

Use `httpx.ASGITransport` against the real miner app with `FakeChain`:

1. Valid validator → 200 + valid response signature.
2. Registered non-validator → 403 `tw.forbidden_not_validator`.
3. Unregistered hotkey → 403 `tw.forbidden_not_registered`.
4. Replay same headers → 401 `tw.auth_replayed`.
5. Request signed for another miner → 401 `tw.auth_wrong_receiver`.
6. Old nonce (frozen clock) → 401 `tw.auth_stale`.
7. Metagraph staleness stages (frozen clock): past soft age → still 200 and `/readyz` shows `degraded`; past max age → a validator that called earlier gets 200, a validator never seen before gets 503 `tw.metagraph_stale`; with `TW_METAGRAPH_STRICT=1` both get 503; a fresh snapshot clears the known-callers set.
8. Oversized body → 413 before verification (assert the verifier was not called).
9. Handler timeout → 504.
10. Validator client against 3 fake miners (one slow, one returning a bad signature, one good) → correct `MinerResult`s.
11. Streaming route: valid trailer accepted; tampered chunk rejected; also reordered, dropped and extra chunks, a tampered or duplicate trailer, events after the trailer and a missing trailer (handler error mid-stream) are rejected as `tw.bad_response_signature` (9.2, D29).
12. Legacy v10 bridge, server side: a request built from `legacy_v10.json` vectors is accepted on a `compat.Synapse` route (body hash computed by the kit), answered in v10 shape, and rejected after the end date; replay and caller policy still apply.
13. Legacy v10 bridge, client side: against a fake v10 Axon, `auto` falls back to v10 once and remembers it; a miner that has answered over btauth/1 is never downgraded by a v10-shaped answer alone; after its on-chain protocol tag moves from `TW_PROTOCOL_TAG` to another value (FakeChain re-serve), the next query reaches it over v10; re-probe switches an upgraded miner back.
14. Compat layer: the template's `Dummy` Synapse, `forward`, `blacklist` and `priority` functions run unchanged on `compat.Axon`; `compat.Dendrite` returns the v10 result shapes, including `dendrite.status_code` on timeout.
15. Compat blacklist cannot widen access: a `blacklist_fn` that returns `False` for an unregistered caller still gets 403 `tw.forbidden_not_registered`.

### 13.5 Cross-language interop (localnet)

`conformance/interop/run_matrix.py` starts each miner implementation on its own port, registers each with its own hotkey on the localnet subnet, then runs the Python validator against all of them, and runs TS/Go/Rust client signers against the Python miner. Pass = every cell 100% success over 200 requests, with response signatures verified.

### 13.6 Negative/abuse tests (run against a local miner)

- 10,000 requests/s with invalid signatures from one IP → IP limiter kicks in, CPU < 2 cores, valid validator traffic still served (p99 < 200 ms). The CPU bound is a hard assert, measured on a quiet host like the benchmark (decision D45: nothing else heavy running, load recorded with the result); a run under deliberately added load is kept as extra information, never as the result.
- Slowloris (slow headers/body) → connections closed by timeouts.
- 100 MB body → 413 without allocating it.
- Streams (D29): a slow-drip stream (one byte per idle period) and an endless stream are cut by the validator at the limits; a client that opens many streams and never reads them does not stall the miner for other validators. Pass rule (D42): the legitimate validator gets 100% 200; the attacker's requests may be 200, 429 or 503 `tw.replay_store_unavailable` (fail-closed refusals), nothing else.

### 13.7 Benchmark targets (`taowire bench`)

On 4 vCPU / 8 GB, 4 uvicorn workers + Redis on the same host, **reached directly** (host networking, a Unix socket, or the container's own IP), not through Docker's userland port proxy (`docker-proxy`). This matches a production deployment, and it is what "met" means (decision D17). `just bench` uses the direct path by default and prints which path it used. A run through `docker-proxy` may be recorded as extra information, never as the result.

| Metric | Target |
|---|---|
| Verified requests/s (trivial handler, 1 KB body) | ≥ 500 |
| Added latency of auth + policy, p50 / p99 | ≤ 2 ms / ≤ 5 ms |
| Validator fan-out to 256 local miners, 1 KB | all done in ≤ 2 s |

Record results in `docs/benchmarks.md` with hardware and versions.

### 13.8 Migration tests

**Scanner and codemods** (`tests/migration`): run `migrate scan` and `migrate apply` on `examples/migrations/template-v10-to-v11/before/`; the output must equal `after/` exactly (golden test), and every rule in `rules.py` has at least one positive and one negative fixture.

**Mixed fleet** (`just mixed-fleet`, `examples/migrations/template-v10-to-v11/mixed-fleet.yml`): on localnet, run a v10 miner and v10 validator (from the `bittensor==10.5.0` venv) next to a TaoWire miner and TaoWire validator, all on one subnet.

| Validator ↓ / Miner → | v10 miner | TaoWire miner |
|---|---|---|
| v10 validator | baseline | 100% success over 200 requests (8.11.2) |
| TaoWire validator | 100% success over 200 requests (8.11.3) | 100% success, responses verified |

Then walk through stages 1–4 of the rollout runbook (10b.5) on the same fleet, including each rollback, and check that weights keep landing on chain at every stage.

---

## 14. Local development runbook

### 14.1 Prerequisites

- Linux or macOS (Apple Silicon needs Rosetta only if building subtensor from source), Docker, Python 3.12 + `uv`, Node 20, Go 1.22, Rust stable, `just`, Redis (Docker).

### 14.2 Start a local chain

```bash
docker run --rm --name local_chain -p 9944:9944 -p 9945:9945 \
  ghcr.io/raofoundation/subtensor-localnet:devnet
# fast blocks (0.25 s) by default; append `False` for real 12 s blocks
btcli query is-fast-blocks --network local
```

Tags: `devnet` (what devnet runs), `testnet` (what testnet runs, **use this before testnet e2e**), `main`/`latest`, `sha-<commit>`, `v<spec_version>`. A fresh localnet has subnets 0 (root) and 1.

**Fast-blocks caveat:** rate limits, immunity and tempo pass 48× faster than wall-clock. Run timing tests (weights rate limit, serving rate limit) with 12-second blocks.

**Localnet facts (verified in Phases 0–1):** `scripts/localnet_up.sh` sets the test subnet's tempo to 10 blocks (on 12-second blocks too, via the localnet sudo key), so permits move within minutes: on a 6-neuron subnet, miners that receive weights get validator permits after a few tempos, so tests must not hard-code which dev hotkey lacks a permit. The chain rejects `ServeAxon` with `127.0.0.1` (`InvalidIpAddress`); use `127.0.0.2` on Linux (all of 127/8 is loopback) or the LAN address on macOS. Fast-block localnets produce transient write failures (short forks, era expiry, MEV-shield timeouts); the setup script and the gateway rebuild and re-sign on these.

### 14.3 Wallets and funding (local only)

```bash
# Alice is pre-funded with 1,000,000 TAO on localnet. Her seed is PUBLIC. Local use only.
btcli wallet regen-coldkey -w alice --no-password \
  --seed 0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a

for w in owner validator miner_py miner_ts miner_go miner_rs; do
  btcli wallet create -w $w -H default --no-password
done
btcli tx transfer --dest owner     --amount-tao 2000 -w alice --network local -y
btcli tx transfer --dest validator --amount-tao 1000 -w alice --network local -y
for m in miner_py miner_ts miner_go miner_rs; do
  btcli tx transfer --dest $m --amount-tao 50 -w alice --network local -y
done
```

### 14.4 Create and activate the subnet

```bash
btcli tx register-subnet -w owner --network local          # expect netuid 2
btcli tx start-call --netuid 2 -w owner --network local
btcli tx burned-register --netuid 2 -w validator --network local
for m in miner_py miner_ts miner_go miner_rs; do
  btcli tx burned-register --netuid 2 -w $m --network local
done
# Give the validator stake so it gets a permit (stake to its own hotkey):
btcli tx add-stake --hotkey validator/default --netuid 2 --amount-tao 500 -w validator --network local
btcli query metagraph --netuid 2 --network local --json
```

Exact flag names can change between v11 releases; check `btcli tx --help` and `btcli tx add-stake --help` on the pinned version, and update `scripts/localnet_up.sh` accordingly.

### 14.5 Run

```bash
cp .env.example .env.local   # TW_NETWORK=local TW_NETUID=2 TW_ALLOW_PRIVATE_AXONS=1 ...
docker run -d --name tw-redis -p 6379:6379 redis:7
TW_WALLET_NAME=miner_py TW_EXTERNAL_IP=127.0.0.2 TW_BIND_PORT=8091 \
  uv run python examples/text-ops-subnet/text_ops/miner.py
# localnet dev wallets have unencrypted coldkeys: add TW_REFUSE_IF_COLDKEY_PRESENT=0 (localnet only; logged as unsafe)
TW_WALLET_NAME=validator uv run python examples/text-ops-subnet/text_ops/validator.py
```

Expected within 2 minutes (fast blocks): validator logs `round ok n_ok=1`, a `weights submitted` line with a block hash, and `btcli query metagraph --netuid 2 --network local --json` shows non-zero weights after the reveal period.

---

## 15. Testnet end-to-end runbook

The goal is to prove the product on the real public testnet across all languages. This costs **test TAO** and depends on testnet health.

### 15.1 Before you start (go / no-go)

1. **Testnet health.** Check open issues in `github.com/RaoFoundation/subtensor` for testnet incidents. Example: issue #3230 (stall began 8 Oct 2026, issue opened 11 Oct, fix merged and issue closed 21 Oct) reported ~414 of 589 testnet subnets stalled by an epoch-scheduler bug. A closed issue does not mean the fix has reached testnet; check the runtime version too. If an incident like this is open, weights and emissions may not update; postpone or limit the run to networking checks.
2. **Localnet rehearsal on the `testnet` image tag** passes completely (Section 14 with `subtensor-localnet:testnet`).
3. **SDK pin unchanged**, or Section 3 re-verified for the new version.

### 15.2 Test TAO

There is no public faucet on real networks (the `faucet` extrinsic is disabled outside local builds; `btcli explain FaucetDisabled`). Request test TAO through the official Bittensor community channels (Discord, linked from bittensor.com) and confirm the current process there; it changes over time. Budget:

```bash
btcli query subnet-registration-cost --network test --json   # subnet lock (largest item)
btcli query burn --netuid <N> --network test --json           # per-hotkey registration
```

Plan: subnet lock + 6 hotkey registrations (1 validator, 4 miners, 1 spare) + validator stake (enough for a permit on your own subnet; on a new subnet the threshold is the runtime default unless changed) + 10% margin for fees.

**Alternative if subnet lock is unaffordable:** use an existing testnet subnet whose owner agrees, register your hotkeys there, and run only your own validator and miners. You then cannot control hyperparameters; note it in the report.

### 15.3 Infrastructure

| Host | Spec | Runs |
|---|---|---|
| `val-1` | 2 vCPU, 4 GB | Python validator, SQLite, (optional) own testnet lite node via `deploy/compose/testnet-node.yml` |
| `mine-1` | 2 vCPU, 4 GB, public IPv4 | Python miner (2 workers) + Redis |
| `mine-2` | 2 vCPU, 4 GB, public IPv4 | TS miner + sidecar, Go miner + sidecar, Rust miner + sidecar (different ports) |

Firewall: miners open only their miner ports to the internet. Metrics and sidecar ports stay on loopback. SSH by key only.

Keys: create all coldkeys on a trusted workstation. Copy **only** `hotkeys/<name>` (and `coldkeypub.txt`) to servers. Coldkeys never leave the workstation.

### 15.4 Chain setup (from the trusted workstation)

```bash
export N=test
btcli tx register-subnet -w owner --network $N            # note NETUID from output
btcli tx start-call --netuid $NETUID -w owner --network $N
btcli query subnet-hyperparameters --netuid $NETUID --network $N --json > reports/hyperparams.json
for w in validator miner_py miner_ts miner_go miner_rs; do
  btcli tx burned-register --netuid $NETUID -w $w --network $N
done
btcli tx add-stake --hotkey validator/default --netuid $NETUID --amount-tao <X> -w validator --network $N
```

Subnet registration can be **queued** when testnet is full; `register-subnet` waits for `NetworkAdded` and returns the netuid. Registration is rate-limited network-wide (one per ~7,200 blocks).

Optional subnet settings for faster feedback (owner, rate-limited to about one change per parameter per two tempos):

```bash
btcli tx set-hyperparameter --netuid $NETUID --name tempo --value 360 -w owner --network $N
btcli tx set-hyperparameter --netuid $NETUID --name immunity_period --value 7200 -w owner --network $N
```

Keep `immunity_period > commit_reveal_period × tempo`.

### 15.5 Deploy and start

1. On `mine-1`: `.env` with `TW_NETWORK=test`, `TW_NETUID`, `TW_EXTERNAL_IP=<public ip>`, `TW_WORKERS=2`, `TW_REDIS_URL`. Run `taowire doctor --role miner` until all checks pass, then start (`deploy/systemd/taowire-miner.service`).
2. On `mine-2`: for each language, start `taowire sidecar` (own hotkey, own port 9910/9911/9912), then the miner binary with its sidecar URL and token. Each miner calls the sidecar's `/v1/serve-axon` at startup.
3. Wait for axons to appear: `btcli query metagraph --netuid $NETUID --network test --json | jq '.neurons[] | {uid, hotkey, axon}'`.
4. On `val-1`: `taowire doctor --role validator`, then start the validator.

### 15.6 Test cases (all must pass)

| ID | Test | Pass condition |
|---|---|---|
| T1 | Axon publication | All 4 miners show the configured `ip:port` on chain |
| T2 | Happy path, all languages | 3 consecutive rounds, every miner `ok=True`, correct results, response signatures valid |
| T3 | Weights on chain | ≥ 2 successful `SetWeights` (block hashes logged); after the reveal period, `btcli query metagraph` shows weights/incentive for all 4 miner UIDs |
| T4 | Unregistered caller rejected | Run `taowire sign-request` with an unregistered hotkey against each miner → 403 `tw.forbidden_not_registered` |
| T5 | Non-validator rejected | Signed request from `miner_py`'s hotkey to `miner_go` → 403 `tw.forbidden_not_validator` |
| T6 | Replay rejected | Capture one validator request (debug log at the client, `TW_DEBUG_DUMP_REQUEST=1` on a test validator only) and resend within 10 s → 401 `tw.auth_replayed` on every language |
| T7 | Wrong receiver | Re-target a request signed for miner A to miner B → 401 `tw.auth_wrong_receiver` |
| T8 | Stale request | Resend after 15 s → 401 `tw.auth_stale` |
| T9 | Size limit | 5 MB body → 413 on every language, before auth |
| T10 | Multi-worker replay safety | Send the same signed request to both workers of `mine-1` (direct ports) → exactly one 200 |
| T11 | Miner restart | Restart a miner; validator marks it failed during downtime, recovers next round; no re-publish if IP unchanged |
| T12 | Validator restart | Restart validator; scores reload from SQLite; next weights continue the EMA |
| T13 | Metagraph staleness | Run `mine-1` with short test values (`TW_METAGRAPH_SOFT_AGE_S=120`, `TW_METAGRAPH_MAX_AGE_S=300`) and block its chain endpoints (firewall): after 120 s `/readyz` reports `degraded` and the validator is still served; after 300 s the validator is still served, while a signed request from a hotkey that has not called before gets 503 `tw.metagraph_stale`; recovers after unblocking |
| T14 | Clock skew | Shift `mine-2` clock +5 s (test VM only) → requests rejected as stale, `/readyz` reports `clock_skew`; restore |
| T15 | Streaming (Python miner) | Streaming route completes with valid `tw-end`; tampered proxy test → rejected |
| T16 | Mixed fleet on testnet | Add a v10 miner and a v10 validator (template code, `bittensor==10.5.0`) to the subnet; all four cells of the 13.8 matrix pass for 3 rounds; then run rollout stages 1–4 and confirm weights after each |

### 15.7 Language matrix (must be green)

| Validator / client ↓  Miner → | Python | TypeScript | Go | Rust |
|---|---|---|---|---|
| Python validator | T2–T9 | T2–T9 | T2–T9 | T2–T9 |
| TS client signer | T2 | — | — | — |
| Go client signer | T2 | — | — | — |
| Rust client signer | T2 | — | — | — |

### 15.8 Evidence to collect (`reports/testnet-<date>/`)

- `versions.txt`: bittensor version, chain spec version (`btcli query ...`), kit commit, language package versions.
- `hyperparams.json`, `metagraph-before.json`, `metagraph-after.json`.
- Validator logs for the test window; miner logs; `weight_submissions` table dump.
- A filled copy of the T1–T16 table with timestamps, block numbers and pass/fail.

### 15.9 Cleanup

Stop services. Keep the subnet if more runs are planned. Otherwise note that dissolving a subnet distributes its TAO reserve to alpha holders and there is no lock refund; decide with the owner. Remove hotkeys from servers if no longer used.

### 15.10 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All requests 401 `tw.auth_stale` | clock skew | enable NTP (`chrony`); check `taowire doctor` |
| 401 `tw.auth_bad_signature` from one language only | target decoded or body re-serialized | log the target string both sides; compare with conformance P4 |
| 403 `tw.forbidden_not_validator` for your validator | no permit yet (permits update per epoch) | wait one tempo; check stake and `validator_permit` |
| Validator gets `connect_error` | firewall, wrong `TW_EXTERNAL_IP`, NAT | probe from outside; re-check axon on chain |
| `SetWeights` fails `rate_limited` | weights rate limit | scheduler waits; no action |
| `SetWeights` fails `NotEnoughStakeToSetWeights` | stake below threshold | add stake to the validator hotkey |
| `IncorrectWeightVersionKey` | subnet requires newer key | set `TW_WEIGHTS_VERSION_KEY` |
| `ServeAxon` fails `rate_limited` | serving rate limit | wait `serving_rate_limit` blocks |
| Weights never appear | commit-reveal delay or testnet incident | wait reveal period; check testnet issues |

---

## 16. Security specification

### 16.1 The traps and how the kit handles each

| # | Trap | Default handling | Test |
|---|---|---|---|
| 1 | Replay across processes/hosts | Redis store required when >1 worker/instance; refuse to start otherwise; fail-closed on Redis outage | T10, unit |
| 2 | Hashing re-serialized body | Verify on raw bytes before parsing; handlers never see bytes before verification | integration 1, property |
| 3 | Decoded path used as target | Raw target in every adapter; conformance P4 | conformance |
| 4 | Clock drift | NTP check, `/readyz` signal, doctor | T14 |
| 5 | Unbound receiver | `require_receiver=True` hard-coded in miners; signer refuses empty receiver | T7 |
| 6 | Transport retries resend signed requests | httpx `retries=0`; app-level retries re-sign | unit |
| 7 | Authenticated ≠ authorized | Strict caller policy by default; staged metagraph staleness: never admits unknown callers on stale data, without taking all miners down in a chain outage (8.5.1) | T4, T5, T13 |
| 8 | Flooding / oversized bodies | IP limit → size cap → verify (threaded, bounded) → hotkey limit | 13.6, T9 |
| 9 | Unsigned responses | `twresp/1` on by default; scoring treats bad signatures as failures | integration 10 |
| 10 | Public miner IPs | Docs: firewall, optional proxy, only miner port exposed | review |
| 11 | Answer copying / leaking | Timelock extension (opt-in) | integration |
| 12 | Weak legacy bridge (both directions) | Opt-in, mandatory end dates on both sides, kit freshness + replay + caller policy on inbound v10, no downgrade after a miner speaks btauth/1 (only its own signed on-chain tag change re-enables v10, D16), `migrate scan` flags unhashed Synapse fields, traffic counters | integration 12–13, T16 |
| 19 | Compat hooks weakening security | `blacklist_fn` runs after caller policy and can only narrow access; custom `verify_fn` refused | integration 15 |
| 13 | Coldkey on server | Refuse to start if unencrypted coldkey readable; never access `wallet.coldkey` | unit |
| 14 | Supply chain | Locked deps, `just audit`, signed releases, provenance | Section 18 |
| 15 | Nonce collisions (coarse clocks) | Monotonic nonce in all languages | unit |
| 16 | Redirects breaking target binding / SSRF | `follow_redirects=False`; private axons rejected unless localnet flag | unit |
| 17 | Error messages leaking internals | Fixed public messages; request IDs for correlation | unit |
| 18 | Sidecar abuse | Loopback only, bearer token file 0600, fixed netuid | unit |

### 16.2 Secure defaults rule

A configuration that weakens any row above must use a variable whose name starts with `TW_UNSAFE_` or must be clearly bounded (like `TW_LEGACY_V10_UNTIL`). The miner logs every active `TW_UNSAFE_*` at WARNING on startup and exposes `tw_unsafe_settings_active` as a metric.

### 16.3 TLS

- Plain HTTP is acceptable for integrity because both requests (btauth) and responses (twresp) are signed. It does not give confidentiality. Subnets with private payloads must use HTTPS.
- Options: (a) uvicorn with `TW_TLS_CERT_FILE`/`TW_TLS_KEY_FILE`; (b) a reverse proxy (Caddy/nginx) terminating TLS. With a proxy, the proxy must pass the original request target and body unchanged (no path normalization, no body re-encoding), and `TW_TRUSTED_PROXIES` must be set.
- `ServeAxonTls` publishes a compact key (1 algorithm byte + ≤ 64-byte public key), not an X.509 certificate. In `https-if-tls-published` mode, the validator pins the miner's TLS public key against the published one. The exact algorithm-byte meaning must be confirmed in Phase 4 against the chain source (`serve_axon_tls` in `pallets/subtensor`) and recorded in an ADR before enabling this mode.
- **Phase 4 rules (decision D31).** The ADR is ADR-0011 (`docs/adr/0011-serve-axon-tls-key-format.md`), with the subtensor commit read, what the installed SDK sends, and a localnet publish-and-read-back. Only key types the ADR documents are published or accepted; anything else is a `StartupError` (miner) or treated as "no usable key" with a WARNING (validator; in `https` mode that miner fails, it is never reached over HTTP). Pinning compares the leaf certificate's public key with the published key; CA trust is not used for pinned miners. TLS together with the v10 inbound bridge (`TW_LEGACY_V10_UNTIL`) is allowed: v10 Dendrites speak plain HTTP only, so the miner logs WARNING `legacy_v10_with_tls` at startup and the docs say v10 validators cannot reach it (decision D37). A miner that rotates its certificate must re-publish before serving the new one; until then validators refuse it (`tw.tls_pin_mismatch`). Test certificates are generated at test time and never committed. Reverse proxies: the docs and `deploy/` examples (Caddy, nginx) keep the request target and body byte-for-byte; a test shows that a path-normalising proxy makes requests fail verification.

### 16.4 Host hardening (documented, not enforced)

Run as a non-root user; wallet directory mode 0700, hotkey file 0600; secrets via a secrets manager or environment injection; automatic security updates; time sync (chrony); separate hosts for validator and miners; never run untrusted subnet code on a machine with a coldkey.

### 16.5 Security review (Phase 6 gate)

Before the first public release:

1. Internal review against this section with a checklist signed off per row.
2. External review (paid auditor or reputable community reviewer) of: `auth/*`, `limits/*`, `policy/*`, `extensions/response_sig.py`, all four btauth implementations, the sidecar.
3. Fuzzing: 24 h of hypothesis-driven fuzzing on Python header parsing; `cargo fuzz` on the Rust payload/verify path; Go native fuzzing on `Verify`.
4. All high/critical findings fixed; medium findings fixed or documented with rationale.

---

## 17. Phase plan and acceptance criteria

Estimates assume one backend engineer and one blockchain engineer working together. They are planning figures, not commitments.

### Phase 0 — Foundations (1 week)

Tasks:
- Create the repo with the Section 6 skeleton, licences, `justfile`, `.env.example`.
- Depend on `bittensor>=11.3.0,<12` (lock 11.3.0 for development); write a smoke script that imports every v11 symbol from Section 3 and fails loudly if any is missing (`scripts/check_sdk_surface.py`). Run it against the latest 11.x release too.
- Confirm package names are free; reserve them (PyPI, npm, crates.io).
- Bring up localnet; script `localnet_up.sh` end to end (wallets, funding, subnet, registrations, stake).
- Resolve the open item in 8.3 (unit of `total_stake`).
- **Migration groundwork:** create the `bittensor==10.5.0` venv (`scripts/legacy_venv.sh`); capture `legacy_v10.json` vectors (10b.6) and correct Section 8.11.1 to match; confirm whether the v11 metagraph exposes the on-chain axon `protocol` field (8.11.3); check the archived template's licence for `examples/migrations/before/`.
- **Design partners:** sign up at least 2 existing v10 subnets willing to be ported as case studies (S7).
- **Core team:** first contact as in Section 1.7, step 1.
- **Funding:** pick the funding model and apply for the first grant or sponsorship (Section 20.1); the external security review in Phase 6 must be paid for.
- **Metrics baseline:** write the M1 counting script (Section 1.6) and record today's value (expected 0).

Exit criteria:
- `just lint test` runs (even with placeholder tests).
- `scripts/check_sdk_surface.py` passes.
- `localnet_up.sh` produces a subnet with 1 validator (with permit) and 1 miner registered.
- `legacy_v10.json` committed and reviewed; 8.11.1 matches it.
- Design partners named (or the gap recorded as a risk).
- Core team contacted; their answer (or no answer) recorded in ADR-0009.
- Funding model chosen; funding for the Phase 6 security review requested.

### Phase 1 — Python core security and miner (2–3 weeks)

Tasks: `config`, `errors`, `crypto`, `chain/*`, `auth/*`, `policy/*`, `limits/*`, `miner/*`, `observability/*`, `testing/*`.

Exit criteria:
- Unit + property + integration tests 1–9 pass; coverage ≥ 90% on `auth/`, `policy/`, `limits/`.
- A Python miner runs on localnet, publishes its axon, and serves a signed request from `taowire sign-request`.
- Multi-worker safety check refuses unsafe configs.

### Phase 2 — Validator client, loop, example subnet and migration core (3 weeks)

Tasks: `validator/*`, `extensions/response_sig.py`, `examples/text-ops-subnet`, `taowire init`, `taowire doctor`; **migration core:** `extensions/legacy_v10/` (both directions), `compat.Synapse`, `compat.Axon`, `compat.Dendrite`, `compat.weights`, `taowire migrate scan`.

Exit criteria:
- Integration tests 10 and 12–15 pass.
- The archived template runs on `taowire.compat` with hand-made changes (`examples/migrations/template-v10-to-v11/after/`).
- Mixed-fleet matrix (13.8) green on localnet.
- On localnet: validator queries the miner, scores, sets weights; weights visible on chain after reveal.
- `taowire init my-subnet` produces a project that passes its own tests out of the box.
- Quickstart (`docs/quickstart.md`) followed by someone new in < 60 min on localnet.

### Phase 3 — Hardening, performance and migration tooling (2–3 weeks)

Tasks: rate limiting with Redis, clock guard, readiness, drain, metrics, bench, abuse tests (13.6), deployment files (`deploy/`); **migration tooling:** `taowire migrate apply` and `migrate status`, `TemplateValidatorAdapter`, `docs/migration-from-v10.md`, `docs/migration-rollout.md`, design-partner ports.

Exit criteria:
- Benchmark targets in 13.7 met and recorded.
- Abuse tests pass.
- `docs/security.md` complete.
- `migrate scan` + `apply` on the template's `before/` produces `after/` exactly (13.8 golden test).
- Rollout stages 1–4 (10b.5), including rollbacks, walked through on the localnet mixed fleet.
- At least one design-partner subnet ported, with a case study meeting S6.

### Phase 4 — Extensions (2 weeks)

Tasks: streaming (9.2) including `compat.StreamingSynapse`, timelock (8.10), TLS modes (16.3) including the ADR on `ServeAxonTls` key format. Carried over from the Phase 3 gate: G5-1 (`compat.Subtensor`, 10b.2.6, and the data-universe recount), G5-2 (re-planned timelocked commits, D32), G5-3 (`just check` never silently uses a stale Go tool).

Exit criteria:
- Integration test 11 passes; streaming works on localnet, including a v10-style `StreamingSynapse` on `compat`.
- Sealed challenge and sealed response work on localnet; drand failure paths tested with the fake backend.
- ADR-0011 accepted with evidence; each TLS mode tested on localnet, including a mismatched pinned key being rejected.
- The localnet weight-reveal end-to-end test passes 5 runs in a row (G5-2).
- Phase 3 results hold: golden test, template S6 and llm-detection S6 unchanged or better; data-universe S6 measured and recorded (D24: not a gate criterion).

D24 (Phase 3): one design-partner subnet meeting S6 with a localnet mixed fleet closes "at least one design-partner subnet ported".

### Phase 5 — Multi-language (3–4 weeks)

Tasks: conformance vectors + generator; TS, Go, Rust packages (Section 11); sidecar (11.6); example miners in each language; `just interop`. Carried over from the Phase 4 gate: G6-1 (`uv build` sdist holds only an explicit include list), G6-2 (watch the unread-streams abuse test, D42), G6-3 (`TW_STREAM_MAX_PER_CALLER`, D36), G6-4 (`WeightsVersionKey` preflight, D38), G6-5 (abuse test pass rule, D42).

Exit criteria:
- `just conformance` green in all four languages.
- Interop matrix (13.5) green on localnet.
- Each language package has a README with a 20-line quickstart and API docs.

### Phase 6 — Testnet e2e, security review, release candidate (2 weeks + review time)

Tasks: Section 15 runbook; security review (16.5); fix findings; docs pass; `v1.0.0-rc1`. Carried over from the Phase 5 gate: G7-1 (Python `decode_chunk` / `encode_chunk` and the trailer parser apply D43), G7-2 (Rust axum example and docs: a header read timeout, or a hard rule to run behind a proxy; covered by the security review), G7-3 (re-read `WeightsVersionKey` right before each commit instead of once per tempo, or document the one-commit gap).

Exit criteria (= product Definition of Done):
- T1–T16 pass; language matrix 15.7 green; evidence stored in `reports/`.
- No open high/critical security findings (the review covers `compat/` and `extensions/legacy_v10/`).
- All success criteria S1–S7 met.

**Total:** roughly 15–19 weeks for two engineers (the migration work adds about 2–3 weeks). If time is short, the multi-language phase (5) moves after 1.0, because migration has the larger pool of users.

---

## 18. Versioning and manual release process

### 18.1 Versioning

- Semantic versioning per package. All packages in the monorepo share a minor version line (1.0.x, 1.1.x) to keep the compatibility story simple.
- `twresp/1` and the sidecar API are versioned on their own; breaking changes create `twresp/2` / `/v2/` paths with an overlap period of at least one minor release.

### 18.2 Compatibility matrix (keep in README)

| TaoWire | bittensor allowed | bittensor tested | Chain spec tested | Python | Node | Go | Rust |
|---|---|---|---|---|---|---|---|
| 1.0.x | `>=11.3.0,<12` | 11.3.0 (add each release as it is tested) | record at release (`btcli` query) | 3.10–3.14 | 20, 22 | 1.22+ | 1.80+ |

"Allowed" is what pip accepts. "Tested" is what the kit has been checked against; other versions inside the range work but log a warning at startup (8.7.3).

### 18.3 Supporting a new SDK release

Do this for every stable 11.x release, within **2 weeks** of it shipping (Section 20.2):

1. Read the bittensor release notes and the migration page for changes to anything in Section 3.
2. In a branch, move the lock file to the new release; run `scripts/check_sdk_surface.py`, `just check`, localnet tests, interop and `just mixed-fleet`.
3. Re-run conformance vectors **without** regenerating; any difference is a breaking change in `btauth` and must be investigated before going further.
4. If everything passes: add the version to the "tested" column, update Section 3 if anything changed, ship a patch release.
5. If it breaks the kit: ship a patch release that excludes that version (`!=11.x.y`) right away so users are protected, then fix and lift the exclusion.
6. A new major SDK version (12.x) needs a new TaoWire minor or major release; the `<12` bound is only raised after that work.

### 18.4 Manual release checklist (no CI yet)

1. `just check audit localnet-test interop` all green on a clean checkout.
2. Update `CHANGELOG.md`; tag `vX.Y.Z` (signed tag).
3. Build artifacts: `uv build`; `npm pack`; `cargo package`; Go tag `go/vX.Y.Z`.
4. Generate SHA-256 checksums for all artifacts; sign the checksum file (Sigstore `cosign sign-blob` or GPG).
5. Publish: PyPI, npm (`--provenance` once CI exists), crates.io. Record artifact hashes in the GitHub release.
6. Smoke test installs from the public registries on a clean machine.
7. Before 1.0 only (D26): raise the Go module directive and `golang.org/x/crypto` / `x/sys` to versions with no govulncheck findings, and re-check the Rust `ed25519-dalek` choice (11.5).
8. Before 1.0 only (D39): `just check` / `just audit` use pinned, project-local `cargo-audit`, `clippy` and npm tools through an ensure step like `scripts/go_tools.sh` (G5-3), never whatever is on the host PATH.

When CI/CD is added later, move these exact steps into workflows and switch PyPI/npm to trusted publishing.

---

### 18.5 Alpha pre-release (decision D47)

Before Phase 6, one alpha is published so subnet builders can build on the kit and review it. It is a pre-release in every registry, so nobody gets it without asking for it.

| Package | Registry | Version |
|---|---|---|
| `taowire` | PyPI | `0.1.0a1` (PEP 440 pre-release; `pip install taowire` skips it, `pip install --pre taowire` or `taowire==0.1.0a1` gets it) |
| `@taowire/btauth` | npm | `0.1.0-alpha.1`, dist-tag `alpha` (never `latest`) |
| `taowire-btauth` | crates.io | `0.1.0-alpha.1` (crates.io releases cannot be deleted, only yanked) |
| `github.com/taowire/taowire/go` | Go module proxy | tag `go/v0.1.0-alpha.1` |

Rules:
- Every README and package description starts with the alpha notice: not security-reviewed, APIs may change, for localnet and testnet, **not for mainnet value**.
- The 18.4 checklist applies (signed tag `v0.1.0a1`, checksums signed, smoke installs from the public registries), except item 1 needs `just check audit localnet-test interop` only (no testnet).
- Source is public at `github.com/taowire/taowire` before any package goes up, so reviewers can read what they install. The whole git history is scanned for secrets before the first push.
- Feedback: GitHub issues; security reports through GitHub private vulnerability reporting (`SECURITY.md`).
- Further alphas (`0.1.0a2`, …) follow the same rules. `1.0.0-rc1` still needs Phase 6.

## 19. Risks and open questions

| Risk | Impact | Mitigation |
|---|---|---|
| v11 changes fast (frequent pre-releases) | Breakage | Version range with a tested list, gateway boundary, surface check at build time and at startup, per-release procedure 18.3, fast `!=` exclusions |
| Exact pin conflicts with users' own `bittensor` version | Teams drop the kit rather than stay on an old SDK | Range, not pin (Section 3); never publish an `==` pin |
| Testnet instability | E2E blocked | Localnet rehearsal on `testnet` tag; health check before runs |
| Test TAO availability | E2E blocked | Request early; option to use a partner subnet |
| Other-language crypto library divergence | Interop failures | Conformance vectors, strict mode, live interop matrix |
| Core team ships an official kit | Most teams choose the official one; months of work lose their users | Treat them as a partner from Phase 0 (Section 1.7): early contact, upstream `twresp/1` and vectors, agreed boundaries (ADR-0009), interoperate or merge if they build one anyway |
| Security liability | Many subnets affected by one bug | Review, fuzzing, SECURITY.md, patch deadlines (20.2) backed by funding (20.1) |
| No funding after 1.0 | Kit stops being maintained; an unmaintained security library is worse than none | Funding model decided in Phase 0 (20.1); maintenance commitments sized to funding (20.2); hand-over plan if funding ends (20.4) |
| Nobody adopts it | Effort wasted | Product metrics and 6-month decision point (1.6) |
| Metagraph staleness rules too loose | A de-permitted validator keeps access during a long chain outage | Only callers already accepted on fresh data; `TW_METAGRAPH_STRICT=1` for subnets that prefer hard stops (8.5.1) |
| `total_stake` unit ambiguity | Wrong policy thresholds | Resolve in Phase 0 (8.3) |
| `ServeAxonTls` key format | TLS pinning mode wrong | Confirm from chain source before enabling (16.3) |
| v10 wire format details wrong | Bridge fails against real v10 nodes | **Closed in Phase 0:** 8.11.1 rewritten from vectors captured from a real 10.5.0 Dendrite/Axon; mixed-fleet test every release |
| Existing subnets drift far from the template shape | `migrate` and `compat` cover less than expected | Design-partner ports in Phase 3; every miss becomes a rule; `scan` reports coverage honestly |
| Teams keep the legacy bridge on indefinitely | Weaker v10 security lingers on the subnet | Mandatory end dates on both sides; refuse to start after them; traffic counters for owners |
| Chain runtime upgrade breaks v10 nodes mid-transition | Stage 1–3 subnets lose their v10 half suddenly | Track release notes; runbook says to start migration early; v11 side is unaffected |
| No design partners sign up | S7 unmet; tooling tuned only on the template | Recruit in Phase 0; fall back to porting open-source subnets without their teams |

Open questions to settle by Phase 2:

1. Should the default miner selection exclude permit holders (current default) or include them?
2. Do we offer a hosted "port reachability probe" for `doctor`, or only document how to check?
3. Licence: Apache-2.0 (proposed) vs MIT.
4. Which funding mix (Section 20.1), and who signs the maintenance commitments (20.2)?
5. Does the core team want TaoWire linked from the official docs, merged upstream, or kept separate (Section 1.7)?

---

## 20. Sustainability and maintenance

TaoWire is security code that many subnets' rewards depend on. When a bug is found, every subnet using it is exposed until a fix ships. The SDK and the chain also change often (about 14 runtime upgrades between July and October 2026), so the kit needs steady work just to keep running. Open-source security libraries without funding tend to be abandoned, and an abandoned one is worse than none, because teams keep trusting it. This section says who pays and what we promise.

### 20.1 Funding model

Decide in Phase 0. The recommended mix:

| Source | What it pays for | Notes |
|---|---|---|
| Ecosystem grants (Bittensor / subnet-ecosystem programs, where available) | Build phases, external security review | Apply in Phase 0; the Phase 6 review must not depend on money that has not arrived |
| Sponsorship from subnets that use the kit | Ongoing maintenance (20.2) | Simple tiers, for example: listed sponsor, priority on issues; never private security fixes |
| Paid migration help | Hands-on porting of a subnet with `taowire migrate` and the rollout runbook (10b) | Uses the same open-source tools; case studies feed M2 (1.6) |
| Optional hosted services (later) | Port-reachability probe for `doctor` (open question 2), uptime and version monitoring for miners | Must stay optional; the kit never requires them |

Rules:

- The kit stays fully open source (Apache-2.0 proposed). No paid tier gets security fixes earlier than everyone else.
- Budget items to cover per year: maintainer time (at least one engineer part-time after 1.0), one external security review per major release, test infrastructure and test TAO, and the hosts in Section 15.3.

### 20.2 Maintenance commitments

Promised in `SECURITY.md` and the README only once funding for them exists:

| Commitment | Target |
|---|---|
| Critical security fix (remote bypass of auth, replay or policy) | Fix or mitigation released within 72 hours of a confirmed report |
| High security fix | Within 14 days |
| New stable bittensor 11.x release | Tested and added to the "tested" list, or excluded with `!=`, within 2 weeks (18.3) |
| Chain runtime upgrade affecting the kit | Patch within 1 week of the upgrade reaching testnet |
| Supported release lines | Latest minor and the one before it get security fixes |
| Issue first reply | Within 3 working days (M6) |

### 20.3 Ownership

- **PM:** funding, metrics (1.6), core-team relationship (1.7), design partners.
- **Maintainers (at least 2 people with release rights):** releases, security fixes, SDK and runtime upgrades. Two people so one absence never blocks a critical fix.
- **Security contact:** named in `SECURITY.md`, with a private reporting channel.

### 20.4 If funding ends

Announce it at least 3 months ahead; mark the packages as "maintenance ended" on every registry and in the README; publish a final release; and offer the project to the core team or to a subnet team willing to take it over. Never leave it looking maintained when it is not.

---

## Appendix A — Error codes and HTTP status mapping

| Code | HTTP | Raised when | Response signed? |
|---|---|---|---|
| `tw.rate_limited` | 429 | IP or hotkey bucket empty (`Retry-After` set) | IP: no · hotkey: yes |
| `tw.payload_too_large` | 413 | Body over limit | no |
| `tw.auth_malformed` | 401 | `MalformedAuth` | no |
| `tw.auth_wrong_receiver` | 401 | `WrongReceiver` | no |
| `tw.auth_stale` | 401 | `StaleRequest` | no |
| `tw.auth_bad_signature` | 401 | `BadSignature` | no |
| `tw.auth_replayed` | 401 | `ReplayedRequest` | no |
| `tw.forbidden_denied` | 403 | Deny list | yes |
| `tw.forbidden_not_registered` | 403 | Not in metagraph | yes |
| `tw.forbidden_not_validator` | 403 | No validator permit | yes |
| `tw.forbidden_low_stake` | 403 | Below min stake | yes |
| `tw.invalid_request` | 422 | Body fails the route model | yes |
| `tw.handler_error` | 500 | Unhandled handler exception | yes |
| `tw.metagraph_stale` | 503 | Snapshot older than max age and caller not in the known-callers set, or `TW_METAGRAPH_STRICT=1` (8.5.1) | no |
| `tw.replay_store_unavailable` | 503 | Redis unreachable | no |
| `tw.sidecar_unauthorized` | 401 | Sidecar request without exactly `Authorization: Bearer <token>` (11.6, D44); sidecar only | no |
| `tw.handler_timeout` | 504 | Handler exceeded timeout | yes |
| `tw.forbidden_blacklisted` | 403 | `compat` `blacklist_fn` returned `True` | yes (v10 shape on the legacy path) |
| `tw.legacy_auth_failed` | 401 | v10 signature, hash, freshness or replay check failed, or the body does not parse into the route's Synapse | no |
| `tw.legacy_disabled` | 410 | v10 request after `TW_LEGACY_V10_UNTIL` | no |

Client-side only (in `MinerResult.error_code`): `tw.timeout`, `tw.connect_error`, `tw.http_<status>`, `tw.bad_response_signature`, `tw.response_too_large`, `tw.invalid_response`, `tw.no_axon`, `tw.tls_pin_mismatch` (the miner's TLS key differs from its published `ServeAxonTls` key, 16.3), `tw.timelock_unavailable` (a sealed response or challenge could not be opened: drand unreachable or rate-limited after retries, or not revealed within `TW_TIMELOCK_TIMEOUT_S`, 8.10).

Chain outcomes (`TxOutcome.code`) use `bt.ErrorCode` values unchanged (Section 3.5).

## Appendix B — Metrics catalogue

| Metric | Type | Labels |
|---|---|---|
| `tw_requests_total` | counter | `route`, `status`, `code` |
| `tw_request_duration_seconds` | histogram | `route` |
| `tw_auth_verify_duration_seconds` | histogram | — |
| `tw_auth_failures_total` | counter | `code` |
| `tw_policy_denials_total` | counter | `code` |
| `tw_rate_limited_total` | counter | `layer` (`ip`/`hotkey`) |
| `tw_payload_too_large_total` | counter | — |
| `tw_metagraph_age_seconds` | gauge | — |
| `tw_metagraph_refresh_failures_total` | counter | — |
| `tw_metagraph_degraded` | gauge | — (0 fresh, 1 degraded, 2 known-callers-only) |
| `tw_clock_offset_seconds` | gauge | — |
| `tw_clock_step_seconds` | gauge | — (size of the last backwards wall-clock step detected, D21) |
| `tw_nonce_store_errors_total` | counter | `backend` |
| `tw_unsafe_settings_active` | gauge | `name` |
| `tw_legacy_v10_requests_total` | counter | `direction` (`inbound`/`outbound`), `result` |
| `tw_validator_miners_by_protocol` | gauge | `protocol` (`btauth/1`/`v10`) |
| `tw_legacy_v10_days_remaining` | gauge | `direction` |
| `tw_validator_round_duration_seconds` | histogram | — |
| `tw_validator_miner_results_total` | counter | `ok`, `code` |
| `tw_validator_weight_submissions_total` | counter | `ok`, `code` |
| `tw_validator_last_weights_block` | gauge | — |
| `tw_stream_aborted_total` | counter | `side` (`miner`/`validator`), `reason` |
| `tw_timelock_open_total` | counter | `result` (`ok`/`not_ready`/`unavailable`) |
| `tw_tls_pin_failures_total` | counter | — |

Label values never include hotkeys or IPs (cardinality and privacy).

## Appendix C — Golden test vectors

From the Bittensor v11 signed-requests guide.

**Fixtures:** sender `//Alice`, receiver `//Bob` (sr25519 `5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty`), nonce `1752076800000000000`, body `{"prompt": "hello"}` (19 bytes, no trailing newline), request `POST /generate?stream=false`.

`sha256(body)` = `341c57448e531310fbbe83f44cea2a5e838bd9e8a6b82b269f01d0dbbc23c3cc`

**sr25519.** `//Alice` = `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`. Exact signed payload:

```
btauth/1
sr25519
POST
/generate?stream=false
341c57448e531310fbbe83f44cea2a5e838bd9e8a6b82b269f01d0dbbc23c3cc
1752076800000000000
5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
```

sr25519 signatures are randomized: a conforming implementation signs this payload, verifies it against Alice's public key, and verifies signatures produced by other implementations.

**ed25519.** `//Alice` with ed25519 derivation = `5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu`. The payload is identical except line 2 is `ed25519` and line 7 is that address. The signature must be exactly:

```
0x1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704
```

Python helper for pinning: `bittensor.http_auth.build_payload(...)`.

These values were reproduced with `bittensor==11.3.0` on 22 October 2026 (`Keypair.create_from_uri("//Alice", crypto_type=CRYPTO_ED25519).sign(payload)` returns exactly the signature above).

## Appendix D — SS58 address decoding

Needed by the Go and Rust implementations (TS uses `decodeAddress`).

For Bittensor addresses (network prefix 42, a single prefix byte `0x2a`):

1. `raw = base58_decode(address)` (Bitcoin alphabet). Length must be 35 bytes.
2. `prefix = raw[0]`; must equal `42`.
3. `pubkey = raw[1:33]` (32 bytes).
4. `checksum = raw[33:35]`.
5. Expected: `blake2b_512(b"SS58PRE" || raw[0:33])[0:2]`. Must equal `checksum`. Else `MalformedAuth`.

Reject anything else (other prefixes, other lengths). Test with `//Alice` = `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`, whose public key is `0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d`.

## Appendix E — Reference links

Bittensor (v11, current):
- Docs home: https://www.bittensor.com/docs
- Machine-readable index: https://www.bittensor.com/llms.txt
- Signed requests (btauth/1): https://www.bittensor.com/docs/guides/signed-requests
- Migration v9/v10 → v11: https://www.bittensor.com/docs/migration
- Local development: https://www.bittensor.com/docs/guides/local-development
- Mining: https://www.bittensor.com/docs/guides/mining
- Validating: https://www.bittensor.com/docs/guides/validating
- Running a subnet: https://www.bittensor.com/docs/guides/subnets
- Timelock: https://www.bittensor.com/docs/guides/timelock
- Wallets and keys: https://www.bittensor.com/docs/concepts/wallets
- Running a node: https://www.bittensor.com/docs/guides/running-a-node
- Transactions catalog (JSON): https://www.bittensor.com/catalog/intents.json
- Queries catalog (JSON): https://www.bittensor.com/catalog/reads.json
- Errors catalog (JSON): https://www.bittensor.com/catalog/errors.json
- Releases: https://www.bittensor.com/releases
- Monorepo: https://github.com/RaoFoundation/subtensor
- SDK package: https://pypi.org/project/bittensor/
- Testnet stall issue (example of health check): https://github.com/RaoFoundation/subtensor/issues/3230

Related prior art (for comparison, not dependencies):
- Archived v10 template: https://github.com/latent-to/bittensor-subnet-template
- StockTensor (v11 subnet using btauth/1, offline fake-chain tests): https://github.com/stocktensor/stocktensor-subnet
- bittensor-auth (ORO AI; auth only, non-btauth format): https://pypi.org/project/bittensor-auth/
- Fiber (Chutes; own protocol): https://github.com/chutesai/fiber
- btlightning (QUIC transport; own handshake): https://pypi.org/project/btlightning/

Libraries:
- FastAPI https://fastapi.tiangolo.com · uvicorn https://www.uvicorn.org · httpx https://www.python-httpx.org · Pydantic https://docs.pydantic.dev · redis-py https://redis.readthedocs.io
- @polkadot/util-crypto https://polkadot.js.org/docs/util-crypto · Fastify https://fastify.dev
- go-schnorrkel https://github.com/ChainSafe/go-schnorrkel
- schnorrkel https://docs.rs/schnorrkel · ed25519-dalek https://docs.rs/ed25519-dalek · axum https://docs.rs/axum

## Appendix F — Glossary

| Term | Meaning |
|---|---|
| Axon | In v11: the `ip:port` a hotkey published on chain. Not a server object. |
| btauth/1 | Bittensor v11's hotkey-signed HTTP request scheme. |
| Coldkey / hotkey | Money key (offline) / operational key (on servers). |
| Commit-reveal | Weights are hidden (timelocked) when submitted and revealed later by the chain. |
| Fail-closed | When unsure (stale data, store down), reject rather than allow. |
| Metagraph | Snapshot of a subnet's neurons, stakes, permits and axons. |
| Netuid | Subnet number. |
| Nonce | Here: the request's Unix time in nanoseconds; unique per (hotkey, nonce). |
| Permit | Validator permit: allows setting weights that count. |
| Sidecar | Local helper process giving non-Python miners chain access via v11. |
| SS58 | Substrate address format; Bittensor uses prefix 42. |
| Tempo | Blocks per epoch (default 360). |
| twresp/1 | TaoWire's response-signing extension. |
| UID | A neuron's slot number on a subnet. |
| Weights | A validator's scores for miners, submitted on chain. |
