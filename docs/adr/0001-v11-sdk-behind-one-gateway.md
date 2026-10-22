# ADR-0001: The v11 SDK is the only chain client in Python, behind one gateway

- Status: accepted
- Date: 2026-10-22 (Phase 0 findings, Phase 1 implementation)
- Owner: Engineer B
- Spec: Section 7 (ADR-0001), 3, 8.3, 8.5.1. PM decisions D1, D2 and D5 (`.team-shared/GATE-phase-0.md`)

## Context

Bittensor v11 generates its chain layer from runtime metadata, so it follows runtime upgrades without hand-written decoding. Copying or re-implementing any of it would drift from the chain. v11 also releases often, so every place that touches the SDK is a place that can break on an upgrade.

## Decision

1. **One gateway.** All chain reads and writes in the kit go through the `ChainGateway` Protocol in `tensorwire/chain/gateway.py`. The real implementation, `BittensorGateway`, is the only kit module that uses `bittensor` for chain operations. The rest of the kit sees kit-owned, frozen views (`NeuronView`, `MetagraphView`, `TxOutcome`), never SDK types. `testing/fake_chain.FakeChain` implements the same Protocol for tests.
2. **Signing and verification** go through two narrow modules:
   - `auth/*` may import `bittensor.http_auth`, `bittensor.signing` and `bittensor.sp_core` only.
   - `crypto.py` may also import `bittensor.keyfiles` (`Keypair`) and `bittensor.wallet` (`Wallet`). It wraps signing and verification so that an SDK rename touches one file (spec 3.6). This extension was agreed in COORDINATION.md on 2026-10-22.
3. **Enforcement** has two layers (`just lint`, `just test`):
   - import-linter contract "ADR-0001": only `chain.gateway`, `crypto` and `auth.*` import `bittensor` at all.
   - `tests/unit/test_architecture.py`: a per-module allowlist of `bittensor` submodules, including imports inside functions. It covers what import-linter cannot see inside an external package.
4. **Startup check.** `BittensorGateway.connect()` checks that the installed SDK has every symbol and client read it uses. If any is missing it raises `SdkSurfaceError` naming each one and the supported range. `scripts/check_sdk_surface.py` is the full check (spec 3, 18.3).

## Stake units (spec 8.3 open item): findings and decision D2

Measured on localnet (`subtensor-localnet:devnet`, runtime spec_version 482, bittensor 11.3.0) with `scripts/localnet_probe.py`. Evidence: `reports/phase-0/b/localnet-probe.json`.

- `MetagraphNeuron.alpha_stake` is in the subnet's alpha (a `Balance` tagged with the netuid). `tao_stake` is root TAO.
- `MetagraphNeuron.total_stake` is the chain's **stake weight**, `alpha_stake + TaoWeight × tao_stake`, and is also tagged as subnet alpha. Measured: alpha 285.716635065, root TAO 100, TaoWeight 0.05267697 (raw u64 / 2^64). Predicted 290.984332503, reported 290.984332498 (fixed-point rounding). `total_stake.tao` raises `UnitMismatchError`.
- So the spec's "`float(n.total_stake.tao)` if TAO-denominated" never applies on 11.3.0. Converting `total_stake` with the pool price would also be wrong, because the root part was already scaled by TaoWeight.

**Decision D2 (PM, Phase 0 gate):**

```
NeuronView.total_stake_tao = alpha_stake × Metagraph.price + tao_stake
```

- `price` is the pool's **spot** price (`tao_in / alpha_in`). The result is approximate: the TAO value at spot, with no slippage.
- If the price is missing (empty pool), zero, negative or not finite, the alpha part counts as 0, so `min_stake_tao` fails closed.
- On the root subnet (netuid 0) alpha is TAO, so the price is 1.
- `alpha_stake` and `tao_stake` stay raw floats in their own units.
- `TW_MIN_CALLER_STAKE_TAO` means "TAO value at spot price".

Trade-offs that were considered:

- A large swap can move the spot price for a short time. The threshold is a coarse filter (the validator permit is the main gate), and the cache snapshot is minutes old anyway. An attacker who pumps the price for one block gains little and pays real slippage.
- The moving (EMA) price is harder to manipulate, but it is not usable on young subnets (3.4e-07 measured on a fresh localnet subnet against a spot price of 2.6), so it would lock out every caller there.
- The chain's own `StakeThreshold` compares against stake weight, not TAO. Spec Section 2 wording becomes "stake weight (alpha + TaoWeight × root TAO)".

## Other chain facts the gateway depends on

These were verified on localnet in Phases 0 and 1.

- **Protocol tag (D1).** `ServeAxon.protocol` is a **u8**. The kit publishes `TW_PROTOCOL_TAG` (default 87, 0x57) and the gateway refuses values outside 0..255 before signing. It reads the tag back from `Metagraph.raw["axons"][uid]["protocol"]` into `NeuronView.axon_protocol` (D5). The tag is advisory, never a security signal.
- **Addresses.** The chain rejects `ServeAxon` with `127.0.0.1` (`InvalidIpAddress`) but accepts `127.0.0.2` and private ranges. It accepts `0.0.0.0`, which un-serves the axon.
- **Commit-reveal (Phase 1 finding).** When commit-reveal is enabled (the localnet default), `SetWeights` submits a timelocked commit, and the chain reveals it later. The chain **accepted such a commit from a hotkey with no validator permit**: the `SetWeights` outcome was `ok`. So for `set_weights`, `TxOutcome.ok` means "the commit was included", not "the weights apply". `FakeChain`'s `not_authorized` models the plain path. Validators should check `blocks_since_last_update` and their permit themselves (Phase 2). Pinned by `tests/localnet/test_gateway_localnet.py::test_set_weights_commit_without_permit_is_accepted`.
- **Era anchoring.** The SDK anchors a mortal era at the **finalized** head. On fast-block localnets, finality runs 3–8 blocks behind the best block (measured). An 8-block MEV-shield era (`BurnedRegister`) therefore often expires before inclusion, and short forks produce "signature does not match". The kit's own writes (`ServeAxon`, `SetWeights`) are never shielded and use a 128-block era, but they can still hit the fork errors.

## Gateway behaviour (spec 8.3, implemented in Phase 1)

- **One client.** One async `bt.Client` (what `await bt.Subtensor(...)` returns), opened by `connect()` and closed by `close()`.
- **Endpoints.** The endpoint list is `TW_NETWORK` then `TW_CHAIN_FALLBACKS`. If no fallbacks are set, the SDK's public pool is used for `finney`/`test`. After a connection failure or timeout, the client is rebuilt on the next endpoint. The SDK also rotates inside a client.
- **Reads.** Each attempt has a `TW_CHAIN_TIMEOUT_S` timeout. Connection errors, timeouts and node errors are retried 5 times with jittered exponential backoff (0.5 s doubling to 8 s), then the read raises `ChainUnavailable`. An unknown netuid raises `SubnetNotFound`. Other exceptions are bugs and propagate.
- **Writes are never resent blindly.**
  1. Each attempt is first planned (`client.plan`: a dry run, nothing signed). A failed SDK preflight is returned with its own code and nothing is submitted. Example: the weights rate-limit check gives `rate_limited` with "retry in ~N blocks".
  2. A submission that the pool rejected or dropped before inclusion is retried as a **new** extrinsic, signed after the next finalized block, up to 3 attempts. These are the names in `RESIGN_ERROR_NAMES`: `BadProof` ("signature does not match"), `AncientBirthBlock`, `Stale`, `Future`, `PriorityTooLow`, `Invalid`, `Dropped`, `Usurped`. The same design fixes `localnet_up.sh` (gate item F1).
  3. A timeout or connection loss **after** submission returns `code="unknown"` and is not retried, because the transaction may still land. The caller reads chain state first. `Retracted` and `FinalityTimeout` are also returned as is.
  4. Chain-side failures map to `TxOutcome.code` as `bt.ErrorCode` values, unchanged.
- **Logging.** Every write is logged on the `tensorwire.chain` logger with an intent summary, attempt, outcome code, error name and block hash. Hotkeys and signatures are never logged.

## Consequences

- An SDK upgrade is absorbed in `chain/gateway.py`, `crypto.py` and `auth/*`. The rest of the kit and its users see kit types only.
- Policy thresholds in TAO are approximate by design (D2). Documentation must say so.
- `TxOutcome.ok` for `set_weights` under commit-reveal means "committed". Phase 2 validator code must not treat it as "applied".
