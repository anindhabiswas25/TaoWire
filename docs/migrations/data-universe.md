# Case study: Macrocosmos data-universe (Bittensor subnet 13), a design-partner stand-in

Source: <https://github.com/macrocosm-os/data-universe> at `bb261aa`, MIT licence,
`bittensor==10.3.0`. A public open-source subnet standing in for a design partner
(S7); nobody from the team was involved. The port lives outside this repository
(`~/Project/tensorwire/.ports/data-universe`, git-ignored): none of the subnet's
code is committed here, only these counts and the evidence in
`reports/phase-3/gate-fix/port-data-universe/`.

**Result: S6 = 91 changed lines** (target ≤ 50, spec 1.5), counted as for the
template: `git diff` between the `tensorwire migrate apply` output and the
finished port, subnet code only (tests, scripts and docs left out), without
import lines and removed `# TW-MIGRATE:` markers.

**data-universe is not template-derived.** Its miner and validator are its own
classes on top of v10's `bt.subtensor`, `bt.wallet` and `bt.metagraph`, and
S6 targets template-derived subnets. Most of the 91 lines are its v10 chain
calls (commitments, UID lookups, block hashes, metagraph syncing), not
networking. The number is reported as measured; see "What would lower it".

## What `migrate scan` and `migrate apply` did

With `apply` at eng/build `b7ee321`:

- `scan` (before): 142 files (`scan-before.txt`).
- `apply`: 46 files changed, 739 rewrites, 52 `# TW-MIGRATE:` comments
  (`apply.txt`). TWM007 ×680 (`bt.logging`), TWM001 ×12, TWM004 ×8, TWM003 ×6
  (`bt.axon` → `Axon(miner=TWMiner.from_env())`, imported under an alias because
  the subnet has its own `class Miner`), TWM031 ×10 (config calls and `bt.Config`
  annotations), TWM032 ×10 (`bt.logging` set-up statements), TWM033 ×6
  (`bt.Wallet(config=...)` → v11's constructor), TWM012, TWM021, TWM023, TWM027,
  TWM028.
- TWM031, TWM032 and TWM033 are new: they came from this port (each removed a
  class of hand edits; see "Misses").

## The hand fixes, counted (S6)

| File | +/- | Counted | Why |
|---|---|---|---|
| `common/chain.py` (new) | +54 | 49 | `class Chain`: the calls the subnet made through `bt.subtensor`, on v11 and the kit. `metagraph()` returns `compat.Metagraph` over the kit gateway's snapshot (`S`, `validator_permit`, `axons`, `uids` as v10 shaped them), `get_uid_for_hotkey_on_subnet` / `get_current_block` / `set_weights` go through `BittensorGateway`, `get_block_hash` / `get_commitment` / `set_commitment` / `query_subtensor` through v11's `bt.SyncClient` (commitments are signed by the hotkey) |
| `neurons/validator.py` | +5 / −22 | 19 | the v10 `bt.logging.trace` monkeypatch removed (v11 has no `bt.logging`; 13 lines); `Chain(...)` instead of `bt.Subtensor(config=...)` twice, with the wallet built first; the validator's own axon served in the background (`serve_in_background()`, v10's `start()` did not block) |
| `neurons/miner.py` | +4 / −5 | 7 | `Chain(...)`; `self.axon.miner.serve_in_background()` instead of `self.axon.start()` (the miner's loop and scraper coordinator run after it); the status log's `Emission` field (v11's metagraph data, not in compat) dropped |
| `dynamic_desirability/*.py` | +8 / −11 | 10 | `Chain(network)` instead of `bt.Subtensor(...)` in the commitment reader, uploader and preference store |
| `common/utils.py` | +2 / −13 | 4 | `uid.item()` → `uid` (compat UIDs are ints) |
| `upload_utils/s3_utils.py` | +1 / −3 | 2 | `wallet.get_coldkeypub()` is v11's `wallet.coldkeypub` |
| `common/api_client.py` | import only | 0 | `bittensor_wallet.keypair.Keypair` → `bittensor.keyfiles.Keypair` |
| **Total** | | **91** | |

Left as they are, with their markers: three TWM100 notes on Synapses without
`required_hash_fields` and three TWM104 notes on blacklists. Both are risks of
the v10 wire during the bridge period, not code that has to change. Changing
the hash fields would break the mixed fleet: they are part of the v10 wire
format, which old and new nodes must share (found in the llm-detection fleet).
After the rollout, btauth/1 signs the whole body and they no longer matter.
The tests (`tests/`) were not ported; they mock v10 objects
(`bt.MockSubtensor`, `bt.Metagraph(netuid=1, sync=False)`).

## What was run

- Static: everything compiles, no undefined names (`ruff --select F821`), and
  `scan` reports nothing outside the risk notes in subnet code.
- Imports: `neurons.miner`, `neurons.validator`,
  `dynamic_desirability.desirability_retrieval`, `vali_utils.miner_evaluator`
  and `upload_utils.s3_uploader` import on bittensor 11.3.0 + TensorWire, with
  the subnet's own requirements (except `bittensor==10.3.0`).
- `common/chain.py` against the localnet chain: metagraph (6 UIDs, v10 shape),
  UID lookup, block hash, subnet owner hotkey, and a commitment written with the
  dev `miner_ts` hotkey and read back.
- Their ported miner on localnet (dev `miner_ts`, 127.0.0.4:8097, settings
  from `TW_*`): the kit published the axon, and their `GetMinerIndex` handler
  answered a TensorWire `compat.Dendrite` signed by the dev `validator` hotkey
  over btauth/1 (200, twice).

**Not run:** the validator end to end, and no mixed fleet for this subnet. The
validator needs the Data Universe API and S3 services
(`data-universe-api.api.macrocosmos.ai`) at startup and on every evaluation,
and calling a third party's production service with dev keys is not an
acceptable test. The miner's uploader was pointed at a dead local URL for the
same reason. The mixed-fleet requirement of S6 is met by llm-detection
(`docs/migrations/llm-detection.md`).

## Misses, and what became of each

| Miss | Now |
|---|---|
| `bt.logging.set_info(True)`, `bt.logging.set_debug(True)`, `bt.logging(config=..., logging_dir=...)`, `bt.logging.set_trace(True)` (10 statements) were TWM025, by hand | **TWM032** (auto): bare `bt.logging` set-up statements are removed |
| `bt.Wallet(config=self.config)` (6) was TWM014, by hand | **TWM033** (auto): v11's `bt.Wallet(name=, hotkey=, path=)`; scan treats that v11 shape as v11 |
| `bt.wallet.add_args(parser)` etc. and `bt.config(parser)` were TWM006, by hand | **TWM031** (auto, from the llm-detection port): `add_v10_args`, `compat.config` |
| `config: bt.Config` annotations failed at import on v11 | **TWM031** maps them to compat `Config` |
| `bt.Subtensor(network=...)` is a valid v11 call, so scan does not flag it, but the object is then used with v10 method names (`get_commitment`, `get_uid_for_hotkey_on_subnet`) | limit, documented: scan cannot tell which API an object is used with. The hand port replaces these |
| `uid.item()` on `metagraph.uids` elements (TWM023 covers `metagraph.<v>.item()` only) | limit, documented |
| compat `Axon.start()` blocks, v10's did not | limit, documented (`docs/migration-from-v10.md`): `axon.miner.serve_in_background()` when code runs after `start()` |

## What would lower it

49 of the 91 lines are `common/chain.py`, a small v10-shaped facade over v11
reads. A compat version of it (`tensorwire.compat` offering the v10
`subtensor` reads and writes that template code and subnets like this use)
would remove most of them for every such subnet. That is a product decision
(the compat layer's scope is spec 10b.2-10b.3), so it is a spec question for
the PM, not something this port added on its own.

## Time

About 60 minutes for the hand port and its checks (apply at 19:27, port
committed 19:33 after a first pass on the previous apply from about 18:40),
plus the time to add TWM031-TWM033 to the kit. The engineer is an AI; these
times do not stand for what a human team needs.
