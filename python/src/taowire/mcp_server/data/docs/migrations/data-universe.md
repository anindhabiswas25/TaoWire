# Case study: Macrocosmos data-universe (Bittensor subnet 13), a design-partner stand-in

Source: <https://github.com/macrocosm-os/data-universe> at `bb261aa`, MIT licence,
`bittensor==10.3.0`. A public open-source subnet standing in for a design partner
(S7); nobody from the team was involved. The port lives outside this repository
(a git-ignored checkout): none of the subnet's code is committed here, only these
counts.

**Result: S6 = 24 changed lines** (target ≤ 50, spec 1.5 with D18), counted as
for the template: `git diff` between the `taowire migrate apply` output and
the finished port, subnet code only (tests, scripts and docs left out), without
import lines and removed `# TW-MIGRATE:` markers. Phase 3 measured **91**; the
difference is `compat.Subtensor` (spec 10b.2.6, D34) and the TWM008 rewrite onto
it.

**data-universe is not template-derived.** Its miner and validator are its own
classes on top of v10's `bt.subtensor`, `bt.wallet` and `bt.metagraph`, and
S6 targets template-derived subnets, so this number is reported, not gated
(D24).

## What `migrate scan` and `migrate apply` did

With `apply` as of Phase 4 (WP7):

- `scan` (before): 142 files, 788 findings (748 auto, 34 manual, 6 risk).
- `apply`: 46 files changed, 754 rewrites, 40 `# TW-MIGRATE:` comments.
  TWM007 ×680 (`bt.logging`), **TWM008 ×15** (new: `bt.Subtensor(config=...)`
  and `bt.Subtensor(network=...)` → `compat.Subtensor`, plus `bt.Subtensor`
  annotations), TWM001 ×12, TWM031 ×10, TWM032 ×10, TWM004 ×8, TWM003 ×6,
  TWM033 ×6, TWM021 ×2, TWM023 ×2, TWM012, TWM027, TWM028.
- `scan` after `apply`: 40 findings (0 auto, 34 manual, 6 risk); 20 of the
  manual ones are TWM009 notes on code that works on compat as it is.

## The hand fixes, counted (S6)

The diff from the `apply` output to the finished port, counted with the
template's counter (`examples/migrations/template-v10-to-v11/golden.py`).

| File | +/- | Counted | Why |
|---|---|---|---|
| `neurons/validator.py` | +1 / −16 | 13 | the v10 `bt.logging.trace` monkeypatch removed (v11 has no `bt.logging`; 11 lines); the validator's own axon served in the background (`serve_in_background()`; v10's `start()` did not block) |
| `neurons/miner.py` | +2 / −3 | 5 | `self.axon.miner.serve_in_background()` instead of `self.axon.start()` (the miner's loop and scraper run after it); the status log's `Emission` field (v11 metagraph data, not in compat) dropped |
| `common/utils.py` | +2 / −11 | 4 | `uid.item()` → `uid` (compat UIDs are ints); the rest are markers |
| `upload_utils/s3_utils.py` | +1 / −2 | 2 | `wallet.get_coldkeypub()` is v11's `wallet.coldkeypub` |
| `common/api_client.py` | import only | 0 | `bittensor_wallet.keypair.Keypair` → `bittensor.keyfiles.Keypair` |
| 6 more files | markers only | 0 | |
| **Total** | | **24** | |

Gone compared with Phase 3: `common/chain.py` (49 lines, a hand-written v10
`subtensor` facade) and the 18 lines around the `Chain(...)` call sites (in the neurons
and `dynamic_desirability/*`). `apply` now writes `Subtensor(config=...)` /
`Subtensor(network=...)` and the subnet's own calls (`metagraph`,
`get_uid_for_hotkey_on_subnet`, `get_commitment`, `set_commitment`,
`get_block_hash`, `get_current_block`, `is_hotkey_registered`,
`query_subtensor("SubnetOwnerHotkey", ...)`, `set_weights`) run unchanged.

Left as they are, with their markers: three TWM100 notes on Synapses without
`required_hash_fields` and three TWM104 notes on blacklists. Changing the hash
fields would break the mixed fleet (D28, `docs/migration-rollout.md`); after
the rollout btauth/1 signs the whole body. The tests (`tests/`) were not ported;
they mock v10 objects (`bt.MockSubtensor`, `bt.Metagraph(netuid=1, sync=False)`).

## What was run

- Static: everything compiles, no undefined names (`ruff --select F821`), and
  `scan` reports nothing outside the risk notes and TWM009 notes in subnet code.
- Imports: `neurons.miner`, `neurons.validator`, `common.utils`,
  `common.metagraph_syncer`, `dynamic_desirability.{chain_utils,desirability_retrieval,desirability_uploader}`,
  `vali_utils.miner_evaluator` and `upload_utils.s3_uploader` import on
  bittensor 11.3.0 + TaoWire with the subnet's own requirements.
- Their chain code on localnet: the subnet
  owner hotkey (`get_subnet_owner_hotkey` → `query_subtensor`), their
  `ChainPreferenceStore.store_preferences` (a commitment written with the dev
  `miner_ts` hotkey, from their `fork` worker) and their
  `_sync_retrieve_metadata` reading it back: equal. The first run of this
  check found that `compat.Subtensor` hung in a forked child (fixed in Phase 4:
  in a forked child the facade starts its own loop thread and connections).
- Their ported miner on localnet (dev `miner_ts`, 127.0.0.4:8097, settings
  from `TW_*`): the kit published the axon, and
  their `GetMinerIndex` handler answered a TaoWire `compat.Dendrite` signed
  by the dev `validator` hotkey over btauth/1.

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
| `bt.logging` set-up statements (10) by hand | **TWM032** (auto, Phase 3) |
| `bt.Wallet(config=self.config)` (6) by hand | **TWM033** (auto, Phase 3) |
| `bt.wallet.add_args(parser)`, `bt.config(parser)`, `config: bt.Config` | **TWM031** (auto, Phase 3) |
| v10 `subtensor` reads and commitments: a 49-line hand facade | **`compat.Subtensor`** (10b.2.6, D34) and **TWM008** (auto): `bt.subtensor(...)`, `bt.Subtensor(config=...)` and annotations |
| `bt.Subtensor(network=...)` is a valid v11 call, but here it is used with v10 method names | **TWM008** (auto) when the file also calls a method v11's client lacks (`get_commitment`, `get_uid_for_hotkey_on_subnet`, ...) |
| v10 writes `compat.Subtensor` does not perform (stake, transfer, register, ...) | **TWM036** (manual, names the v11 replacement); the facade raises `NotImplementedError` with the same text. data-universe makes none |
| `uid.item()` on `metagraph.uids` elements (TWM023 covers `metagraph.<v>.item()` only) | limit, documented (4 lines here) |
| compat `Axon.start()` blocks, v10's did not | limit, documented (`docs/migration-from-v10.md`): `axon.miner.serve_in_background()` when code runs after `start()` (3 lines here) |
| their `bt.logging.trace` monkeypatch | manual (TWM025): v11 has no `bt.logging`; 11 lines here |

## What would lower it further

13 of the 24 lines are the `bt.logging.trace` monkeypatch, a workaround for a
v10 log message that v11 does not print; removing it is the right port, and a
rule that deletes arbitrary assignments to `bt.logging` attributes would be
guessing. A non-blocking `Axon.start()` option would save the 2 `start()`
lines, but changes compat's documented behaviour; not done.

## Time

About 15 minutes for the hand port on top of `compat.Subtensor` and the
checks above, plus the time to build `compat.Subtensor`, TWM008 (auto),
TWM035 and TWM036 in the kit. The engineer is an AI; these times do not stand
for what a human team needs.
