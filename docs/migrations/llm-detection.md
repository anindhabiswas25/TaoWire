# Case study: It's AI llm-detection (Bittensor subnet 32), a design-partner stand-in

Source: <https://github.com/It-s-AI/llm-detection> at `37dcb27` (2026-07-23),
MIT licence, `bittensor==10.5.0`. A public open-source subnet standing in for a
design partner (S7); nobody from the team was involved. The port lives outside
this repository (`~/Project/tensorwire/.ports/llm-detection`, git-ignored): none
of the subnet's code is committed here, only these counts, the launcher and
fleet driver, and the evidence in `reports/phase-3/gate-fix/port-llm-detection/`.

**Result: S6 = 8 changed lines** (target ≤ 50, spec 1.5 with D18: the subnet's
own customised `detection/base/*` and `detection/utils/config.py` are counted),
and the mixed fleet ran on localnet: the unported subnet on bittensor 10.5.0
next to its port, every validator querying every miner, weights revealed (see
"Mixed fleet").

## History of the number

The first port (Phase 3, `apply` at that time) reported S6 = 21 and left out the
subnet's own bases and config as "framework". Spec 1.5 counts them (D18). Counted
that way, the first port was **691** lines: the hand rewrite of the three
customised bases (670) plus 21. The answer was to make `migrate apply` do that
work (D18: "the answer is a migrate rule or compat helper, not a narrower
count"):

- **TWM026 (auto now): the customised-base swap.** `apply` puts
  `BaseMinerNeuron` / `BaseValidatorNeuron` on `TemplateMinerAdapter` /
  `TemplateValidatorAdapter`, removes the methods the kit runs (run loops,
  threads, `serve_axon`, `set_weights`) and the `__init__` statements that built
  the wallet, subtensor, metagraph, dendrite and axon, and keeps every method the
  subnet wrote.
- **compat gives those kept methods the template surface they use**
  (`docs/migration-from-v10.md`): a hotkey-only `self.wallet`, a read-only
  `self.subtensor`, `sync()` in the template's order, a pinned `self.metagraph`
  that moves on `metagraph.sync()` (their `resync_metagraph` compares a deep copy
  before and after), v10's `bt.config` behaviour (a missing option reads as
  `None`), the chain readable in `__init__`, and `with Miner() as miner:` serving
  in the background. New: `compat.TemplateMinerAdapter` (allowed by the PM).
- **TWM031 (auto): v10 config calls** (`bt.wallet.add_args(parser)`,
  `bt.config(parser)`, `bt.logging.check_config(...)`, `bt.Config` annotations).

## What `migrate scan` and `migrate apply` did

With `apply` at eng/build `b7ee321` (`scan-before.txt`, `apply.txt`):

- 89 files read, 28 changed, 154 rewrites, 14 `# TW-MIGRATE:` comments.
- TWM007 ×125, TWM001 ×5, TWM013 ×4, TWM023 ×4, TWM026 ×3 (the three bases),
  TWM028 ×3, TWM031 ×6, TWM003, TWM004, TWM021, TWM027 (their 90-minute
  `time.sleep` at the end of the async `forward`).
- In subnet code, `apply` left: a TWM026 note on each swapped base listing the
  removed methods, two TWM009 notes on `self.metagraph.sync(...)` (which works on
  compat: deleting the note is all), and one TWM100 risk note. The rest are in
  `prompting/` (vendored mocks the neurons never import) and the template's v10
  tests.

## The hand fixes, counted (S6)

`reports/phase-3/gate-fix/port-llm-detection/hand-fixes.patch`, counted with the
template's counter (`s6.txt`): added + removed lines, without import lines and
removed `# TW-MIGRATE:` markers.

| File | +/- | Counted | Why |
|---|---|---|---|
| `detection/base/validator.py` | +4 / −4 | 5 | their stake filter on v11: `bt.SyncClient(...).staking.stake_for_coldkeys(...)` instead of v10's `subtensor.get_stake_info_for_coldkey(...)`, and `.stake.alpha` instead of `.stake.tao` (v11 raises on `.tao` for alpha). SDK change, not networking |
| `requirements.txt` | +2 / −1 | 3 | `tensorwire`; `bittensor>=11.3.0,<12` instead of `==10.5.0` |
| `detection/base/miner.py` | markers only | 0 | |
| **Total** | | **8** | |

Their `forward`, `blacklist`, `priority`, reward, scoring, encryption, stake
filter logic, per-miner counters, version checks, wandb logging and both
`neurons/*.py` entry points are unchanged apart from what `apply` rewrote.

**Not changed on purpose: TWM100.** `TextSynapse` has no
`required_hash_fields`, so a v10 signature covers none of its fields. Adding them
in the port broke the mixed fleet in both directions (`tw.legacy_auth_failed`
on the TensorWire miner, "Hash mismatch between header body hash and parsed body
hash" on the v10 Axon): the hash fields are part of the v10 wire format, which
old and new nodes must share. Fix it in a release both sides take, or drop it:
after the rollout btauth/1 signs the whole body and the v10 wire is gone. This
is now in the case study and in the rollout guidance.

## Mixed fleet (spec 1.5, 13.8)

Localnet netuid 2, dev wallets only. `fleet.py` starts four processes through
`launch.py` and checks every cell from the nodes' own metrics and logs, and the
weights from the chain:

| Validator ↓ / Miner → | v10 miner (37dcb27, bittensor 10.5.0, `miner_go`, 127.0.0.3:8093) | TensorWire miner (the port, `miner_py`, 127.0.0.2:8092) |
|---|---|---|
| v10 validator (37dcb27, `owner`) | their v10 Axon admits the v10 validator (their `priority` trace line per request) | v10 bridge, inbound (`tw_legacy_v10_requests_total{direction="inbound",result="ok"}`) |
| TensorWire validator (the port, `validator`) | v10 bridge, outbound (`...{direction="outbound",result="ok"}`) | btauth/1 with twresp/1 verified (`round ok` `n_btauth`) |

**Result (run 6, 12 s-block localnet, blocks 80-154, `fleet-run6-12s-PASS/`):
PASS.** Answered requests per cell when the driver stopped: TensorWire
validator → TensorWire miner 164 btauth/1 rounds; TensorWire validator → v10
miner 319 v10 requests; v10 validator → TensorWire miner 355; v10 validator →
v10 miner 335. Weights revealed (`TimelockedWeightsRevealed`, commit-reveal on)
for both validators, each over both miners: the v10 validator (`owner`) at
block 144, `[[2, 64266], [4, 65535]]`; the TensorWire validator at block 154,
`[[2, 65535], [4, 65535]]`. All four nodes were alive until the driver
stopped them (exit −2 = SIGINT).

**What was stubbed (model boundary only, `launch.py`):** the miner's detection
models (`PPLModel`, `DebertaClassifier`: multi-GB transformer models) answer a
fixed probability per text; the validator's challenge generator (`DataGenerator`
with Ollama LLMs and datasets) returns fixed human and AI texts with word labels;
the text attacks (`DataAugmentator`, fastText / WordNet) are the identity.
Everything else is the subnet's code: protocol, encryption of predictions,
blacklist and priority, the validator's query, retry and decrypt path, the
reward and scoring code with its out-of-domain split, the stake filter (on v11
for the port, v10 for the original), and weight setting.

**Test configuration, not code:** their forward sleeps until 90 minutes have
passed (`EPOCH_MIN_TIME`); the launcher sets 5 s. wandb runs disabled. Their
version check fetches `detection/__init__.py` from GitHub; the launcher answers
that one URL with the checkout's own file (a DNS hiccup stopped one run). CLI
flags: `--neuron.vpermit_tao_limit 1000000000` (localnet validators hold far
more stake than 4096, and their uid filter would otherwise skip every miner),
`--blacklist.minimum_stake_requirement 0` on the miners, `--neuron.axon_off` and
`--neuron.epoch_length 10` on the v10 validator. The TensorWire nodes take their
settings from `TW_*` (`fleet.py` lists them).

**Fast blocks vs the unported validator.** On the 0.25 s-block localnet the v10
validator's commits were accepted but never revealed: v10's `set_weights`
computes the reveal round for 12 s blocks unless it is given `block_time`, and
their code does not pass it (finding 14.2 from the template fleet). The
TensorWire validator's weights were revealed on fast blocks
(`fleet-run5-fast-blocks/`). The final run used the 12 s-block localnet, where
v10's assumption holds.

Runs that did not count, kept as evidence: run 2 (the chain's drand feed was
rate-limited, HTTP 429), runs 3-4 (a leftover node from a smoke test held the
metrics port; then the drand feed stalled again and the node ran out of WASM
instances, partly from the first driver scanning every block's events; the
driver now reads `Weights` at the head), run 5 (fast blocks, above).

## Misses, and what became of each

| Miss | Now |
|---|---|
| Customised bases were hand-ported (670 lines under D18) | **TWM026 auto** + the compat template surface |
| `bt.wallet.add_args(parser)` etc., `bt.config(parser)`, `bt.Config` annotations by hand | **TWM031** |
| Their `resync_metagraph` compares `copy.deepcopy(self.metagraph)` before and after `sync()`; a live view made it a no-op | compat `Metagraph` pinned mode (moves on `sync()`), used by both adapters |
| Their miner reads `config.neuron.disable_set_weights`, which only validators define; v10's `bt.config` returned `None` | compat `Config` reads a missing option as `None` |
| `BaseNeuron.__init__` checks registration and reads the UID before the miner serves | the miner adapter reads one metagraph snapshot before it serves |
| `with Miner() as miner:` and `with Validator() as v:` | both adapters serve in the background with SIGTERM handling |
| The TWM100 fix broke the mixed fleet | documented: hash fields change only with all peers, or after the rollout |
| v10 `set_weights` on fast blocks never reveals | not the kit's; runs that need v10 reveals use 12 s blocks |
| Their stake filter uses v10 SDK reads | hand fix (v11's own migration, spec 3) |

## Limits

- `prompting/` is vendored data-generation code from another subnet with v10
  mocks; nothing in the miner or validator imports it. It keeps its markers.
- The template's v10 tests (`tests/`) were not ported.
- The removed `__exit__` / `stop_run_thread` finished the wandb run; on the kit,
  wandb's own exit hook finishes it.

## Time

The kit work behind this result (compat surface, `TemplateMinerAdapter`, the
TWM026 swap, TWM031) took about 2.5 hours; the port itself, once `apply` could
do it: `apply` at 17:54, hand fixes committed at 19:00, most of that hour spent
on the mixed fleet (environments, launcher) and on the misses above. With the
final `apply` the hand fixes are 8 lines. The engineer is an AI; these times do
not stand for what a human team needs.
