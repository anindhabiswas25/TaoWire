# Case study: the archived v10 subnet template

Source: <https://github.com/latent-to/bittensor-subnet-template> at
`539b77c` (MIT), copied unmodified to
`examples/migrations/template-v10-to-v11/before/`. The port is in `after/`.

**Result: S6 = 17 changed lines of subnet code** after `tensorwire migrate
apply` (target ≤ 50, spec 1.5). The template's miner (`forward`,
`blacklist`, `priority`) and validator (`forward`, `reward`) run on
TensorWire with their logic unchanged. `after/` runs on localnet from `TW_*`
variables alone (`reports/phase-3/a/after-localnet/`): rounds over
btauth/1, weights committed with `TW_WEIGHTS_VERSION_KEY`, and
`tensorwire migrate status` reading both nodes. The mixed-fleet localnet
walk-through (v10 and TensorWire nodes, rollout stages 1-4) is Engineer B's
evidence in `reports/phase-3/b/`.

## How it is built (golden test, spec 13.8)

`after/` is exactly `before/` + `tensorwire migrate apply` +
`hand-fixes.patch`. `python/tests/migration/test_template_golden.py` checks
this byte for byte, and checks that a second `apply` changes nothing.
`examples/migrations/template-v10-to-v11/golden.py s6` prints the count
below, and `golden.py write` rebuilds the patch after `apply` or `after/`
changes.

## What `migrate apply` did on its own

35 files read, 22 changed: 179 rewrites, 57 `# TW-MIGRATE:` comments.

| Rule | Rewrites | What |
|---|---|---|
| TWM007 | 138 | `bt.logging.info/trace/...(...)` → `logging.info/debug/...(...)` |
| TWM003 / TWM004 | 7 / 6 | `bt.axon(...)` → `Axon(miner=Miner.from_env())`, `bt.dendrite(wallet=w)` → `Dendrite(signer=RequestSigner(w))` |
| TWM001 / TWM021 | 7 / 2 | `bt.Synapse`, `bt.TerminalInfo`, `bt.AxonInfo` → `tensorwire.compat` |
| TWM013 | 6 | `[self.metagraph.axons[uid] for uid in uids]` → `axons_from(self.metagraph, uids)` |
| TWM023 | 3 | `self.metagraph.n.item()` → `self.metagraph.n` |
| TWM012 | 2 | `process_weights_for_netuid(uids=u, weights=w, ...)` → `(u, w)` |
| TWM024 | 2 | `from template.base.validator import BaseValidatorNeuron` → `from tensorwire.compat import TemplateValidatorAdapter as BaseValidatorNeuron` (the template's base is stock) |
| TWM027 | 2 | `time.sleep(5)` in `async def forward` → `await asyncio.sleep(5)`. The template's own bug, and it matters now: the kit's health endpoints share the event loop |

`import bittensor as bt` is removed wherever nothing uses `bt` any more, and
the new imports take its place. String annotations such as
`"bt.metagraph.Metagraph"` become `"Metagraph"` (TWM028, 4 of them).

The 57 comments mark what a person has to do: `bt.subtensor` /
`bt.wallet` / `bt.metagraph` / `bt.config` and `bt.axon.add_args` in the template's framework and
in `docs/stream_tutorial/`, the v10 mocks, `bt.logging.set_config`, the
mixed-fleet limit of the `StreamingSynapse` tutorial (TWM034: streaming is
TensorWire to TensorWire only; since Phase 4 `apply` ports the class itself,
TWM002), and the two security findings
(`Dummy` has no `required_hash_fields`, TWM100; `force_validator_permit`
defaults to `False`, TWM103).

## The hand fixes, counted (S6)

Counted as in spec 1.5 (D15): `git diff` between the `apply` output and the
final port, subnet code only. Import lines and the removal of `apply`'s own
`# TW-MIGRATE:` markers do not count. Added and removed lines both count.

| File | +/- | Counted | Why |
|---|---|---|---|
| `neurons/miner.py` | +3 / −7 | 9 | `Miner().run()` replaces v10's `with Miner() as miner: while True: sleep`. `miner=` pass-through for the in-process test |
| `neurons/validator.py` | +2 / −2 | 4 | `**kit_parts` pass-through for the in-process test |
| `template/protocol.py` | +3 / −1 | 3 | `required_hash_fields = ("dummy_input",)` (TWM100), plus a comment line and a blank line |
| `requirements.txt` | +1 | 1 | `tensorwire` |
| `template/__init__.py` | −1 | 0 | `from . import api` (an import line) |
| **Total** | | **17** | |

Six of the 17 lines are test plumbing. Without the in-process test the port
would be 11 lines.

Reported separately, not hidden:

- **Template framework** (`template/base/`, `template/utils/config.py`,
  `template/mock.py`, `template/api/`): 1,147 counted lines. Almost all of
  it is deleting files the kit replaces: `base/validator.py` (now
  `TemplateValidatorAdapter`), `base/utils/weight_utils.py`, `mock.py`,
  `api/`. The written code is `base/miner.py` (12 lines),
  `base/neuron.py` (8) and `utils/config.py` (21 added, 25 removed). There is
  no miner-side adapter yet, so the miner base still needs this small hand
  port in every template-derived subnet (see "Limits").
- **Tests**: the template's v10 mock tests are deleted (`tests/helpers.py`,
  `test_mock.py`, `test_template_validator.py`, which were placeholders) and
  `tests/test_template_on_tensorwire.py` (70 lines) runs the miner and the
  validator in process on `FakeChain`.

Phase 2's hand port without `apply` was 41-68 lines of subnet code, 32 of
them logging.

## What the kit gained from this port

- Phase 2: `compat.Metagraph` (+ `of_miner`), per-call `timeout_s`, rules
  TWM021-023.
- Phase 3: `compat.TemplateValidatorAdapter` (the template's validator base
  on the kit's runner: schedule, score store, weights with
  `TW_WEIGHTS_VERSION_KEY`, v10 fallback, `/metrics`), `migrate apply`, rule
  TWM024 (the swap) and TWM025 (`bt.logging` configuration, by hand), and
  `axons_from` accepting a `compat.Metagraph`. `configure_logging` now drops
  the handler that a module-level `logging.info()` silently adds before the
  kit configures logging. Ported code does that, and every line was being
  printed twice.

## Behaviour that changed (TemplateValidatorAdapter)

Scoring keeps the template's semantics (`self.scores`, its moving average,
unqueried miners decay, replaced hotkeys zeroed). What changed:

- Steps start at most every `TW_ROUND_INTERVAL_S`. Weights follow the
  chain's rate limit and `TW_MIN_WEIGHT_INTERVAL_BLOCKS`, not
  `neuron.epoch_length`.
- The moving-average alpha is `TW_SCORE_ALPHA`.
- Scores and the step count persist in `TW_STATE_DIR`
  (`save_state` / `load_state` do nothing).

## Limits (not covered by a rule, by design)

- The miner side of the template framework (`template/base/miner.py`,
  `neuron.py`) is ported by hand. `apply` rewrites `bt.axon` there and marks
  `bt.wallet` / `bt.subtensor` / `bt.metagraph`. A `TemplateMinerAdapter`
  would remove this step (open question for the PM).
- v10's `with Miner() as miner:` main loop: the kit's miner runs in the
  foreground (`Miner().run()`).

## Time

`migrate apply` runs in under a second on this repository. The hand fixes
were made by Engineer A (an AI engineer) in Phase 2 and adjusted in Phase 3;
the wall-clock time is not a measure of what a human team needs. The
design-partner case studies (S7) record what scan/apply missed on code
nobody here wrote.
