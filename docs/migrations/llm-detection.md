# Case study: It's AI llm-detection (Bittensor subnet 32), a design-partner stand-in

Source: <https://github.com/It-s-AI/llm-detection> at `37dcb27` (2026-07-23),
MIT licence, `bittensor==10.5.0`. It's a public open-source subnet standing
in for a design partner (S7). Nobody from the team was involved. The port
lives outside this repository (`~/Project/tensorwire/.ports/`, git-ignored):
none of the subnet's code is committed here, only these counts.

**Result: S6 = 21 changed lines of subnet code** after `tensorwire migrate
apply` (target ≤ 50, spec 1.5). On FakeChain, in process, their real miner
(`forward` / `blacklist` / `priority`, end-to-end encrypted predictions)
answers their real validator path (`dendrite_with_retries`,
`_decrypt_responses`, their `update_scores` with a counter-dependent alpha)
over btauth/1. The kit then sets weights with `TW_WEIGHTS_VERSION_KEY`.
Their stake filter, ported to the v11 reads, gives the same answer as an
independent read of the localnet chain. Evidence:
`reports/phase-3/a/port-llm-detection/`.

## Why this subnet

Template-derived (`detection/base/{neuron,miner,validator}.py`), with the
customisations a real team makes: its own validator base (a stake filter
over coldkey stake, per-miner counters with an early alpha, version checks
against GitHub, wandb logging signed with the hotkey), one Synapse with
end-to-end encryption, and its own command-line options. Engineer B ports
macrocosm-os/data-universe. I first checked trajectoryRL (MIT), but it has
no Synapse, axon or dendrite, so it has nothing to migrate.

## What `migrate scan` and `migrate apply` did

- `scan` (before): 89 files, 202 findings, template shape detected.
- `apply`: 28 files changed, 182 rewrites, 23 `# TW-MIGRATE:` comments.
  The rewrites: TWM007 ×157 (`bt.logging`), TWM003 ×5, TWM004 ×3, TWM001
  ×5, TWM013 ×4, TWM023 ×4, TWM012 ×2, TWM021 ×1, and TWM027 ×1 (their
  90-minute `time.sleep` at the end of the async `forward`, which would have
  stopped the kit's health endpoints for 90 minutes).
- `apply` did **not** swap their `BaseValidatorNeuron` for the adapter. It
  added TWM026 instead: "keep your additions: make your BaseValidatorNeuron
  subclass TemplateValidatorAdapter".
- `scan` after the port: 4 findings, all in `prompting/mock.py`, vendored
  code from another subnet that the miner and validator never import (see
  "Limits").

## The hand fixes, counted (S6)

Counted as for the template (`golden.py` counter): `git diff` between the
`apply` output and the finished port. Import lines and removed `# TW-MIGRATE:`
markers don't count.

| File | +/- | Counted | Why |
|---|---|---|---|
| `neurons/miner.py` | +3 / −6 | 9 | `Miner().run()` instead of the v10 `with Miner() as miner:` loop. `miner=` pass-through for the in-process test |
| `detection/protocol.py` | +6 / −1 | 5 | `required_hash_fields = ("texts", "predictions", "version", "enc_pubkey")`: the Synapse had none, so a v10 signature covered no field (TWM100) |
| `neurons/validator.py` | +2 / −3 | 4 | `**kit_parts` pass-through for the in-process test |
| `requirements.txt` | +2 / −1 | 3 | `tensorwire`; `bittensor>=11.3.0,<12` instead of `==10.5.0` |
| **Total** | | **21** | |

Their `forward`, `blacklist`, `priority`, reward and scoring code is unchanged
apart from what `apply` rewrote.

Reported separately:

- **Framework** (`detection/base/*`, `detection/utils/config.py`): 111 lines
  written, 613 deleted (670 counted).
  - `base/validator.py` now subclasses `TemplateValidatorAdapter`. It keeps
    their `update_scores`, `new_wandb_run`, `log_step` verbatim, a
    `resync_metagraph` with their counter rule, and the stake filter on the
    v11 reads (`client.staking.stake_for_coldkeys`, `.alpha`).
  - `base/miner.py` and `base/neuron.py` are the template's kit-based bases
    plus their additions: the blacklisted-hotkey set, and the version check
    re-read once per epoch on a background thread instead of inside `sync()`.
  - `utils/config.py` is plain `argparse`, with wallet, chain and axon
    settings from `TW_*`.
- **Tests**: the template's two v10 placeholder tests deleted (270 lines).

## Misses, and what became of each

| Miss | Now |
|---|---|
| A customised `BaseValidatorNeuron` was swapped for the adapter, dropping its methods | `apply` swaps only a stock base. A customised one gets **TWM026** listing the added methods. A base that already subclasses the adapter counts as ported (no finding) |
| `self.metagraph.S[uid].item()` was missed (only `metagraph.n.item()` was covered) | **TWM023** also matches subscripted values |
| `bt.logging.info("raw_weights", w)` was rewritten to `logging.info("raw_weights", w)`, which `logging` treats as %-format arguments | **TWM007** keeps v10's text: `logging.info("%s - %s", w, "raw_weights")` |
| `bt.Axon.add_args(parser)` became `Axon.add_args(parser)`, which doesn't exist | `apply` leaves `bt.<X>.add_args` / `check_config` alone (**TWM006**, by hand) |
| `time.sleep` in a coroutine (also in the template) | **TWM027** (auto): `await asyncio.sleep(...)` |
| `compat.Dendrite` failed on a `Field(..., allow_mutation=False)` request field (frozen in pydantic v2) | compat fix: frozen fields keep the request's value, as v10 did. Regression test in `test_compat_layer.py` |
| The adapter's `update_scores` replaced `self.scores` with the kit's EMA, so a subclass couldn't keep its own scoring | `TemplateValidatorAdapter` now keeps the template's `self.scores` semantics and copies the scores to the kit's store each step. The subnet's own `add_args` options are honoured |

## Limits (documented, not rules)

- **v11 SDK changes outside networking.** `subtensor.get_stake_info_for_coldkey`
  is `client.staking.stake_for_coldkeys` in v11, and `.stake.tao` on alpha
  raises `UnitMismatchError` (use `.alpha`). These are the SDK's own migration
  (spec 3.3-3.4), not the kit's. `scan` doesn't flag every v11 read change.
- **`prompting/`** is vendored data-generation code from another subnet,
  including v10 mocks (`MockSubtensor`, a `bt.Dendrite` subclass). Nothing
  in the miner or validator imports it. It keeps its `# TW-MIGRATE:` markers.
- **Not exercised here:** the Ollama models, dataset generation and the
  DeBERTa / perplexity miners (tens of GB of models). The test stubs exactly
  those, plus wandb. The networking, signing, encryption, scoring, store and
  weight path is the subnet's real code.
- No mixed-fleet localnet run for this subnet: the template's mixed-fleet
  walk-through (Engineer B) covers the bridge.

## Time

Clone at 12:15, port finished at 13:30 (2026-10-23): about 75 minutes. That
includes finding the misses above and fixing them in the kit. The last
`apply` plus the hand fixes took 7 minutes. Engineer A is an AI engineer;
these times do not stand for what a human team needs.
