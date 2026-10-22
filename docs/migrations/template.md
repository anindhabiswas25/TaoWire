# Case study: the archived v10 subnet template

Source: <https://github.com/latent-to/bittensor-subnet-template> at
`539b77c` (MIT), copied unmodified to
`examples/migrations/template-v10-to-v11/before/`. Ported by hand to
`tensorwire.compat` in `after/` (Phase 2; `migrate apply` arrives in Phase 3).

**Result:** the template's miner (`forward`, `blacklist`, `priority`) and
validator (`forward`, `reward`, `update_scores`, `set_weights`) run on
TensorWire. `after/tests/test_template_on_tensorwire.py` starts both in
process on FakeChain: the validator queries the miner over btauth/1, scores
the answer (EMA 0.1 after one step), and the second step submits weights.
`python/tests/migration/test_template_port.py` runs that test and re-scans
the port.

## What `migrate scan` reported on `before/`

35 files, 212 findings: 28 auto, 182 manual, 2 risk. Template shape
detected. The two risks:

- `template/protocol.py` TWM100: `Dummy` has no `required_hash_fields`, so a
  v10 signature covers none of its fields.
- `template/utils/config.py` TWM103: `--blacklist.force_validator_permit`
  defaults to `False`.

Most manual findings are `bt.logging` calls (TWM007, 146 of them, many in
`docs/stream_tutorial/`, which this port leaves alone: streaming is Phase 4).

## What changed

Subnet code (what a team wrote on top of the template):

| File | +/- lines | Change |
|---|---|---|
| `template/protocol.py` | +5 / −2 | `compat.Synapse`; `required_hash_fields = ("dummy_input",)` (TWM100) |
| `neurons/miner.py` | +10 / −14 | `bt.logging` → `logging`; `Miner().run()`; `miner=` pass-through |
| `neurons/validator.py` | +5 / −9 | same, `Validator().run()` |
| `template/validator/forward.py` | +5 / −5 | `bt.logging` → `logging`; `await asyncio.sleep(5)` instead of `time.sleep(5)` in the coroutine |
| `template/validator/reward.py` | +2 / −2 | `bt.logging` → `logging` |
| `template/utils/uids.py` | +4 / −3 | type hint; `metagraph.n` is an int (TWM023) |
| `template/__init__.py` | −1 | no `api` module |
| `requirements.txt` | +1 | `tensorwire` |

That is 68 lines touched (32 added, 36 removed; 41 if each changed line is
counted once). 32 of them are `bt.logging` lines (and the `bittensor` imports they needed) that `migrate apply`
(Phase 3) is meant to rewrite. `forward`, `blacklist`, `priority` and
`reward` logic is unchanged.

The template's framework (`template/base/*`, `template/utils/config.py`) was
rewritten onto the kit, not edited:

| File | +/- lines | Now |
|---|---|---|
| `template/utils/config.py` | +21 / −17 | plain `argparse` for the template's own options; wallet, chain and axon options are `TW_*` |
| `template/base/neuron.py` | +13 / −110 | config only; the kit loads the hotkey, connects, checks registration |
| `template/base/miner.py` | +16 / −138 | `compat.Axon(miner=Miner.from_env())`; `Metagraph.of_miner` for `self.metagraph` |
| `template/base/validator.py` | +132 / −225 | the template's loop kept; `compat.Dendrite`, the kit's gateway and `MetagraphCache`, `WeightScheduler` for `set_weights` |

Deleted, because v11 has no equivalent and the kit provides one:
`template/mock.py` and `tests/helpers.py`, `tests/test_mock.py`,
`tests/test_template_validator.py` (v10 `MockSubtensor` / `MockWallet` →
TensorWire's FakeChain and fixtures; the template's own validator tests were
placeholders), `template/api/*` (`SubnetsAPI` is gone; call the subnet with
`compat.Dendrite`), and `template/base/utils/weight_utils.py` (v11
`SetWeights` normalises; `compat.weights.to_mapping`). Added:
`tests/test_template_on_tensorwire.py` (70 lines).

`docs/stream_tutorial/` and `verify/` are untouched and still v10 code; they
are not part of the subnet's runtime.

S6 (≤ 50 changed lines for a template-derived subnet) is about the subnet
code after `migrate apply`; the hand port is at 41-68 depending on how lines
are counted, with the logging lines as the bulk. The base classes are what
`TemplateValidatorAdapter` (Phase 3) is meant to replace, so a team does not
port them at all.

## What the kit gained from this port

- `compat.Metagraph` (`hotkeys`, `S`, `validator_permit`, `axons`, `n`, ...)
  and `Metagraph.of_miner(miner)`: the template's `blacklist` and `priority`
  read `self.metagraph.hotkeys.index(...)` and `self.metagraph.S[uid]`.
- `ValidatorClient(timeout_s=...)` per call, for `Dendrite(..., timeout=)`.

## What `migrate scan` missed, and the rules added for it

| Miss | New rule |
|---|---|
| `from bittensor.subnets import SubnetsAPI` | `bittensor.subnets` → TWM016 |
| `from bittensor import AxonInfo` | TWM021 (`compat.AxonInfo`) |
| `from bittensor import NeuronInfo, PrometheusInfo, __ss58_format__` | TWM022 |
| `self.metagraph.n.item()` (a tensor on v10, an int now) | TWM023 |

Not covered by a rule, by design: `time.sleep` inside a coroutine
(a general async bug, already in the v10 template), and strings such as
`"bt.Config"` in type hints.

## Time

The port was done by Engineer A (an AI engineer) in about six minutes of
wall-clock time between commits, after the compat layer existed. That is not
a measure of what a human team needs; the design-partner case studies (S7)
record human time.
