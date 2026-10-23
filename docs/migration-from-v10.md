# Migrating a v10 subnet to TensorWire

For subnets built on `bittensor` 10.x (most are forks of the archived
template). v11 removed `bt.Synapse`, `bt.axon`, `bt.dendrite` and friends;
TensorWire gives you the same shapes on top of v11, with signed requests and
responses, replay protection and caller policy built in, and a bridge so old
and new nodes keep working together while the subnet migrates.

The path:

1. `tensorwire migrate scan .` lists everything that needs changing.
2. Port the code to `tensorwire.compat` (mostly import changes; see the rules
   below and the worked example of the template).
3. Release. Old and new nodes keep talking (the legacy bridge).
4. Follow the rollout runbook (spec 10b.5; `docs/migration-rollout.md` arrives
   in Phase 3) to end the transition.

New subnets should use the native API (`Miner`, `SubnetValidator`); `compat`
is for migrating code.

## Install

```bash
pip install 'tensorwire[migrate]'      # libcst, for `tensorwire migrate`
```

## `tensorwire migrate scan`

```bash
tensorwire migrate scan path/to/subnet              # text
tensorwire migrate scan path/to/subnet -f md        # Markdown, for the migration PR
tensorwire migrate scan path/to/subnet -f json      # for tooling
```

It parses the code (it never imports or runs it), skips virtualenvs and
caches, never follows symlinks out of the repository, and reports each finding
as `file:line: rule [severity] title`, with what it found and the fix. It says
at the top when the repository has the template's shape. Severities:

- `auto`: a mechanical rewrite (`tensorwire migrate apply`, Phase 3, does
  these for you);
- `manual`: needs a person;
- `risk`: works, but weakens the subnet's security.

Exit status 0 when every finding is `auto`, 1 otherwise (or when a file does
not parse).

## The compat layer

```python
from tensorwire.compat import Synapse, Axon, Dendrite, AxonInfo, axons_from, Metagraph, weights
```

| v10 | TensorWire |
|---|---|
| `class Dummy(bt.Synapse)` | `class Dummy(Synapse)`: same fields, `deserialize()`, `required_hash_fields`, `dendrite`/`axon` `TerminalInfo`, `is_success` / `is_timeout` / ... |
| `bt.axon(wallet=..., config=...)` | `Axon(miner=Miner.from_env())` (settings from `TW_*`) |
| `axon.attach(forward_fn, blacklist_fn, priority_fn)` | the same call; each Synapse becomes `POST /<SynapseName>` |
| `axon.serve(netuid, subtensor)` / `axon.start()` | `serve(netuid=...)` only checks the netuid; `start()` runs the miner (blocks) |
| `bt.dendrite(wallet=wallet)` | `Dendrite(signer=RequestSigner(hotkey))` |
| `await dendrite(axons, synapse, timeout, deserialize)` | the same call and result shapes |
| `[metagraph.axons[uid] for uid in uids]` | `axons_from(metagraph_view, uids)`, or `Metagraph(...).axons[uid]` |
| `metagraph.hotkeys`, `.S`, `.validator_permit`, `.n` | `Metagraph(source)` / `Metagraph.of_miner(miner)`: same names, plain lists |
| `process_weights_for_netuid` + `convert_weights_and_uids_for_emit` | `weights.to_mapping(uids, weights)`; v11 `SetWeights` normalises itself |

What changes in behaviour:

- **Every request is verified before your code runs.** The kit checks the
  btauth/1 signature (or the v10 one on the bridge), freshness, replay and the
  caller policy (registered, validator permit, minimum stake, allow/deny
  lists) first. `blacklist_fn` runs after that, with `synapse.dendrite.hotkey`
  set to the verified caller: it can only narrow access, never widen it. A
  `True` result answers 403 `tw.forbidden_blacklisted`. In v10 the blacklist
  saw placeholder body values (it ran before the body was parsed); now it
  sees the real ones.
- `priority_fn` orders admission when a route's concurrency limit (16) is
  reached; at most `TW_COMPAT_MAX_QUEUE` (256) wait, then 429.
- `verify_fn` is refused: verification is the kit's job.
- `forward_fn` keeps its signature; plain `def` functions run in a thread.
- Dendrite failures never raise. As in v10 the item comes back with
  `dendrite.status_code` (408 timeout, 503 connect error or no axon,
  401/403/... passed through, 500 for an answer that failed verification) and
  `dendrite.status_message` set to the `tw.*` code.
- On the btauth/1 wire only your Synapse's own fields travel; `dendrite` and
  `axon` are filled locally. The v10 bridge still sends the whole Synapse.

## Old and new nodes together (the legacy bridge)

- **Miners** on TensorWire answer unmodified v10 validators while
  `TW_LEGACY_V10_UNTIL=<date>` is set (routes declared through `compat.Axon`
  accept v10 automatically). See `docs/miner-guide.md`.
- **Validators** on TensorWire reach unmodified v10 miners with
  `TW_LEGACY_V10_CLIENT=auto` and `TW_LEGACY_V10_CLIENT_UNTIL=<date>`. See
  `docs/validator-guide.md`.
- Both dates are mandatory and at most 180 days ahead: the bridge is for a
  transition, not forever. The v10 scheme signs only `required_hash_fields`
  and never signs responses; wire details in `docs/protocol/legacy-v10.md`.

## Worked example

`examples/migrations/template-v10-to-v11/` holds the archived template
(`before/`, unmodified) and its hand port (`after/`), whose test runs the
template's miner and validator together on TensorWire's FakeChain. What
changed and what it took: `docs/migrations/template.md`.

## Rules

<a id="twm001"></a>
### TWM001: bt.Synapse / bt.TerminalInfo (`auto`)

From tensorwire.compat import Synapse (TerminalInfo likewise).

<a id="twm002"></a>
### TWM002: bt.StreamingSynapse (`manual`)

Compat.StreamingSynapse arrives with the kit's streaming support (Phase 4); until then keep the route on v10 or answer without streaming.

<a id="twm003"></a>
### TWM003: bt.axon / bt.Axon (`auto`)

Tensorwire.compat.Axon(miner=Miner.from_env()); settings come from TW_*.

<a id="twm004"></a>
### TWM004: bt.dendrite / bt.Dendrite (`auto`)

Tensorwire.compat.Dendrite(signer=RequestSigner(wallet)).

<a id="twm005"></a>
### TWM005: bt.Tensor (`manual`)

Serialize tensors with the ML library (bytes/base64 or lists).

<a id="twm006"></a>
### TWM006: bt.config / bt.Config / add_args (`manual`)

Kit settings (TW_* variables, spec 12) or the team's own config.

Wallet, chain, axon and logging options (`bt.wallet.add_args`,
`bt.subtensor.add_args`, `bt.axon.add_args`, `bt.logging.add_args`) become
`TW_*` variables; keep `argparse` for your subnet's own options. The template
port replaces `bt.config(parser)` with a ten-line helper that turns
`--neuron.sample_size` into `config.neuron.sample_size`.

<a id="twm007"></a>
### TWM007: bt.logging calls (`auto`)

Standard logging: bt.logging.info(...) -> logging.info(...); trace -> debug, success -> info (the kit configures JSON logs).

<a id="twm008"></a>
### TWM008: bt.subtensor / bt.AsyncSubtensor (`manual`)

The kit's chain gateway and MetagraphCache, or bt.Subtensor directly.

<a id="twm009"></a>
### TWM009: bt.metagraph / metagraph.sync() (`manual`)

The kit's MetagraphCache (refreshes itself); compat.Metagraph for hotkeys / S / validator_permit.

<a id="twm010"></a>
### TWM010: subtensor.set_weights(...) (`manual`)

The kit's weight scheduler (SubnetValidator), or bt.SetWeights.

<a id="twm011"></a>
### TWM011: subtensor.serve_axon(...) (`manual`)

Nothing: the kit publishes the axon at startup (TW_EXTERNAL_IP).

<a id="twm012"></a>
### TWM012: weight_utils helpers (`auto`)

Tensorwire.compat.weights.to_mapping(uids, weights); v11 SetWeights normalises itself.

<a id="twm013"></a>
### TWM013: [metagraph.axons[uid] for uid in uids] (`auto`)

Tensorwire.compat.axons_from(metagraph, uids).

<a id="twm014"></a>
### TWM014: bt.wallet (`manual`)

Load the hotkey only (TW_WALLET_*); the kit never touches the coldkey.

<a id="twm015"></a>
### TWM015: mock chain objects (`manual`)

Tensorwire.testing.FakeChain and the pytest fixtures.

<a id="twm016"></a>
### TWM016: bt.SubnetsAPI (`manual`)

Call the subnet with compat.Dendrite or ValidatorClient.

<a id="twm017"></a>
### TWM017: top-level bt.Keypair (`manual`)

From bittensor.keyfiles import Keypair.

<a id="twm018"></a>
### TWM018: v10 module paths (`manual`)

Bittensor.core.* and bittensor.utils.* are gone in v11; see spec 3.8.

<a id="twm019"></a>
### TWM019: custom Axon / Dendrite subclass (`manual`)

Port by hand onto Miner routes / ValidatorClient.

<a id="twm020"></a>
### TWM020: custom verify_fn (`manual`)

Remove it: the kit verifies every request; use the caller policy or blacklist_fn.

<a id="twm021"></a>
### TWM021: bt.AxonInfo (`auto`)

Tensorwire.compat.AxonInfo (ip, port, hotkey, is_serving).

<a id="twm022"></a>
### TWM022: v10 chain info types (`manual`)

NeuronInfo / PrometheusInfo are gone: read NeuronView from the kit's metagraph; the SS58 format is 42 (tensorwire.crypto.SS58_FORMAT).

<a id="twm023"></a>
### TWM023: tensor methods on metagraph values (`auto`)

Compat.Metagraph values are plain ints and lists: .item() / .tolist() are dropped (wrap in numpy.array(...) where an array is needed).

<a id="twm024"></a>
### TWM024: template BaseValidatorNeuron (`auto`)

From tensorwire.compat import TemplateValidatorAdapter as BaseValidatorNeuron (the kit runs the loop, scores and weights).

<a id="twm025"></a>
### TWM025: bt.logging configuration (`manual`)

Remove it: the kit configures logging (TW_LOG_LEVEL); use the standard logging module for anything else.

<a id="twm026"></a>
### TWM026: customised template BaseValidatorNeuron (`manual`)

Keep your additions: make your BaseValidatorNeuron subclass tensorwire.compat.TemplateValidatorAdapter and keep only the methods the template does not have (spec 10b.2.4).

<a id="twm027"></a>
### TWM027: time.sleep in a coroutine (`auto`)

Await asyncio.sleep(...): a blocking sleep also stops the kit's health and metrics endpoints.

<a id="twm028"></a>
### TWM028: bittensor type in a string annotation (`auto`)

The compat type: "bt.Synapse" -> "Synapse", "bt.metagraph.Metagraph" -> "Metagraph" (AxonInfo, TerminalInfo likewise).

<a id="twm029"></a>
### TWM029: bittensor name inside a string (`manual`)

Update it by hand (a mock.patch target such as 'mod.bt.logging.info' breaks once the code it names is migrated).

<a id="twm030"></a>
### TWM030: unknown bittensor name (`manual`)

Neither a known v10 symbol nor part of the v11 public API: check it by hand (removed in v11, or a typo).

<a id="twm100"></a>
### TWM100: Synapse without required_hash_fields (`risk`)

List every request field that matters in required_hash_fields: on the v10 wire other fields can be changed without breaking the signature.

<a id="twm101"></a>
### TWM101: Synapse with partial required_hash_fields (`risk`)

Add the missing request fields to required_hash_fields.

Why TWM100 and TWM101 matter: a v10 request signature covers
`computed_body_hash`, and that hash covers only the fields listed in
`required_hash_fields`. Any other field can be changed in transit without
breaking the signature (captured vector N8 shows a v10 Axon accepting such a
request). On the btauth/1 wire the whole body is signed, so this matters only
while v10 validators still call your miners, but it matters then. List every
request field your miner's answer depends on. The template's `Dummy` listed
none.

<a id="twm102"></a>
### TWM102: allow_non_registered=True (`risk`)

Remove it: unregistered callers are refused by the kit's caller policy.

<a id="twm103"></a>
### TWM103: force_validator_permit=False (`risk`)

Require a permit (TW_REQUIRE_PERMIT=1, the kit default).

The template's own `--blacklist.force_validator_permit` defaults to `False`.
On TensorWire the kit's caller policy requires a permit before
`blacklist_fn` runs (`TW_REQUIRE_PERMIT=1`), so the flag no longer opens
anything; the finding stays until the flag is removed or defaults to `True`.

<a id="twm104"></a>
### TWM104: blacklist that never checks registration (`risk`)

Rely on the kit's caller policy (registered + permit) and keep blacklist_fn for extra, narrower rules.
