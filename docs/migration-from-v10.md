# Migrating a v10 subnet to TaoWire

For subnets built on `bittensor` 10.x (most are forks of the archived
template). v11 removed `bt.Synapse`, `bt.axon`, `bt.dendrite` and friends;
TaoWire gives you the same shapes on top of v11, with signed requests and
responses, replay protection and caller policy built in, and a bridge so old
and new nodes keep working together while the subnet migrates.

The path:

1. `taowire migrate scan .` lists everything that needs changing.
2. `taowire migrate apply .` makes the mechanical rewrites and marks
   everything else with a `# TW-MIGRATE:` comment.
3. Fix the marked items by hand. For a template-derived subnet that is mostly
   config and the template's own base classes; the subnet's code changes by
   tens of lines (17 for the template, 21 for llm-detection:
   `docs/migrations/`).
4. Release. Old and new nodes keep talking (the legacy bridge).
5. Follow the rollout runbook (`docs/migration-rollout.md`) to end the
   transition; `taowire migrate status` gives its numbers.

New subnets should use the native API (`Miner`, `SubnetValidator`); `compat`
is for migrating code.

## Install

```bash
pip install 'taowire[migrate]'      # libcst, for `taowire migrate`
```

## `taowire migrate scan`

```bash
taowire migrate scan path/to/subnet              # text
taowire migrate scan path/to/subnet -f md        # Markdown, for the migration PR
taowire migrate scan path/to/subnet -f json      # for tooling
```

It parses the code (it never imports or runs it), skips virtualenvs and
caches, never follows symlinks out of the repository, and reports each finding
as `file:line: rule [severity] title`, with what it found and the fix. It says
at the top when the repository has the template's shape. Severities:

- `auto`: a mechanical rewrite (`taowire migrate apply` does these for
  you);
- `manual`: needs a person;
- `risk`: works, but weakens the subnet's security.

Exit status 0 when every finding is `auto`, 1 otherwise (or when a file does
not parse).

## `taowire migrate apply`

```bash
git status                               # apply refuses a dirty tree: commit first
taowire migrate apply path/to/subnet --dry-run   # the unified diff, nothing written
taowire migrate apply path/to/subnet             # rewrite in place
git diff                                 # exactly what apply changed
```

It rewrites every `auto` rule (the list is under "Rules": imports, `bt.logging`
calls, Axon/Dendrite construction, the metagraph axons list, the weights
helpers, `time.sleep` in coroutines, the template's validator base) and puts a
`# TW-MIGRATE: TWMxxx <instruction>` line above every statement that still
needs a person, including any `auto` case it could not rewrite safely.
`import bittensor as bt` goes once nothing uses `bt` any more. Names it
inserts never shadow your own (a module with its own `class Miner` gets
`from taowire import Miner as TWMiner`). Running it twice changes nothing.
It reads and writes only `.py` files, never through symlinks, and never
touches wallets or `.env` files. Exit status 0; 1 when a file could not be
parsed or rewritten (that file is named, the others are still done); 2 when
it refuses to run. Afterwards `migrate scan` shows what is left.

## The template's validator base: `TemplateValidatorAdapter`

`apply` replaces the template's `BaseValidatorNeuron` import with
`taowire.compat.TemplateValidatorAdapter` when your
`template/base/validator.py` is the stock one (TWM024). The kit then runs
what that base did by hand: the hotkey (never the coldkey), the chain and
metagraph, `compat.Dendrite` (with the v10 fallback), the score store, weight
setting with `TW_WEIGHTS_VERSION_KEY`, and `/healthz`, `/readyz`, `/metrics`
on `TW_METRICS_BIND`. Your `forward()` and `reward()` stay as they are;
`self.config`, `self.metagraph`, `self.dendrite`, `self.step`, `self.scores`,
`self.hotkeys`, `self.uid`, `update_scores()`, `run()` and
`with Validator() as v:` keep working. Scoring keeps the template's semantics
(the moving average with alpha `TW_SCORE_ALPHA`, unqueried miners decay,
replaced hotkeys are zeroed); the kit stores the scores and sets weights from
them. Steps start at most every `TW_ROUND_INTERVAL_S`; weights follow the
chain's rate limit and `TW_MIN_WEIGHT_INTERVAL_BLOCKS`.

### A customised copy of the template's bases (TWM026)

Many subnets keep their own copy of the template's bases
(`<pkg>/base/neuron.py`, `miner.py`, `validator.py`) with methods added:
wandb logging, stake filters, version checks, per-miner counters. `apply`
puts those classes on the kit's adapters and keeps every method you wrote:

- `BaseMinerNeuron(BaseNeuron)` becomes `BaseMinerNeuron(BaseNeuron,
  TemplateMinerAdapter)`, and `BaseValidatorNeuron(BaseNeuron)` becomes
  `BaseValidatorNeuron(BaseNeuron, TemplateValidatorAdapter)`.
- The methods the kit runs now are removed: `run`, `run_in_background_thread`,
  `stop_run_thread`, `__enter__`, `__exit__`, the validator's `serve_axon`
  and `set_weights`, and `BaseNeuron`'s abstract `run`. A
  `# TW-MIGRATE: TWM026` line lists the ones that held code: move anything
  custom they did (say, closing a wandb run) into `sync()` or
  `resync_metagraph()`, then delete the line.
- In `__init__`, `**kit_parts` is passed through to the adapter (tests use
  it to inject `FakeChain`), `BaseNeuron.__init__` calls `super().__init__()`
  first, and the statements that built what the kit owns now go: the
  assignments to `self.wallet`, `self.subtensor`, `self.metagraph`,
  `self.dendrite`, `self.axon`, `self.uid`, `self.loop` and `self.config`,
  the template's config merge, and `bt.logging(...)` set-up. Everything else
  stays where it was.

Your kept methods then run against the template surface the adapters
provide (`taowire.compat.neuron`):

| You use | On TaoWire |
|---|---|
| `self.config` | your `add_args` options, `netuid` from `TW_NETUID`, and v10's `wallet.*` / `subtensor.*` / `logging.*` / `axon.*` groups filled from the `TW_*` settings the kit really uses |
| `self.wallet.hotkey` | the hotkey (`ss58_address`, `public_key`, `sign()`). `self.wallet.coldkey` raises: the kit never loads it |
| `self.subtensor` | reads from the kit's metagraph: `block`, `get_current_block()`, `metagraph()`, `is_hotkey_registered()`, `chain_endpoint`. Anything else raises: other chain reads use v11's `bt.Subtensor` (spec 3) |
| `self.metagraph`, `self.uid`, `self.block` | the kit's metagraph cache; `copy.deepcopy(self.metagraph)` freezes a snapshot, `metagraph.sync()` is a no-op |
| `sync()`, `check_registered()`, `should_sync_metagraph()`, `should_set_weights()`, `serve_axon()`, `set_weights()` | the template's `sync()` order; registration is checked at startup (exit 3), the kit serves the axon and sets weights on its own schedule, so `set_weights()` does nothing by itself. Your own versions of these methods take precedence |
| Chain reads in `__init__` | the validator adapter starts the kit on its first chain read, as v10's `BaseNeuron.__init__` connected; the miner adapter does one read for `__init__` and then serves from its own cache |
| `with Miner() as miner:` / `with Validator() as v:` | serve in the background; SIGTERM stops them like Ctrl-C |
| The miner's per-epoch loop | `sync()` runs once per `neuron.epoch_length` blocks |

What stays a hand change: v11's own API changes outside networking (for
example `subtensor.get_stake_info_for_coldkey` is
`client.staking.stake_for_coldkeys` in v11), and anything else the scan still
marks. `apply` swaps a package only when its three bases have the template's
shape (`BaseMinerNeuron` and `BaseValidatorNeuron` subclass `BaseNeuron`);
otherwise the TWM026 marker stays on the import and the swap is yours. The
llm-detection case study shows one: `docs/migrations/llm-detection.md`.

For the stock template, the miner side is the example's
`template/base/miner.py` and `neuron.py` (the template port); the
`TemplateMinerAdapter` does the same for a customised copy.

### v10 config calls (TWM031)

`bt.wallet.add_args(parser)` (and `subtensor`, `axon`, `logging`) becomes
`add_v10_args(parser, "wallet")`, `bt.config(parser)` becomes
`taowire.compat.config(parser)`, and bare `bt.logging.check_config(c)`
statements go. The v10 option names stay, so your code that reads
`config.wallet.name` or `config.logging.logging_dir` keeps working; their
defaults come from the `TW_*` variables, and the kit itself only ever reads
`TW_*` settings.

## The compat layer

```python
from taowire.compat import Synapse, StreamingSynapse, Axon, Dendrite, AxonInfo, axons_from, Metagraph, weights
```

| v10 | TaoWire |
|---|---|
| `class Dummy(bt.Synapse)` | `class Dummy(Synapse)`: same fields, `deserialize()`, `required_hash_fields`, `dendrite`/`axon` `TerminalInfo`, `is_success` / `is_timeout` / ... |
| `class StreamPrompting(bt.StreamingSynapse)` | `class StreamPrompting(StreamingSynapse)`: same `process_streaming_response` / `extract_response_json` / `deserialize`; the miner's `forward` still returns `create_streaming_response(token_streamer)` (TWM002, auto) |
| `bt.axon(wallet=..., config=...)` | `Axon(miner=Miner.from_env())` (settings from `TW_*`) |
| `axon.attach(forward_fn, blacklist_fn, priority_fn)` | the same call; each Synapse becomes `POST /<SynapseName>` |
| `axon.serve(netuid, subtensor)` / `axon.start()` | `serve(netuid=...)` only checks the netuid; `start()` runs the miner (blocks) |
| `bt.dendrite(wallet=wallet)` | `Dendrite(signer=RequestSigner(hotkey))` |
| `await dendrite(axons, synapse, timeout, deserialize)` | the same call and result shapes |
| `[metagraph.axons[uid] for uid in uids]` | `axons_from(metagraph, uids)` (a `compat.Metagraph` or a `MetagraphView`), or `Metagraph(...).axons[uid]` |
| `metagraph.hotkeys`, `.S`, `.validator_permit`, `.n` | `Metagraph(source)` / `Metagraph.of_miner(miner)`: same names, plain lists |
| `bt.subtensor(config=config)` and its reads / commitments | `Subtensor(config=config)`: same method names and keywords ([below](#compatsubtensor)) |
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
- **Streaming** (`StreamingSynapse`) runs on the kit's signed SSE streams
  ([streaming.md](streaming.md)): each body frame your token streamer sends
  is one signed chunk, with a `tw-end` trailer at the end.
  `Dendrite(..., streaming=True)` returns one async generator per axon, as in
  v10: what your `process_streaming_response` yields (it reads
  `response.content.iter_any()`), then the final item. The bytes your code
  reads are **not verified yet**; the final item is your filled Synapse only
  when the trailer verified, otherwise a fresh copy of the request with
  `dendrite.status_code` set (408 timeout, 500 bad signature, ...). Score from
  the final item. Streaming works TaoWire to TaoWire only (D33): a v10
  Dendrite gets the v10-shaped `tw.invalid_request` from a streaming route
  (TWM034).

<a id="compatsubtensor"></a>
### `compat.Subtensor`

Subnets that call `bt.subtensor` directly (data-universe, for one) keep those
calls on `taowire.compat.Subtensor` (spec 10b.2.6, D34). It is
synchronous, like v10's, and every call goes through the kit's chain gateway:

```python
from taowire.compat import Subtensor

subtensor = Subtensor(config=config)   # or Subtensor("ws://127.0.0.1:9944")
mg = subtensor.metagraph(netuid)        # a compat Metagraph
uid = subtensor.get_uid_for_hotkey_on_subnet(hotkey_ss58=hk, netuid=netuid)
sha = subtensor.get_commitment(netuid=netuid, uid=uid)   # "" if none
subtensor.set_commitment(wallet=wallet, netuid=netuid, data=sha)
```

| Call | Notes |
|---|---|
| `metagraph(netuid, lite=True, block=None)` | the compat `Metagraph`; `lite` is ignored |
| `block`, `get_current_block()` | the current block |
| `get_block_hash(block=None)` | `0x` hash, `None` for a block that does not exist |
| `get_uid_for_hotkey_on_subnet(hotkey_ss58, netuid)` | `None` if not registered |
| `is_hotkey_registered(hotkey_ss58, netuid)` | `netuid` is required (v10's any-subnet scan is not offered) |
| `get_commitment(netuid, uid)` | the plaintext commitment, `""` if none (as v10) |
| `query_subtensor(name, params=[...])` | a `SubtensorModule` storage value as plain Python data (v10 returned an SDK object); untrusted |
| `commit(wallet, netuid, data)` / `set_commitment(...)` | one `Raw` field of 1..128 UTF-8 bytes, signed by the wallet's **hotkey**; `True` once included |
| `set_weights(wallet, netuid, uids, weights, version_key=0)` | v10's `(ok, message)`; submitted once, never resent. Prefer the kit's weight scheduler, which also re-plans expired timelocked commits |
| `serve_axon(...)` | a no-op: the kit publishes the axon at startup |
| any other v10 write (`add_stake`, `transfer`, `register`, `commit_weights`, ...) | `NotImplementedError` naming the v11 replacement (TWM036) |

The coldkey is never read. `block=` other than `None` (historical reads)
raises `NotImplementedError`; use v11's `bt.Subtensor` for those. Any other
attribute is an `AttributeError`, never a silent `None`. `close()` (or a
`with` block) closes the chain connections. Tests pass
`gateway_factory=lambda hk: chain if hk is None else chain.with_signer(hk.ss58_address)` to run on a
`FakeChain`.

## Old and new nodes together (the legacy bridge)

- **Miners** on TaoWire answer unmodified v10 validators while
  `TW_LEGACY_V10_UNTIL=<date>` is set (routes declared through `compat.Axon`
  accept v10 automatically). See `docs/miner-guide.md`.
- **Validators** on TaoWire reach unmodified v10 miners with
  `TW_LEGACY_V10_CLIENT=auto` and `TW_LEGACY_V10_CLIENT_UNTIL=<date>`. See
  `docs/validator-guide.md`.
- Both dates are mandatory and at most 180 days ahead: the bridge is for a
  transition, not forever. The v10 scheme signs only `required_hash_fields`
  and never signs responses; wire details in `docs/protocol/legacy-v10.md`.

## Worked example

`examples/migrations/template-v10-to-v11/` holds the archived template
(`before/`, unmodified) and its port (`after/` = `migrate apply` output plus
`hand-fixes.patch`, checked byte for byte by the golden test), whose test runs
the template's miner and validator together on TaoWire's FakeChain. What
changed and what it took: `docs/migrations/template.md`. A real subnet with a
customised base: `docs/migrations/llm-detection.md`.

## Rules

<a id="twm001"></a>
### TWM001: bt.Synapse / bt.TerminalInfo (`auto`)

From taowire.compat import Synapse (TerminalInfo likewise).

<a id="twm002"></a>
### TWM002: bt.StreamingSynapse (`auto`)

From taowire.compat import StreamingSynapse (the kit's signed SSE streaming, spec 9.2; same process_streaming_response / extract_response_json / deserialize). The miner's `forward` still returns `synapse.create_streaming_response(token_streamer)`; `compat.Dendrite(..., streaming=True)` still returns one async generator per axon. What changes: the final item is the filled Synapse only when the stream's signed trailer verified, otherwise a fresh copy of the request with the error status (see [streaming.md](streaming.md)).

<a id="twm003"></a>
### TWM003: bt.axon / bt.Axon (`auto`)

Taowire.compat.Axon(miner=Miner.from_env()); settings come from TW_*.

<a id="twm004"></a>
### TWM004: bt.dendrite / bt.Dendrite (`auto`)

Taowire.compat.Dendrite(signer=RequestSigner(wallet)).

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
### TWM008: bt.subtensor(...) / bt.Subtensor(config=...) (`auto`)

Taowire.compat.Subtensor: the v10 reads and commitments on the kit's gateway (spec 10b.2.6); or the kit's MetagraphCache.

`apply` rewrites `bt.subtensor(...)`, `bt.Subtensor(config=...)` and
`bt.Subtensor` annotations to `compat.Subtensor` ([below](#compatsubtensor)).
`bt.Subtensor(network=...)` is a valid v11 call, so it is rewritten only in a
file that also calls a method v11's client does not have
(`get_current_block`, `get_block_hash`, `get_uid_for_hotkey_on_subnet`,
`is_hotkey_registered`, `get_commitment`, `set_commitment`,
`query_subtensor`): there it is v10's class. Elsewhere `bt.Subtensor("test")`
is v11's own client and is left alone; `bt.subtensor.add_args(...)` stays
TWM006 / TWM031.

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

Taowire.compat.weights.to_mapping(uids, weights); v11 SetWeights normalises itself.

<a id="twm013"></a>
### TWM013: [metagraph.axons[uid] for uid in uids] (`auto`)

Taowire.compat.axons_from(metagraph, uids).

<a id="twm014"></a>
### TWM014: bt.wallet (`manual`)

Load the hotkey only (TW_WALLET_*); the kit never touches the coldkey.

<a id="twm015"></a>
### TWM015: mock chain objects (`manual`)

Taowire.testing.FakeChain and the pytest fixtures.

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

Taowire.compat.AxonInfo (ip, port, hotkey, is_serving).

<a id="twm022"></a>
### TWM022: v10 chain info types (`manual`)

NeuronInfo / PrometheusInfo are gone: read NeuronView from the kit's metagraph; the SS58 format is 42 (taowire.crypto.SS58_FORMAT).

<a id="twm023"></a>
### TWM023: tensor methods on metagraph values (`auto`)

Compat.Metagraph values are plain ints and lists: .item() / .tolist() are dropped (wrap in numpy.array(...) where an array is needed).

<a id="twm024"></a>
### TWM024: template BaseValidatorNeuron (`auto`)

From taowire.compat import TemplateValidatorAdapter as BaseValidatorNeuron (the kit runs the loop, scores and weights).

<a id="twm025"></a>
### TWM025: bt.logging configuration (`manual`)

Remove it: the kit configures logging (TW_LOG_LEVEL); use the standard logging module for anything else.

<a id="twm026"></a>
### TWM026: customised template bases (`auto`)

BaseMinerNeuron / BaseValidatorNeuron also subclass taowire.compat.TemplateMinerAdapter / TemplateValidatorAdapter; the run loops, axon serving, set_weights and wallet/subtensor set-up go, your own methods stay (spec 10b.2.4).

See [A customised copy of the template's bases](#a-customised-copy-of-the-templates-bases-twm026).

<a id="twm027"></a>
### TWM027: time.sleep in a coroutine (`auto`)

Await asyncio.sleep(...): a blocking sleep also stops the kit's health and metrics endpoints.

<a id="twm028"></a>
### TWM028: bittensor type in a string annotation (`auto`)

The compat type: "bt.Synapse" -> "Synapse", "bt.metagraph.Metagraph" -> "Metagraph" (AxonInfo, TerminalInfo, "bt.subtensor" -> "Subtensor" likewise).

<a id="twm029"></a>
### TWM029: bittensor name inside a string (`manual`)

Update it by hand (a mock.patch target such as 'mod.bt.logging.info' breaks once the code it names is migrated).

<a id="twm030"></a>
### TWM030: unknown bittensor name (`manual`)

Neither a known v10 symbol nor part of the v11 public API: check it by hand (removed in v11, or a typo).

<a id="twm031"></a>
### TWM031: v10 config calls (`auto`)

bt.<group>.add_args(parser) -> add_v10_args(parser, "<group>"), bt.config(parser) -> taowire.compat.config(parser), a bt.Config annotation -> Config, bt.logging.check_config(...) removed: defaults come from TW_* settings.

See [v10 config calls](#v10-config-calls-twm031). Other shapes (extra arguments, `bt.config` used as a value) stay TWM006.

<a id="twm032"></a>
### TWM032: bt.logging set-up statement (`auto`)

Removed: the kit configures logging (TW_LOG_LEVEL); bare bt.logging(...), bt.logging.set_debug(...), set_trace, enable_* ... statements have nothing left to do.

Only bare statements go; any other use of `bt.logging` that is not a log call (assigning `bt.logging.trace` to patch it, for example) stays TWM025.

<a id="twm033"></a>
### TWM033: bt.Wallet(config=c) (`auto`)

V11's constructor: bt.Wallet(name=c.wallet.name, hotkey=c.wallet.hotkey, path=c.wallet.path) (the subnet's own wallet use; the kit loads its hotkey from TW_WALLET_*).

v11's `Wallet` reads the coldkey only when your code asks for it (`wallet.coldkey`); `wallet.get_coldkeypub()` is the `wallet.coldkeypub` property in v11.

<a id="twm035"></a>
### TWM035: bt.AsyncSubtensor (`manual`)

The kit's chain gateway (async) and MetagraphCache, or v11's bt.Subtensor (await bt.Subtensor(...)); compat.Subtensor is synchronous.

<a id="twm036"></a>
### TWM036: subtensor write compat.Subtensor does not perform (`manual`)

The v11 replacement named in the finding (stake, transfer and registration are coldkey operations: run them from btcli, not a server).

`scan` names the replacement in each finding (`add_stake` -> `bt.AddStake`,
`commit_weights` / `reveal_weights` -> the kit's weight scheduler, ...); the
same table (`taowire.compat.subtensor.V10_WRITES`) is what
`compat.Subtensor` raises `NotImplementedError` with, so code that slips
past the scan fails loudly instead of doing nothing.

<a id="twm100"></a>
### TWM100: Synapse without required_hash_fields (`risk`)

List every request field that matters in required_hash_fields: on the v10 wire other fields can be changed without breaking the signature. This changes the v10 body hash: ship it to every peer at once, or after rollout stage 4 (D28).

<a id="twm101"></a>
### TWM101: Synapse with partial required_hash_fields (`risk`)

Add the missing request fields to required_hash_fields (every peer at once, or after rollout stage 4: it changes the v10 body hash, D28).

Why TWM100 and TWM101 matter: a v10 request signature covers
`computed_body_hash`, and that hash covers only the fields listed in
`required_hash_fields`. Any other field can be changed in transit without
breaking the signature (captured vector N8 shows a v10 Axon accepting such a
request). On the btauth/1 wire the whole body is signed, so this matters only
while v10 validators still call your miners, but it matters then. List every
request field your miner's answer depends on. The template's `Dummy` listed
none.

**Changing `required_hash_fields` breaks a mixed fleet** (D28): the v10 body
hash is part of the wire format both sides compute, so a v10 validator that
still hashes the old field list fails every request to a miner with the new
one, and the other way round. Ship the change to every peer at once, or after
rollout stage 4 ([migration-rollout.md](migration-rollout.md#required_hash_fields)).

<a id="twm102"></a>
### TWM102: allow_non_registered=True (`risk`)

Remove it: unregistered callers are refused by the kit's caller policy.

<a id="twm034"></a>
### TWM034: StreamingSynapse route in a mixed fleet (`risk`)

Streaming works TaoWire to TaoWire only: a v10 Dendrite gets tw.invalid_request from it and a v10 miner cannot stream to a TaoWire validator (D33). Move streaming routes after rollout stage 2, or give v10 peers a non-streaming route until then (`docs/migration-rollout.md`). `scan` flags every `StreamingSynapse` subclass, including subclasses of one defined earlier in the same file; a subclass of a streaming class from another file is not followed, so check those by hand.

<a id="twm103"></a>
### TWM103: force_validator_permit=False (`risk`)

Require a permit (TW_REQUIRE_PERMIT=1, the kit default).

The template's own `--blacklist.force_validator_permit` defaults to `False`.
On TaoWire the kit's caller policy requires a permit before
`blacklist_fn` runs (`TW_REQUIRE_PERMIT=1`), so the flag no longer opens
anything; the finding stays until the flag is removed or defaults to `True`.

<a id="twm104"></a>
### TWM104: blacklist that never checks registration (`risk`)

Rely on the kit's caller policy (registered + permit) and keep blacklist_fn for extra, narrower rules.
