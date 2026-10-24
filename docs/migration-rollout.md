# Rolling out a migration: the subnet owner's runbook

How to move a live v10 subnet to TensorWire without a flag day: old and new
nodes keep working together (the legacy bridge, spec 8.11) while you move
through five stages. Each stage has an entry check, an exit check and a
rollback. You decide when to move on; the kit gives you the numbers
(`tensorwire migrate status`).

Rules for every stage:

- **Validators always move first.**
- The legacy end dates (`TW_LEGACY_V10_UNTIL` on miners,
  `TW_LEGACY_V10_CLIENT_UNTIL` on validators) should fall roughly 4-6 weeks
  after stage 1. The kit refuses dates more than 180 days away, and refuses a
  date that is today or earlier.
- "Weights landed" means **revealed** on chain (`TimelockedWeightsRevealed` /
  the `Weights` row), not the extrinsic's success flag or `LastUpdate`. With
  commit-reveal a commit can be accepted and its reveal silently dropped
  (stage 3).
- Miners that never upgrade are simply scored as failures once stage 4 ends.

This runbook was walked end to end on a localnet mixed fleet (v10 nodes on
`bittensor==10.5.0`, TensorWire nodes from the ported template), including
every rollback: 72 of 72 checks passed (Engineer B, `reports/phase-3/b/rollout/`).
The numbers quoted below are from that walk.

## The numbers: `tensorwire migrate status`

```bash
tensorwire migrate status \
  --metrics-url http://127.0.0.1:9102/metrics \   # a validator's TW_METRICS_BIND
  --metrics-url http://127.0.0.1:9101/metrics \   # a miner's
  [--min-btauth-share 0.95] [--format json]
```

| Field | Meaning |
|---|---|
| `miners_btauth`, `miners_v10` | Miners that answered over each protocol in the validators' last round (summed over the validators given) |
| `btauth_share` | `miners_btauth / (miners_btauth + miners_v10)`; `null` before any round |
| `inbound_v10_total` | v10 requests miners received (from v10 validators) |
| `outbound_v10_total` | v10 requests validators sent (to v10 miners) |
| `days_remaining` | Smallest days left before each end date, per direction |

Exit status: 0; 1 when `--min-btauth-share` is given and not met; 2 when a
source cannot be read. Save the raw text to re-check later or to keep as
evidence: `curl -s http://127.0.0.1:9102/metrics > stage2-validator.prom`,
then `tensorwire migrate status --metrics-file stage2-validator.prom`.

Validators also log one `round ok` line per round with `n_queried`, `n_ok`,
`n_btauth` and `n_v10`.

## Before you start

Pick the weights version keys. A v10 template validator sends
`version_key = __spec_version__` of your release (the template's `0.0.0` is
**0**). Upgraded validators send `TW_WEIGHTS_VERSION_KEY`, which must be
**higher**: here, 0 → **1**. Write both numbers down; stage 3 and its
rollback use them.

## Stage 0: prepare

<a id="required_hash_fields"></a>

- Port the code: `tensorwire migrate scan .`, `tensorwire migrate apply .`
  (on a clean git tree), then fix the `# TW-MIGRATE:` items by hand
  (`docs/migration-from-v10.md`).
- Run the mixed fleet on localnet (spec 13.8): `just mixed-fleet`. All four
  cells (v10 or TensorWire validator × v10 or TensorWire miner) must be
  green. Use the `testnet` image tag of the localnet chain.
- **Do not change a Synapse's `required_hash_fields` in this release**
  (D28). `scan` reports Synapses with empty or partial hash fields (TWM100,
  TWM101) as risks, and fixing them is right, but the field list feeds the v10
  body hash that old and new nodes must compute the same way: a ported miner
  with a different list fails every request from a v10 validator (and a ported
  validator every request to a v10 miner). Ship that change to all peers at
  once, or after stage 4, when no v10 peer is left.
- **Exit:** the mixed-fleet matrix is green.

Localnet note: localnet miners gain permits and stake quickly (one held
119,862 alpha within minutes). The template's `get_random_uids` skips
permitted UIDs with more than `--neuron.vpermit_tao_limit` (4096) stake, so
raise that option for template validators on localnet, or they query only
dead axons.

## Stage 1: validators first

Release the upgraded validator with:

```bash
TW_LEGACY_V10_CLIENT=auto
TW_LEGACY_V10_CLIENT_UNTIL=<today + 28 days>   # YYYY-MM-DD, UTC
TW_WEIGHTS_VERSION_KEY=1                        # higher than the v10 key (0)
TW_METRICS_BIND=127.0.0.1:9102
```

Upgraded validators reach v10 and TensorWire miners alike. They try
btauth/1, and a v10 Axon's answer (HTTP 500 with `bt_header_axon_status_code`)
switches that miner to v10 for the same query. Validators must use sr25519
hotkeys for `auto`.

- **Entry:** stage 0 done.
- **Exit:** every validator is upgraded, and each one's per-round `n_ok` is
  unchanged from before the upgrade (`round ok` log lines).
  `migrate status` against the validators shows the v10 miners, for example
  `miners_v10=2`, `outbound_v10_total > 0`, `days_remaining.outbound=28`.
- **Rollback:** stop the upgraded validator and start the v10 release again.
  Check that its weights are revealed.

## Stage 2: miners upgrade

Release the upgraded miner with:

```bash
TW_LEGACY_V10_UNTIL=<the same date as stage 1>
TW_METRICS_BIND=127.0.0.1:9101
```

It serves btauth/1, and v10 validators that have not upgraded yet over v10
until the end date.

- **Exit:** at least 95% of the miners the validators query answer over
  btauth/1:

  ```bash
  tensorwire migrate status --metrics-url http://<validator>:9102/metrics \
    --min-btauth-share 0.95; echo $?   # 0 = met
  ```

  On the walk: exit 1 with 1 of 2 miners upgraded, exit 0 with 2 of 2.
- **Rollback:** the miner goes back to its v10 release. Its `ServeAxon`
  publishes the v10 protocol tag again. Validators notice at their next
  metagraph refresh (they log `legacy_v10_protocol_tag_changed`) and reach it
  over v10 again. **No validator restart is needed** (D16, spec 8.11.3
  step 5). Without that signed tag change, a validator never downgrades a
  miner that has answered over btauth/1.

## Stage 3: push stragglers

Upgraded validators already send version key 1 (stage 1). Now the **subnet
owner** raises the subnet's weights version hyperparameter to that value, so
v10 validators can no longer set weights:

```python
# owner coldkey; or: btcli sudo set --param weights_version --value 1 --netuid <netuid> -w owner
bt.SetHyperparameter(netuid=<netuid>, name="weights_version", value=1)
```

**Retry until it lands, then read it back.** Admin calls are refused during
the subnet's admin freeze window at the end of every tempo ("Admin operation
is prohibited during the protected weights window"), and can also hit the
chain's transaction rate limit. Read the value back with
`btcli subnets hyperparameters --netuid <netuid>` (or the `WeightsVersionKey`
storage item) before you count the stage as started. On mainnet the window
is part of every tempo too.

- **Tell straggling validators.** A v10 validator's weight commit is still
  **accepted** ("Success", and its `LastUpdate` moves), but its reveal is
  dropped without an error. They will not notice on their own.
- **TensorWire validators with a stale key are stopped at commit time
  (D38).** Before every commit the kit reads `WeightsVersionKey`; when
  `TW_WEIGHTS_VERSION_KEY` is lower it commits nothing, logs
  `weights_version_key_stale` at ERROR with both keys, counts
  `tw_validator_weight_submissions_total{ok="false",code="version_key_stale"}`
  and tries again in the next weight window. Alert on that counter: a validator
  that upgraded the code but not the key shows up at once, not at reveal.
- **Exit:** no v10 traffic to miners for one tempo, read twice one tempo
  apart against the miners' metrics:

  ```bash
  tensorwire migrate status --metrics-url http://<miner>:9101/metrics --format json
  # inbound_v10_total unchanged between the two reads
  ```

  Raising the key does not stop a straggler's *queries*: on the walk, the
  blocked v10 validator kept querying (`inbound_v10_total` 234 → 274 in
  30 s), and the counter went flat only after it was stopped or upgraded.
  So this exit is reached when the stragglers have stopped or upgraded.
- **Rollback:** lower the hyperparameter again (here, back to 0; same retry
  and read-back). v10 validators' weights are revealed again.

## Stage 4: end the transition

Remove `TW_LEGACY_V10_UNTIL` from miners and set `TW_LEGACY_V10_CLIENT=off`
(and unset `TW_LEGACY_V10_CLIENT_UNTIL`) on validators, then restart them.

- **Exit:** the legacy counters stay at zero on the fresh processes:
  `inbound_v10_total=0`, `outbound_v10_total=0`, `days_remaining` null in
  both directions. On the walk: `miners_btauth=4`, both counters 0, and a v10
  Dendrite gets 401 from the miners.
- **Rollback:** re-enable the bridge with a new end date
  (`TW_LEGACY_V10_UNTIL`, `TW_LEGACY_V10_CLIENT=auto` +
  `TW_LEGACY_V10_CLIENT_UNTIL`). On the walk a v10 Dendrite got 200 again,
  with 14 days remaining.

## Alerts worth having

- `tw_legacy_v10_days_remaining < 14`: the end date is close (stage 4 or a
  new date).
- `tw_legacy_v10_requests_total{direction="inbound"}` still rising after
  stage 3: someone is still running v10.
- `tw_validator_last_weights_block` not moving: weights stopped. It counts
  commits; also check that reveals land.
