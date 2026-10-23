# The archived v10 subnet template, before and after

- `before/`: an unmodified copy of <https://github.com/latent-to/bittensor-subnet-template>
  at commit `539b77c30d60dea236ab1c48a3bde7f495caf516` (2026-07-10), MIT licence
  (`before/LICENSE`, Copyright (c) 2023 Opentensor). Nothing in it is changed.
- `after/`: the same subnet on `tensorwire.compat`, ported by hand (spec 10b.6,
  Phase 2). The changes and the lines they touched are listed in
  [`docs/migrations/template.md`](../../../docs/migrations/template.md).

`tensorwire migrate scan before/` is the input of the migration tests
(`python/tests/migration/test_migrate_scan.py`).

## Running `after/` on localnet

Everything comes from `TW_*` variables (spec Section 12); the template's own
options (`--neuron.*`, `--blacklist.*`) still work on the command line. With
the localnet from `scripts/localnet_up.sh` (`~/.tensorwire/localnet/localnet.env`
has `TW_NETWORK`, `TW_NETUID`, `TW_WALLET_PATH`, `TW_ALLOW_PRIVATE_AXONS`):

```bash
cd examples/migrations/template-v10-to-v11/after
set -a; . ~/.tensorwire/localnet/localnet.env; set +a
export PYTHONPATH=$PWD TW_REFUSE_IF_COLDKEY_PRESENT=0   # localnet dev wallets only

# miner: btauth/1, plus v10 validators until the end date
TW_WALLET_NAME=miner_py TW_STATE_DIR=/tmp/tw-miner \
TW_BIND_HOST=127.0.0.2 TW_BIND_PORT=8092 TW_EXTERNAL_IP=127.0.0.2 \
TW_METRICS_BIND=127.0.0.1:9101 TW_LEGACY_V10_UNTIL=$(date -u -d '+28 days' +%F) \
python neurons/miner.py

# validator: reaches v10 miners too; sends weights version key 1
TW_WALLET_NAME=validator TW_STATE_DIR=/tmp/tw-validator \
TW_METRICS_BIND=127.0.0.1:9102 TW_WEIGHTS_VERSION_KEY=1 \
TW_LEGACY_V10_CLIENT=auto TW_LEGACY_V10_CLIENT_UNTIL=$(date -u -d '+28 days' +%F) \
TW_ROUND_INTERVAL_S=3 TW_MIN_WEIGHT_INTERVAL_BLOCKS=10 \
python neurons/validator.py

tensorwire migrate status --metrics-url http://127.0.0.1:9102/metrics \
  --metrics-url http://127.0.0.1:9101/metrics
```

The validator is the template's `neurons/validator.py` on
`tensorwire.compat.TemplateValidatorAdapter`: the kit runs the steps
(`TW_ROUND_INTERVAL_S`), the score store, weight setting with
`TW_WEIGHTS_VERSION_KEY`, and `/healthz`, `/readyz`, `/metrics` on
`TW_METRICS_BIND`. SIGTERM (or Ctrl-C) stops it cleanly.
