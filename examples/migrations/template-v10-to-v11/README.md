# The archived v10 subnet template, before and after

- `before/`: an unmodified copy of <https://github.com/latent-to/bittensor-subnet-template>
  at commit `539b77c30d60dea236ab1c48a3bde7f495caf516` (2026-07-10), MIT licence
  (`before/LICENSE`, Copyright (c) 2023 Opentensor). Nothing in it is changed.
- `after/`: the same subnet on `taowire.compat`: `taowire migrate apply`
  run on `before/`, plus `hand-fixes.patch` (what a person changed by hand).
  The changes and the S6 count are in
  [`docs/migrations/template.md`](../../../docs/migrations/template.md).
- `golden.py`: rebuilds `hand-fixes.patch` (`python golden.py write`) and
  prints the S6 count (`python golden.py s6`).

`python/tests/migration/test_template_golden.py` checks that `before/` +
`apply` + `hand-fixes.patch` is `after/` byte for byte;
`test_migrate_scan.py` scans `before/`.

## Running `after/` on localnet

Everything comes from `TW_*` variables (spec Section 12); the template's own
options (`--neuron.*`, `--blacklist.*`) still work on the command line. With
the localnet from `scripts/localnet_up.sh` (`~/.taowire/localnet/localnet.env`
has `TW_NETWORK`, `TW_NETUID`, `TW_WALLET_PATH`, `TW_ALLOW_PRIVATE_AXONS`):

```bash
cd examples/migrations/template-v10-to-v11/after
set -a; . ~/.taowire/localnet/localnet.env; set +a
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

taowire migrate status --metrics-url http://127.0.0.1:9102/metrics \
  --metrics-url http://127.0.0.1:9101/metrics
```

The validator is the template's `neurons/validator.py` on
`taowire.compat.TemplateValidatorAdapter`: the kit runs the steps
(`TW_ROUND_INTERVAL_S`), the score store, weight setting with
`TW_WEIGHTS_VERSION_KEY`, and `/healthz`, `/readyz`, `/metrics` on
`TW_METRICS_BIND`. SIGTERM (or Ctrl-C) stops it cleanly.
