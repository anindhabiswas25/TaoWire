# The archived v10 subnet template, before and after

- `before/`: an unmodified copy of <https://github.com/latent-to/bittensor-subnet-template>
  at commit `539b77c30d60dea236ab1c48a3bde7f495caf516` (2026-07-10), MIT licence
  (`before/LICENSE`, Copyright (c) 2023 Opentensor). Nothing in it is changed.
- `after/`: the same subnet on `tensorwire.compat`, ported by hand (spec 10b.6,
  Phase 2). The changes and the lines they touched are listed in
  [`docs/migrations/template.md`](../../../docs/migrations/template.md).

`tensorwire migrate scan before/` is the input of the migration tests
(`python/tests/migration/test_migrate_scan.py`).
