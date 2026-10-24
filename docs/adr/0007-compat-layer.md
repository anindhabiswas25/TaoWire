# ADR-0007: A v10-shaped compat layer is part of the kit

- Status: accepted
- Date: 2026-10-23 (Phase 2 implementation)
- Owner: Engineer A
- Spec: Section 7 (ADR-0007), 10b.2, 10b.6

## Context

Most v10 subnets are forks of the archived template: `Synapse` subclasses, a
miner that attaches `forward` / `blacklist` / `priority` to an Axon, and a
validator that calls a Dendrite, scores and sets weights. v11 removed all of
those types. If their shapes survive, a migration is mostly an import change.

## Decision

1. `taowire.compat` provides `Synapse` / `TerminalInfo` (v10 fields,
   order and defaults, `deserialize()`, `required_hash_fields`, status
   properties), `Axon` (over `Miner`), `Dendrite` (over `ValidatorClient`),
   `AxonInfo` / `axons_from`, a read-only v10-shaped `Metagraph` view, and
   `weights.to_mapping`. It is part of the main package and released with it.
2. **No security logic of its own.** Every request through `compat.Axon` goes
   through the full miner pipeline (spec 5.3) first: signature, freshness,
   replay, caller policy, rate limits. The team's `blacklist_fn` runs after
   the kit's policy, so it can only narrow access; `verify_fn` is refused.
3. `compat.Dendrite` keeps v10's call and return shapes, including
   `dendrite.status_code` on failures, but underneath every rule of the
   validator client applies (fresh signature per attempt, no transport
   retries, response cap, `twresp/1`, the v10 fallback when configured).
4. On btauth/1 only the Synapse's own fields travel; `dendrite` and `axon`
   are filled locally. On the legacy v10 path the whole Synapse is the body,
   as v10 expects.
5. Dependency direction: `compat` depends on `miner`, `validator` and
   `extensions.legacy_v10.wire` (which owns the v10 body-hash rule); the
   bridge never imports `compat`. Until the Phase 2 gate merges `wire.py`,
   `compat.Synapse.body_hash` carries the same rule, checked against every
   captured v10 vector (tracked in COORDINATION.md).

## Consequences

- The archived template runs on compat with its subnet logic unchanged
  (`docs/migrations/template.md`).
- `compat` is supported for the 1.x line and documented as "for migrating
  code"; new projects are pointed at `Miner` and `SubnetValidator`.
- Behaviour that v10 code relied on but that was unsafe (blacklist widening
  access, custom signature checks) is deliberately not reproduced.
