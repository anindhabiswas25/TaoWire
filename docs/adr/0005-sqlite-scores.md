# ADR-0005: SQLite for validator score state

- Status: accepted
- Date: 2026-10-23 (Phase 2 implementation)
- Owner: Engineer A
- Spec: Section 7 (ADR-0005), 8.9

## Context

A validator's scores are an EMA built over many rounds. Losing them on a
restart resets every miner to zero and distorts weights for hours. The state
is small (one row per UID), written by one process, and must survive crashes.

## Decision

1. `taowire.validator.scores.ScoreStore` keeps the state in
   `TW_STATE_DIR/scores.db` (directory mode 0700), SQLite in WAL mode with
   `synchronous=NORMAL`, the schema of spec 8.9 (`scores`, `rounds`,
   `weight_submissions`).
2. One writer: the validator process. The validator holds an exclusive lock
   per hotkey (`TW_STATE_DIR/locks/<hotkey>.lock`), so a second process with
   the same hotkey cannot start on the host (it would also collide on nonces,
   spec 8.4.1).
3. EMA per UID, `s = α·new + (1−α)·s` with `α = TW_SCORE_ALPHA`; values
   clamped to [0, 1]. A UID whose hotkey changed starts from zero; UIDs that
   left the metagraph are dropped (`sync_hotkeys` each round).
4. Calls are synchronous and short; the async loop runs them in a worker
   thread.

## Consequences

- No Redis or external database for validators; backups are a file copy.
- Several validator processes cannot share one score store; a validator is
  one process by design (one hotkey = one signing process).
- The store is per subnet (`netuid` in every key), so one state directory can
  serve validators on different subnets.
