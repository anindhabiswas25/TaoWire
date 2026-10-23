# Metrics and logs

## Prometheus metrics

Served on `TW_METRICS_BIND` (default `127.0.0.1:9100`), never on the public
miner port. Label values never contain hotkeys or IP addresses.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `tw_requests_total` | counter | `route`, `status`, `code` | Responses by registered route (`unmatched` for any other path), HTTP status and `tw.*` code (`ok` on success) |
| `tw_request_duration_seconds` | histogram | `route` | Time to answer |
| `tw_auth_verify_duration_seconds` | histogram | | btauth/1 verification, including the wait for a thread |
| `tw_auth_failures_total` | counter | `code` | 401 `tw.auth_*` rejections |
| `tw_policy_denials_total` | counter | `code` | 403 `tw.forbidden_*` and 503 `tw.metagraph_stale` |
| `tw_rate_limited_total` | counter | `layer` (`ip`/`hotkey`) | 429 rejections |
| `tw_payload_too_large_total` | counter | | 413 rejections |
| `tw_metagraph_age_seconds` | gauge | | Snapshot age (NaN before the first) |
| `tw_metagraph_refresh_failures_total` | counter | | Failed refreshes |
| `tw_metagraph_degraded` | gauge | | 0 fresh, 1 degraded, 2 known callers only |
| `tw_clock_offset_seconds` | gauge | | NTP offset (NaN when unknown) |
| `tw_clock_step_seconds` | gauge | | Size of the last backwards wall-clock step that opened the fail-closed window (D21); 0 when none since start |
| `tw_nonce_store_errors_total` | counter | `backend` | Replay-store outages (503 `tw.replay_store_unavailable`) |
| `tw_unsafe_settings_active` | gauge | `name` | 1 per active setting that weakens a default |
| `tw_legacy_v10_requests_total` | counter | `direction`, `result` | Legacy v10 bridge traffic |
| `tw_legacy_v10_days_remaining` | gauge | `direction` | Days to the bridge end date (`inbound`: `TW_LEGACY_V10_UNTIL`, `outbound`: `TW_LEGACY_V10_CLIENT_UNTIL`), computed at every scrape; alert below 14 |
| `tw_validator_miners_by_protocol` | gauge | `protocol` | Miners reached per protocol |
| `tw_validator_round_duration_seconds` | histogram | | Validator round duration |
| `tw_validator_miner_results_total` | counter | `ok`, `code` | Miner query results |
| `tw_validator_weight_submissions_total` | counter | `ok`, `code` | Weight submissions |
| `tw_validator_last_weights_block` | gauge | | Block of the last successful weights |

The legacy and validator metrics are registered by every process and filled
by the components that use them.

Suggested alerts: `tw_metagraph_degraded >= 1` for 15 minutes,
`tw_clock_offset_seconds` above 0.5 s, `tw_clock_step_seconds` above 0 (or
the `clock_step_detected` log event), any increase of
`tw_nonce_store_errors_total`, `tw_unsafe_settings_active` present in
production.

## Logs

One JSON object per line on stdout, for the kit and for the libraries it uses
(uvicorn, bittensor). Every line has `ts` (UTC, ISO 8601), `level`, `logger`
and `event`. Each request produces one line with `request_id`, `route`,
`caller_hotkey` (first 8 characters + `…`; the full hotkey only at
`TW_LOG_LEVEL=DEBUG`), `status`, `latency_ms` and `code`.

Bodies, signatures and signature header values are never logged. The
`request_id` is also returned to the caller in `X-TW-Request-Id` and in error
bodies, so a validator's report can be matched to the miner's log line.
