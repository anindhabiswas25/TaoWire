# The sidecar (`tensorwire sidecar`)

A miner written in TypeScript, Go or Rust verifies btauth/1 and signs twresp/1 itself (its language package),
but it does not talk to the chain. The **sidecar** does that part for it: a small Python service, on the same
host, that holds the miner's hotkey, follows the metagraph and publishes the miner's axon (spec 11.6).

```
validator ──btauth/1──▶ Go / Rust / TS miner ──loopback, bearer token──▶ tensorwire sidecar ──▶ chain
```

## Run it

```bash
pip install tensorwire            # the Python package (it brings the CLI)
export TW_NETWORK=finney TW_NETUID=42 TW_WALLET_NAME=miner TW_WALLET_HOTKEY=default
tensorwire sidecar                # 127.0.0.1:9910; writes the token on first run
```

The first run creates `$TW_STATE_DIR/sidecar.token` (mode 0600) and logs its path, never the token. Point the
miner's sidecar client at the same file (`TW_SIDECAR_TOKEN_FILE`), as the same Unix user or a group-less copy
the miner's user owns. The sidecar refuses to start when:

- `--host` is not `127.0.0.1` or `::1` (override: `TW_SIDECAR_UNSAFE_BIND=1`, logged at WARNING and exported
  as `tw_unsafe_settings_active{name="TW_SIDECAR_UNSAFE_BIND"}`; the token and the chain writes then travel over
  a network — do not);
- the token file exists but is a symbolic link, not a regular file, readable or writable by group or others,
  or not 16–1024 printable ASCII characters;
- an unencrypted coldkey is readable next to the hotkey (`TW_REFUSE_IF_COLDKEY_PRESENT`, as for the miner);
- the hotkey file is missing, or no metagraph arrives within `TW_STARTUP_TIMEOUT_S`.

Exit codes: 2 for invalid settings, 1 for a refused startup.

## Settings

| Variable | Default | Notes |
|---|---|---|
| `TW_SIDECAR_PORT` | `9910` | `--port` overrides it |
| `TW_SIDECAR_TOKEN_FILE` | `$TW_STATE_DIR/sidecar.token` | generated with mode 0600 when missing |
| `TW_SIDECAR_UNSAFE_BIND` | `0` | `1` allows a `--host` other than loopback (unsafe) |
| `TW_NETUID`, `TW_WALLET_*`, `TW_NETWORK`, `TW_CHAIN_*`, `TW_METAGRAPH_*`, `TW_STARTUP_TIMEOUT_S`, `TW_METRICS_BIND`, `TW_PROTOCOL_TAG`, `TW_ALLOW_PRIVATE_AXONS` | spec 12.1 | the chain side, as for every TensorWire process |
| `TW_REQUIRE_PERMIT`, `TW_MIN_CALLER_STAKE_TAO`, `TW_ALLOW_HOTKEYS`, `TW_DENY_HOTKEYS`, `TW_METAGRAPH_STRICT` | spec 12.2 | the policy of `GET /v1/caller` |

Metrics (`TW_METRICS_BIND`, default `127.0.0.1:9100`; give the miner and the sidecar different ports on one
host): `tw_unsafe_settings_active`, `tw_metagraph_refresh_failures_total`.

## API

The four endpoints, their JSON shapes and error codes are the contract in
[multi-language.md, "Sidecar API"](multi-language.md#sidecar-api-spec-116). Summary:

| Endpoint | What for |
|---|---|
| `GET /v1/health` | the sidecar's hotkey, netuid, block and snapshot stage; the clients check the hotkey is the miner's |
| `GET /v1/metagraph?netuid=N` | the snapshot with its age and tempo; the clients cache it (60 s) and apply the 8.5.1 stages themselves |
| `GET /v1/caller/{hotkey}?netuid=N` | the sidecar's own policy decision (for miners that prefer not to keep a cache) |
| `POST /v1/serve-axon` | publish `ip:port` (and a TLS key) for the hotkey, on the configured netuid only; sent once |

Every request needs `Authorization: Bearer <token>` (401 `tw.sidecar_unauthorized` otherwise). There is no
weight setting through the sidecar.

## Clients

| Language | Package | Start |
|---|---|---|
| TypeScript | `@tensorwire/btauth/sidecar` | `new SidecarClient({ netuid, tokenFile, expectedHotkey })`, `await start()`, `policy: sidecar.policyHook()` |
| Go | `github.com/tensorwire/tensorwire/go/sidecar` | `sidecar.New(sidecar.Config{...})`, `Start(ctx)`, `MiddlewareConfig{Policy: sc.Policy()}` |
| Rust | `tensorwire-btauth`, feature `sidecar` | `SidecarClient::new(Config {...})`, `start().await`, `MinerAuth::with_policy(sc.policy())` |

Without a chain, `conformance/interop/sidecar_check.py` runs all three against a FakeChain-backed sidecar
(evidence in `reports/phase-5/sidecar-interop/`).

## Security notes

- The sidecar holds the hotkey; the miner process does not need the chain or the wallet directory beyond its
  own hotkey for signing.
- The bearer token stops another local user (or a browser page doing DNS rebinding against `127.0.0.1`) from
  publishing an axon for your hotkey. Keep the token file owner-only.
- `POST /v1/serve-axon` publishes for the configured netuid only; addresses go through the same `parse_axon`
  rules as everything else (`TW_ALLOW_PRIVATE_AXONS=1` on localnet only).
