# Deploying TensorWire

Reference files for running a TensorWire miner, validator or sidecar (spec 5.5,
15.3, 16.4). Pick one of the following: container images, the localnet compose
stack, or systemd units on a plain host.

| Path | What it is |
|---|---|
| `docker/miner.Dockerfile`, `docker/validator.Dockerfile` | Kit + one subnet package, run as uid 10001 |
| `docker/sidecar.Dockerfile` | `tensorwire sidecar` for non-Python miners (the command ships in Phase 5) |
| `docker/healthcheck.py` | Image `HEALTHCHECK`: `GET /healthz` on the port the process really uses |
| `compose/localnet.yml` | Chain + Redis + miner + validator on a local chain (dev keys only) |
| `compose/testnet-node.yml` | Your own testnet lite node for a validator host (never started by tests) |
| `systemd/tensorwire-{miner,validator,sidecar}.service` | Hardened units for a plain Linux host |

## Keys: what goes where

Create every coldkey on a trusted workstation. A server gets **only** the
hotkey file of the wallet it runs as, never the coldkey (spec 15.3). The kit
refuses to start when it finds a coldkey next to the hotkey
(`TW_REFUSE_IF_COLDKEY_PRESENT`, default on).

```
<TW_WALLET_PATH>/<TW_WALLET_NAME>/hotkeys/<TW_WALLET_HOTKEY>
```

- Directories `0700`, hotkey file `0600`, owned by the user that runs the process.
- Images contain no wallet at all. Mount the single hotkey file **read-only**:
  `-v /srv/keys/miner/hotkeys/default:/run/tensorwire/wallets/miner/hotkeys/default:ro`
  (`TW_WALLET_PATH=/run/tensorwire/wallets` is set in the image).
- systemd units read the hotkey from `/etc/tensorwire/wallets/...`, which
  `ProtectSystem=strict` keeps read-only for the service.
- Other secrets (`TW_REDIS_URL` with a password) come from the environment:
  a secrets manager, `docker run --env-file` with a `0600` file, or the unit's
  `EnvironmentFile=` (`0640 root:tensorwire`). Never bake them into an image.

## Container images

Build context is the repository root. Base images are pinned by digest (the
`PYTHON_IMAGE` and `UV_IMAGE` build arguments). Dependencies are installed
exactly as locked (`uv sync --frozen`).

```bash
docker build -f deploy/docker/miner.Dockerfile -t tensorwire-miner .
docker build -f deploy/docker/validator.Dockerfile -t tensorwire-validator .
docker build -f deploy/docker/sidecar.Dockerfile -t tensorwire-sidecar .

# Your own subnet package instead of the text-ops example (its dependencies
# must already be in python/uv.lock; it is installed with --no-deps):
docker build -f deploy/docker/miner.Dockerfile \
  --build-context subnet=path/to/your-subnet -t my-miner .
docker run ... my-miner your_pkg.miner        # the module to run
```

To bump a base image, read the new digest with
`docker buildx imagetools inspect python:3.12-slim-bookworm`, update the `ARG`
in all three Dockerfiles, rebuild, and run the localnet stack once.

Run a miner (production shape):

```bash
docker run -d --name miner --restart unless-stopped \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -v miner-state:/var/lib/tensorwire \
  -v /srv/keys/miner/hotkeys/default:/run/tensorwire/wallets/miner/hotkeys/default:ro \
  --env-file /etc/tensorwire/miner.env \
  -p 8091:8091 -p 127.0.0.1:9100:9100 \
  tensorwire-miner
```

with `TW_METRICS_BIND=0.0.0.0:9100` in `miner.env` so the published loopback
port reaches it. Inside a bridge network, `127.0.0.1` is the container's own
loopback. Ports:

| Process | Port | Expose |
|---|---|---|
| miner | `TW_BIND_PORT` (8091): the subnet routes plus `/healthz`, `/readyz` | internet (the address published on chain) |
| miner | `TW_METRICS_BIND` (9100): `/metrics` | host loopback or your monitoring network only |
| validator | `TW_METRICS_BIND` (9100): `/metrics`, `/healthz`, `/readyz` | host loopback or your monitoring network only |
| sidecar | `TW_SIDECAR_PORT` (9910) | never: it binds 127.0.0.1, so share the miner's network namespace (`network_mode: "service:<miner>"`) |

Stop with `SIGTERM`. The miner drains for `TW_DRAIN_S` (default 10 s), so give
`docker stop` at least that (`--stop-timeout 30`).

## Localnet stack (dev keys only)

`compose/localnet.yml` runs the pinned `subtensor-localnet` chain, Redis (for
the miner's nonce store) and a miner and validator built from the Dockerfiles
above. The miner and validator use host networking: the chain refuses
`127.0.0.1` as an axon IP, so the miner serves on `127.0.0.2` (Linux).

```bash
# Chain from scripts/localnet_up.sh (default; compose does not manage it):
scripts/localnet_up.sh
docker compose -f deploy/compose/localnet.yml --profile nodes up -d --build --no-deps redis miner validator
docker compose -f deploy/compose/localnet.yml --profile nodes down

# Or let compose start the chain and have localnet_up.sh reuse it:
docker compose -f deploy/compose/localnet.yml up -d chain redis
LOCALNET_TAG=devnet@sha256:0dd5335b49ed3a20431dc404ddf375f17d2219094457f00e12c12181959f9345 \
  scripts/localnet_up.sh
docker compose -f deploy/compose/localnet.yml --profile nodes up -d --build
```

The node containers run as `LOCALNET_UID` (default 1000), because
`localnet_setup.py` writes the dev hotkeys `0600` for the user who ran it.
Production images run as 10001. Set `LOCALNET_FAST_RUNTIME=False` for 12 s
blocks. The validator picks up a newly published miner axon at its next
metagraph refresh (`TW_METAGRAPH_REFRESH_S`, default 120 s).

## Testnet lite node (validator host)

`compose/testnet-node.yml` runs your own subtensor testnet lite node (spec
15.3, `val-1`). RPC is published on the host's loopback only and P2P (30333)
is public. Point the validator at it with `TW_NETWORK=ws://127.0.0.1:9944` and
keep `TW_CHAIN_FALLBACKS=test`. Warp sync takes minutes to hours. It needs
about 4 vCPU, 16+ GB RAM and fast disk.

## systemd (plain host)

```bash
# As root, on the server:
useradd --system --home-dir /var/lib/tensorwire-miner --shell /usr/sbin/nologin tensorwire

# The kit and your subnet package, exactly as locked:
install -d -m 0755 /opt/tensorwire
UV_PROJECT_ENVIRONMENT=/opt/tensorwire/venv uv sync --frozen --no-dev --no-editable \
  --extra redis --extra ntp --project /path/to/tensorwire/python
uv pip install --python /opt/tensorwire/venv/bin/python --no-deps /path/to/your-subnet

# Settings and the hotkey (copied from the workstation, never the coldkey):
install -d -m 0750 -o root -g tensorwire /etc/tensorwire
install -m 0640 -o root -g tensorwire miner.env /etc/tensorwire/miner.env
install -d -m 0700 -o tensorwire -g tensorwire \
  /etc/tensorwire/wallets /etc/tensorwire/wallets/miner /etc/tensorwire/wallets/miner/hotkeys
install -m 0600 -o tensorwire -g tensorwire default /etc/tensorwire/wallets/miner/hotkeys/default

install -m 0644 deploy/systemd/tensorwire-miner.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tensorwire-miner
journalctl -u tensorwire-miner -f          # JSON logs
systemd-analyze security tensorwire-miner  # exposure ~1.2 "OK"
```

`miner.env` holds the `TW_*` settings (`TW_NETWORK`, `TW_NETUID`,
`TW_WALLET_NAME`, `TW_EXTERNAL_IP`, ...). The unit sets `TW_WALLET_PATH` and
`TW_STATE_DIR` itself. Change the module (`TENSORWIRE_MODULE`, default
`text_ops.miner`) or limits with `systemctl edit tensorwire-miner`. Exit codes 2
(invalid settings) and 3 (hotkey not registered) are not restarted. Fix the
cause, then `systemctl restart`.

The units sandbox the process: no capabilities, `NoNewPrivileges`, read-only
OS (`ProtectSystem=strict`) with one writable state directory, no home
directories, private `/tmp` and `/dev`, no kernel tunables, modules, logs or
clock, IPv4/IPv6/Unix sockets only, no W+X memory, and a `@system-service`
syscall filter without `@privileged` and `@resources`. The kit's whole stack
(bittensor's Rust extensions, pydantic-core, cryptography, uvicorn) runs under
all of it. If you add a dependency that JIT-compiles code (some ML runtimes do),
it will fail with `MemoryDenyWriteExecute=yes`; turn that option off for that
unit with a drop-in, not in the shipped file.

## Host hardening checklist (spec 16.4)

The kit cannot enforce these. Check them per host.

- [ ] Processes run as a dedicated non-root user (images: uid 10001; systemd: `tensorwire`).
- [ ] Wallet directories `0700`, hotkey files `0600`; only the hotkey is on the server.
- [ ] Secrets come from a secrets manager or environment injection, never from the image or the repo.
- [ ] Automatic security updates on (`unattended-upgrades` or your distribution's equivalent).
- [ ] Time sync on (chrony or systemd-timesyncd). The kit refuses to start on large clock skew (spec 8.4.4).
- [ ] Validator and miners on separate hosts.
- [ ] Never run untrusted subnet code on a machine that holds a coldkey.
- [ ] Firewall (spec 15.3): miners open only their miner ports to the internet. Metrics and sidecar ports stay on loopback. SSH by key only.
- [ ] A miner with `TW_WORKERS > 1` (or several instances) has `TW_REDIS_URL` set, so replays are detected across workers.
