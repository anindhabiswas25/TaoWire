# Quickstart: your first TaoWire subnet on a local chain

> **Alpha (0.1.0a1).** Not security-reviewed; APIs may change. For localnet and
> testnet, **not for mainnet value**. Feedback: [GitHub issues](https://github.com/anindhabiswas25/TaoWire/issues).

You will start a local Bittensor chain, scaffold a subnet project, run a
miner and a validator, and watch the validator's weights land on chain.
Target time: under 60 minutes. Everything runs on your machine; nothing
touches testnet or mainnet, and only public development keys are used.

| Step | Machine time (measured) |
|---|---|
| 0. Prerequisites | — |
| 1. Get TaoWire | 22 s (empty package cache) |
| 2. Start a local chain | about 3 min on a fresh chain (registrations retry), plus the image pull |
| 3. Create your subnet project | 6 s |
| 4. Configure the miner and the validator | — |
| 5. Check the setup | 2 s |
| 6–7. Run the miner and the validator | 5 s to the first weights |
| 8. See the weights on chain | 1 s |

Add your own reading and typing time.

## 0. Prerequisites

- Linux (x86-64). macOS works too, but use your LAN address instead of
  `127.0.0.2` below (step 4).
- Docker (the local chain runs in a container).
- `git`, Python 3.10–3.14 and [`uv`](https://docs.astral.sh/uv/).

## 1. Get TaoWire

The alpha is a pre-release: `pip install taowire` skips it, so name the
version (or pass `--pre`). One virtual environment holds the kit, its CLI and,
later, your subnet:

```bash
uv venv ~/taowire-env
. ~/taowire-env/bin/activate
uv pip install "taowire[all]==0.1.0a1"
taowire --version                        # taowire 0.1.0a1
```

The local-chain scripts live in the repository:

```bash
git clone --depth 1 https://github.com/anindhabiswas25/TaoWire.git ~/taowire-repo
export TAOWIRE_REPO=~/taowire-repo
```

Every new terminal below starts with `. ~/taowire-env/bin/activate`.

## 2. Start a local chain

```bash
LOCALNET_PYTHON="$(command -v python)" "$TAOWIRE_REPO/scripts/localnet_up.sh"
```

`LOCALNET_PYTHON` is the Python that sets the chain up (it needs `bittensor`,
which the environment from step 1 has).

This starts `subtensor-localnet` (fast 0.25 s blocks), creates a subnet,
development wallets (`owner`, `validator`, `miner_py`, ...), stakes the
validator so it gets a validator permit, and registers the miners. When it
finishes it prints the state directory, by default `~/.taowire/localnet`:

```bash
export LOCALNET_DIR="${LOCALNET_DIR:-$HOME/.taowire/localnet}"
cat "$LOCALNET_DIR/localnet.env"        # TW_NETWORK, TW_NETUID, TW_WALLET_PATH, ...
```

Running it again reuses the chain, the subnet and the wallets: every
development key comes from a fixed, public seed. On a fresh machine the
first run takes about two minutes (it also pulls the image).

Shell variables you set yourself must not start with `TW_`: TaoWire
refuses unknown `TW_*` names at startup (typo protection), which is why the
repository path above is `TAOWIRE_REPO`.

## 3. Create your subnet project

```bash
taowire init ~/my-subnet
cd ~/my-subnet
uv pip install -e '.[dev]'
pytest -q                                # 9 passed: miner, scoring and a validator round, in process
```

The project is the text-ops example subnet: validators send random text and
an operation (`upper`, `reverse`, `sha256`) to `POST /v1/transform`, miners
answer, validators score correct answers weighted by latency. Its files are
explained in its `README.md`; you replace them with your subnet's own task
later.

## 4. Configure the miner and the validator

All settings are `TW_*` environment variables (spec Section 12). Create one
file per process:

```bash
cat "$LOCALNET_DIR/localnet.env" > miner.env
cat >> miner.env <<'EOF'
TW_WALLET_NAME=miner_py
TW_EXTERNAL_IP=127.0.0.2
TW_BIND_HOST=127.0.0.2
TW_BIND_PORT=8091
TW_METRICS_BIND=127.0.0.1:9100
TW_STATE_DIR=./state/miner
TW_REFUSE_IF_COLDKEY_PRESENT=0
EOF

cat "$LOCALNET_DIR/localnet.env" > validator.env
cat >> validator.env <<'EOF'
TW_WALLET_NAME=validator
TW_METRICS_BIND=127.0.0.1:9101
TW_STATE_DIR=./state/validator
TW_ROUND_INTERVAL_S=12
TW_QUERY_VALIDATORS=1
TW_REFUSE_IF_COLDKEY_PRESENT=0
EOF
```

What these mean:

- `TW_EXTERNAL_IP=127.0.0.2`: the address the miner publishes on chain. The
  chain refuses `127.0.0.1`; any other `127.x.y.z` is loopback on Linux.
  `TW_ALLOW_PRIVATE_AXONS=1` (from `localnet.env`) lets validators accept a
  private address; never set it on testnet or mainnet.
- `TW_REFUSE_IF_COLDKEY_PRESENT=0`: the development wallets keep an
  unencrypted coldkey next to the hotkey. TaoWire refuses to start in
  that situation by default, because a server should only ever hold the
  hotkey. Localnet only; the process logs it as an unsafe setting.
- `TW_QUERY_VALIDATORS=1`: on a tiny local subnet, miners that receive
  weights soon hold validator permits too; this makes the validator query
  them anyway.

## 5. Check the setup

```bash
(set -a; . ./miner.env; set +a; taowire doctor --role miner)
(set -a; . ./validator.env; set +a; taowire doctor --role validator)
```

Every line should read `ok`, `WARN` or `skip`, none `FAIL`. Expected warnings
on localnet: the unsafe settings above, the unencrypted coldkey, the axon
(published when the miner starts) and the port (the miner is not running
yet). `doctor` exits with status 1 if anything fails, and says what to fix.

## 6. Run the miner (terminal 1)

```bash
cd ~/my-subnet
(set -a; . ./miner.env; set +a; exec python -m my_subnet.miner)
```

It logs JSON lines. Within a few seconds you see `axon_published` (it
published `127.0.0.2:8091` with protocol tag 87) and `miner_ready`.

## 7. Run the validator (terminal 2)

```bash
cd ~/my-subnet
(set -a; . ./validator.env; set +a; exec python -m my_subnet.validator)
```

Every 12 seconds it sends a task to the miners and logs `round ok` with
`n_ok` (miners that answered correctly, with a valid response signature).
When the chain's weights rate limit allows it, it logs `weights submitted`
with a block hash. On localnet subnets weights use commit-reveal: the
submission is a timelocked commit, and the weights apply when it reveals,
usually seconds later on fast blocks.

## 8. See the weights on chain

In a third terminal:

```bash
cd ~/my-subnet
set -a; . ./validator.env; set +a
python - <<'EOF'
import asyncio, os
import bittensor as bt

async def main() -> None:
    netuid = int(os.environ["TW_NETUID"])
    async with bt.Subtensor("local") as client:
        print("pending commits:", await client.weights.timelocked_weight_commits(netuid))
        print("weights (validator uid -> {miner uid: share}):", await client.weights.weights(netuid))

asyncio.run(main())
EOF
```

The validator's row lists the miner's UID with a non-zero share. That is the
whole loop: a signed request, a signed answer, a score, a weight on chain.

## 9. Stop

Press Ctrl-C in both terminals (the miner drains in-flight requests first).
`"$TAOWIRE_REPO/scripts/localnet_down.sh"` stops the chain.

## Before testnet or mainnet

The localnet settings above are not for public networks. Change these:

- Drop `TW_ALLOW_PRIVATE_AXONS` and `TW_REFUSE_IF_COLDKEY_PRESENT=0`. Copy
  only the hotkey to the server; the kit never needs the coldkey.
- `TW_EXTERNAL_IP` is the miner's public address; open only the miner port in
  the firewall. Keep `TW_METRICS_BIND` on 127.0.0.1 or a private network.
- More than one miner process (`TW_WORKERS > 1`) or host
  (`TW_INSTANCE_COUNT > 1`) needs Redis (`TW_REDIS_URL`) for the shared replay
  store and rate limits; the miner refuses to start without it. Run Redis
  where the miner reaches it directly (`docs/benchmarks.md` shows why).
- Set `TW_CHAIN_FALLBACKS` (or run your own lite node).
- `deploy/` has Docker images and hardened systemd units.

## Where next

- `docs/miner-guide.md`: routes, caller policy, limits, health and metrics.
- `docs/validator-guide.md`: `SubnetValidator`, scores, weights, the client.
- `docs/security.md`: what the kit defends against and what you still have to do.
- `docs/benchmarks.md`: throughput, latency and abuse-test numbers.
- `docs/migration-from-v10.md`: moving an existing v10 subnet onto TaoWire,
  and `docs/migration-rollout.md` for rolling it out.

## Measured

Followed as written on 2026-10-24 (Linux, Python 3.13 picked by `uv venv`, an
empty home directory and package cache, a fresh local chain), with the built
`taowire-0.1.0a1` wheel standing in for `taowire[all]==0.1.0a1` before the
upload. Every step worked; the first weights were committed 4 s after the
validator started and revealed within seconds (`{1: {2: 1.0}}`).
