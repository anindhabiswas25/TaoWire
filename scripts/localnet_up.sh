#!/usr/bin/env bash
# Start a local subtensor chain and prepare it for TensorWire (spec Section 14).
#
# Result: a started subnet (netuid 2 on a fresh chain) with a validator that
# holds a validator permit and four registered miners, plus
#   $LOCALNET_DIR/wallets/       dev wallets (public seeds, localnet only)
#   $LOCALNET_DIR/localnet.json  netuid, addresses, UIDs
#   $LOCALNET_DIR/localnet.env   TW_NETWORK / TW_NETUID / TW_WALLET_PATH / TW_ALLOW_PRIVATE_AXONS
# Running it again reuses the chain and changes nothing that is already done.
#
# Settings (environment):
#   LOCALNET_IMAGE       default ghcr.io/raofoundation/subtensor-localnet
#   LOCALNET_TAG         default devnet; use "testnet" before a testnet run (14.2)
#   LOCALNET_FAST_BLOCKS default 1 (0.25 s blocks); 0 = real 12 s blocks
#   LOCALNET_CONTAINER   default local_chain
#   LOCALNET_DIR         default ~/.tensorwire/localnet (never ~/.bittensor)
#   LOCALNET_PYTHON      Python with bittensor 11.x; default: uv run in ./python
set -euo pipefail

LOCALNET_IMAGE="${LOCALNET_IMAGE:-ghcr.io/raofoundation/subtensor-localnet}"
LOCALNET_TAG="${LOCALNET_TAG:-devnet}"
LOCALNET_FAST_BLOCKS="${LOCALNET_FAST_BLOCKS:-1}"
LOCALNET_CONTAINER="${LOCALNET_CONTAINER:-local_chain}"
LOCALNET_DIR="${LOCALNET_DIR:-$HOME/.tensorwire/localnet}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "localnet_up: $*" >&2; exit 1; }
log() { echo "[localnet] $*"; }

command -v docker >/dev/null || die "docker is required"

if [[ -n "${LOCALNET_PYTHON:-}" ]]; then
  read -r -a python_cmd <<<"$LOCALNET_PYTHON"
elif [[ -f "$repo_root/python/pyproject.toml" ]] && command -v uv >/dev/null; then
  python_cmd=(uv run --project "$repo_root/python" python)
else
  die "set LOCALNET_PYTHON to a Python with bittensor>=11.3,<12 installed"
fi

case "$LOCALNET_FAST_BLOCKS" in
  1) chain_args=() ;;
  0) chain_args=(False) ;;
  *) die "LOCALNET_FAST_BLOCKS must be 0 or 1" ;;
esac

state="$(docker inspect -f '{{.State.Running}}' "$LOCALNET_CONTAINER" 2>/dev/null || true)"
if [[ "$state" == "true" ]]; then
  running_image="$(docker inspect -f '{{.Config.Image}}' "$LOCALNET_CONTAINER")"
  [[ "$running_image" == "$LOCALNET_IMAGE:$LOCALNET_TAG" ]] ||
    die "container $LOCALNET_CONTAINER runs $running_image, not $LOCALNET_IMAGE:$LOCALNET_TAG; run localnet_down.sh first"
  log "reusing running container $LOCALNET_CONTAINER ($running_image)"
else
  if [[ -n "$state" ]]; then
    docker rm -f "$LOCALNET_CONTAINER" >/dev/null
  fi
  for port in 9944 9945; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      die "port $port is already in use"
    fi
  done
  log "starting $LOCALNET_IMAGE:$LOCALNET_TAG as $LOCALNET_CONTAINER (fast blocks: $LOCALNET_FAST_BLOCKS)"
  docker run -d --rm --name "$LOCALNET_CONTAINER" \
    -p 127.0.0.1:9944:9944 -p 127.0.0.1:9945:9945 \
    "$LOCALNET_IMAGE:$LOCALNET_TAG" "${chain_args[@]}" >/dev/null
fi

"${python_cmd[@]}" -I "$repo_root/scripts/localnet_setup.py" \
  --state-dir "$LOCALNET_DIR" --endpoint ws://127.0.0.1:9944

log "env file: $LOCALNET_DIR/localnet.env"
