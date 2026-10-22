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
#   LOCALNET_FALLBACK    default 1: if setup on a chain this run started with fast
#                        blocks keeps failing on transient errors (forks, expired
#                        eras), restart the chain with 12 s blocks and set up again.
#                        0 = fail instead.
#   LOCALNET_CONTAINER   default local_chain
#   LOCALNET_DIR         default ~/.tensorwire/localnet (never ~/.bittensor)
#   LOCALNET_PYTHON      Python with bittensor 11.x; default: uv run in ./python
set -euo pipefail

LOCALNET_IMAGE="${LOCALNET_IMAGE:-ghcr.io/raofoundation/subtensor-localnet}"
LOCALNET_TAG="${LOCALNET_TAG:-devnet}"
LOCALNET_FAST_BLOCKS="${LOCALNET_FAST_BLOCKS:-1}"
LOCALNET_FALLBACK="${LOCALNET_FALLBACK:-1}"
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
  0|1) ;;
  *) die "LOCALNET_FAST_BLOCKS must be 0 or 1" ;;
esac
case "$LOCALNET_FALLBACK" in
  0|1) ;;
  *) die "LOCALNET_FALLBACK must be 0 or 1" ;;
esac

# Exit code of localnet_setup.py when a step failed on transient errors only.
EXIT_TRANSIENT=75

start_chain() {  # $1 = 1 for fast blocks, 0 for 12 s blocks
  local args=()
  [[ "$1" == 0 ]] && args=(False)
  log "starting $LOCALNET_IMAGE:$LOCALNET_TAG as $LOCALNET_CONTAINER (fast blocks: $1)"
  docker run -d --rm --name "$LOCALNET_CONTAINER" \
    -p 127.0.0.1:9944:9944 -p 127.0.0.1:9945:9945 \
    "$LOCALNET_IMAGE:$LOCALNET_TAG" "${args[@]}" >/dev/null
}

run_setup() {
  "${python_cmd[@]}" -I "$repo_root/scripts/localnet_setup.py" \
    --state-dir "$LOCALNET_DIR" --endpoint ws://127.0.0.1:9944
}

started_here=0
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
  start_chain "$LOCALNET_FAST_BLOCKS"
  started_here=1
fi

status=0
run_setup || status=$?
if [[ "$status" == "$EXIT_TRANSIENT" && "$started_here" == 1 &&
      "$LOCALNET_FAST_BLOCKS" == 1 && "$LOCALNET_FALLBACK" == 1 ]]; then
  # The chain was created by this run, so nothing on it is worth keeping.
  log "fast-block setup kept failing on transient errors; falling back to 12 s blocks"
  docker rm -f "$LOCALNET_CONTAINER" >/dev/null
  until ! (exec 3<>"/dev/tcp/127.0.0.1/9944") 2>/dev/null; do sleep 1; done
  start_chain 0
  status=0
  run_setup || status=$?
fi
[[ "$status" == 0 ]] || die "setup failed (exit $status)"

log "env file: $LOCALNET_DIR/localnet.env"
