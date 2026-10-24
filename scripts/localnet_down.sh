#!/usr/bin/env bash
# Stop the local subtensor chain started by localnet_up.sh.
#
#   localnet_down.sh           stop the chain (its state is discarded: the container runs with --rm)
#   localnet_down.sh --purge   also delete $LOCALNET_DIR (dev wallets, localnet.json, localnet.env)
#
# --purge only deletes a directory that localnet_setup.py created (it holds the
# .taowire-localnet marker), so it can never remove real wallets.
set -euo pipefail

LOCALNET_CONTAINER="${LOCALNET_CONTAINER:-local_chain}"
LOCALNET_DIR="${LOCALNET_DIR:-$HOME/.taowire/localnet}"

purge=0
case "${1:-}" in
  "") ;;
  --purge) purge=1 ;;
  *) echo "usage: $0 [--purge]" >&2; exit 2 ;;
esac

if docker inspect "$LOCALNET_CONTAINER" >/dev/null 2>&1; then
  docker rm -f "$LOCALNET_CONTAINER" >/dev/null
  echo "[localnet] stopped $LOCALNET_CONTAINER"
else
  echo "[localnet] $LOCALNET_CONTAINER is not running"
fi

if [[ "$purge" == 1 && -d "$LOCALNET_DIR" ]]; then
  if [[ ! -f "$LOCALNET_DIR/.taowire-localnet" ]]; then
    echo "localnet_down: $LOCALNET_DIR was not created by localnet_setup.py; not deleting" >&2
    exit 1
  fi
  rm -rf -- "$LOCALNET_DIR"
  echo "[localnet] deleted $LOCALNET_DIR"
fi
