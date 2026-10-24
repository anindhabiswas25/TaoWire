#!/usr/bin/env bash
# Create the separate bittensor==10.5.0 virtualenv (ADR-0008, spec 10b.6).
#
# bittensor 10.x and 11.x cannot share an environment, so v10 code (vector
# capture, the mixed-fleet tests) runs from its own venv, outside the repo.
# Dependencies are installed from a hash-locked file, never resolved live.
#
#   legacy_venv.sh           create or check the venv; the last line printed is its python
#   legacy_venv.sh --relock  regenerate scripts/legacy_v10.requirements.txt
#
# Settings (environment):
#   LEGACY_VENV_DIR   default ~/.taowire/venvs/bittensor-10.5.0
#   LEGACY_PYTHON     interpreter version for the venv, default 3.12
set -euo pipefail

LEGACY_VERSION="10.5.0"
LEGACY_VENV_DIR="${LEGACY_VENV_DIR:-$HOME/.taowire/venvs/bittensor-$LEGACY_VERSION}"
LEGACY_PYTHON="${LEGACY_PYTHON:-3.12}"

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="$scripts_dir/legacy_v10.requirements.txt"

die() { echo "legacy_venv: $*" >&2; exit 1; }
command -v uv >/dev/null || die "uv is required (https://docs.astral.sh/uv/)"

if [[ "${1:-}" == "--relock" ]]; then
  input="$(mktemp)"
  trap 'rm -f "$input"' EXIT
  echo "bittensor==$LEGACY_VERSION" >"$input"
  uv pip compile --quiet --universal --generate-hashes --python-version "$LEGACY_PYTHON" \
    --no-header --custom-compile-command "scripts/legacy_venv.sh --relock" \
    "$input" -o "$lock"
  echo "wrote $lock"
  exit 0
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--relock]" >&2
  exit 2
fi

[[ -f "$lock" ]] || die "missing $lock; run $0 --relock"
python="$LEGACY_VENV_DIR/bin/python"

installed_version() {
  "$python" -I -c 'import importlib.metadata as m; print(m.version("bittensor"))' 2>/dev/null || true
}

if [[ -x "$python" && "$(installed_version)" == "$LEGACY_VERSION" ]]; then
  echo "[legacy] bittensor $LEGACY_VERSION venv ready at $LEGACY_VENV_DIR" >&2
else
  echo "[legacy] creating $LEGACY_VENV_DIR (Python $LEGACY_PYTHON, bittensor $LEGACY_VERSION)" >&2
  rm -rf -- "$LEGACY_VENV_DIR"
  mkdir -p "$(dirname "$LEGACY_VENV_DIR")"
  uv venv --quiet --python "$LEGACY_PYTHON" "$LEGACY_VENV_DIR"
  uv pip install --quiet --python "$python" --require-hashes -r "$lock"
  [[ "$(installed_version)" == "$LEGACY_VERSION" ]] || die "bittensor $LEGACY_VERSION did not install"
fi
echo "$python"
