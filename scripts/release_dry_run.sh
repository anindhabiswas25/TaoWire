#!/usr/bin/env bash
# Release dry run (spec 18.4 items 3-4, 18.5): build every package from the
# committed tree, check each one the way its registry will, and write
# SHA256SUMS. Nothing is uploaded, no tag is created, no registry login is used.
#
#   scripts/release_dry_run.sh [OUT]      # default dist/release-<python version>
#
# Python: uv build + twine check --strict. npm: npm pack, installed into a
# temporary project with its optional peers, then scripts/smoke-installed.mjs.
# Rust: cargo package (with verification) + cargo publish --dry-run, all
# features. Go: go mod tidy leaves no diff, go vet, and the committed module
# (git archive) builds outside the repository, alone and from a consumer
# module through a replace directive. Logs go to OUT/logs.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' python/src/taowire/version.py)"
out="$(realpath -m "${1:-dist/release-$version}")"
TWINE="${TWINE:-twine==6.2.0}"
FASTIFY="${FASTIFY:-fastify@5.12.7}"
IOREDIS="${IOREDIS:-ioredis@6.0.0}"

die() { echo "release_dry_run: $*" >&2; exit 1; }
step() { echo "== $*"; }
[[ -z "$(git status --porcelain -- python typescript rust go)" ]] ||
  die "uncommitted changes in a package directory; the artifacts must match a commit"
# Only ever replace an earlier dry run (it has a COMMIT file) or an empty directory.
if [[ -e "$out" && ! -f "$out/COMMIT" && -n "$(ls -A "$out")" ]]; then
  die "$out exists and is not an earlier dry run; refusing to delete it"
fi
rm -rf "$out"
mkdir -p "$out"/{python,npm,rust,go,logs}
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export GOTOOLCHAIN=local
PATH="$(./scripts/go_tools.sh sdk-path)/bin:$PATH"

step "python: uv build + twine check"
(cd python && env -u VIRTUAL_ENV uv build --out-dir "$out/python") >"$out/logs/uv-build.txt" 2>&1
uvx --from "$TWINE" twine check --strict "$out"/python/* >"$out/logs/twine-check.txt" 2>&1

step "npm: npm pack, install into a temporary project, smoke test"
(cd typescript && npm ci --no-fund --no-audit && npm run build && npm pack --pack-destination "$out/npm") \
  >"$out/logs/npm-pack.txt" 2>&1
tarball="$(ls "$out"/npm/*.tgz)"
mkdir "$scratch/npm-smoke"
cp typescript/scripts/smoke-installed.mjs "$scratch/npm-smoke/"
(cd "$scratch/npm-smoke" && npm init -y >/dev/null &&
  npm install --no-fund --no-audit "$tarball" "$FASTIFY" "$IOREDIS" && node smoke-installed.mjs) \
  >"$out/logs/npm-install-smoke.txt" 2>&1

step "rust: cargo package (verified) + cargo publish --dry-run"
(cd rust && cargo package --all-features) >"$out/logs/cargo-package.txt" 2>&1
(cd rust && cargo publish --dry-run --all-features) >"$out/logs/cargo-publish-dry-run.txt" 2>&1
cp rust/target/package/taowire-btauth-*.crate "$out/rust/"

step "go: tidy, vet, standalone build"
{
  go version
  (cd go && go mod tidy) && git diff --exit-code -- go/go.mod go/go.sum && echo "go mod tidy: no changes"
  (cd go && go vet ./...) && echo "go vet: ok"
  mkdir "$scratch/taowire-go" "$scratch/consumer"
  git archive HEAD:go | tar -x -C "$scratch/taowire-go"
  (cd "$scratch/taowire-go" && GOFLAGS=-mod=mod go build ./... && GOFLAGS=-mod=mod go vet ./...) &&
    echo "the committed module builds and vets outside the repository"
  module="$(sed -n 's/^module //p' go/go.mod)"
  printf 'module example.com/consumer\n\ngo 1.22\n\nrequire %s v0.0.0\n\nreplace %s => ../taowire-go\n' \
    "$module" "$module" >"$scratch/consumer/go.mod"
  printf 'package main\n\nimport (\n\t"fmt"\n\n\t"%s/btauth"\n\t"%s/sidecar"\n)\n\nfunc main() {\n\t_ = sidecar.New\n\tfmt.Println(btauth.Protocol, btauth.RespProtocol)\n}\n' \
    "$module" "$module" >"$scratch/consumer/main.go"
  (cd "$scratch/consumer" && GOFLAGS=-mod=mod go build -o consumer . && ./consumer) &&
    echo "a consumer module builds against it through a replace directive"
  echo "module $module, tree $(git rev-parse HEAD:go) at $(git rev-parse HEAD)"
} >"$out/logs/go-module.txt" 2>&1
# The Go proxy builds the module zip from the tag; record what the tag will point at.
git archive --format=tar.gz --prefix=go/ -o "$out/go/taowire-go-$(git rev-parse --short HEAD).tar.gz" HEAD:go

step "SHA256SUMS"
(cd "$out" && sha256sum python/* npm/* rust/* go/* >SHA256SUMS)
git rev-parse HEAD >"$out/COMMIT"
cat "$out/SHA256SUMS"
echo "release dry run OK: $out (commit $(cat "$out/COMMIT"))"
