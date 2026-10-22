# TensorWire quality gates (spec 6.1). There is no CI yet: every check is one command.
# Steps for a language whose directory does not exist yet are skipped with a notice.

set shell := ["bash", "-euo", "pipefail", "-c"]

default: check

# the full local gate
check: lint typecheck test conformance

# install the Python dev environment (all extras: redis, ntp, migrate, dev)
setup:
    cd python && uv sync --all-extras

lint: setup
    cd python && uv run ruff check . && uv run ruff format --check . && uv run lint-imports
    if [ -f typescript/package.json ]; then cd typescript && npm run lint; else echo "skip: typescript/ not present yet"; fi
    if [ -f go/go.mod ]; then cd go && go vet ./... && staticcheck ./...; else echo "skip: go/ not present yet"; fi
    if [ -f rust/Cargo.toml ]; then cd rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings; else echo "skip: rust/ not present yet"; fi

typecheck: setup
    cd python && uv run mypy --strict src
    if [ -f typescript/package.json ]; then cd typescript && npm run typecheck; else echo "skip: typescript/ not present yet"; fi

test: setup
    cd python && uv run pytest tests/unit tests/property tests/integration
    if [ -f typescript/package.json ]; then cd typescript && npm test; else echo "skip: typescript/ not present yet"; fi
    if [ -f go/go.mod ]; then cd go && go test -race ./...; else echo "skip: go/ not present yet"; fi
    if [ -f rust/Cargo.toml ]; then cd rust && cargo test; else echo "skip: rust/ not present yet"; fi

# Python coverage (definition of done: >= 90% on auth/ policy/ limits/ ..., >= 80% elsewhere)
coverage: setup
    cd python && uv run coverage run -m pytest tests/unit tests/property tests/integration && uv run coverage report

# Each language's conformance runner lands in Phase 5; until then the step is skipped.
conformance: setup
    if [ -f python/src/tensorwire/cli/conformance_cmd.py ]; then cd python && uv run tensorwire conformance --vectors ../conformance/vectors; else echo "skip: tensorwire conformance not present yet (Phase 5)"; fi
    if [ -f typescript/package.json ]; then cd typescript && npm run conformance; else echo "skip: typescript/ not present yet"; fi
    if [ -f go/go.mod ]; then cd go && go test ./btauth -run Conformance; else echo "skip: go/ not present yet"; fi
    if [ -f rust/Cargo.toml ]; then cd rust && cargo test --test conformance; else echo "skip: rust/ not present yet"; fi

localnet-up:
    ./scripts/localnet_up.sh

localnet-test:
    cd python && uv run pytest -m localnet tests/localnet

interop:
    cd conformance/interop && uv run python run_matrix.py --network local

migration-test:
    cd python && uv run pytest tests/migration

mixed-fleet:
    ./scripts/legacy_venv.sh && cd python && uv run pytest -m "localnet and mixed_fleet" tests/localnet

bench:
    cd python && uv run tensorwire bench --duration 60

audit: setup
    cd python && uv run pip-audit
    if [ -f typescript/package.json ]; then cd typescript && npm audit --audit-level=high; else echo "skip: typescript/ not present yet"; fi
    if [ -f go/go.mod ]; then cd go && govulncheck ./...; else echo "skip: go/ not present yet"; fi
    if [ -f rust/Cargo.toml ]; then cd rust && cargo audit; else echo "skip: rust/ not present yet"; fi
