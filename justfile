# TensorWire quality gates (spec 6.1). There is no CI yet: every check is one command.
# Steps for a language whose directory does not exist yet are skipped with a notice.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Go (spec 11.4, D23): go.mod keeps the `go 1.22` directive for users; development,
# release builds and `just audit` use a supported toolchain, for this project only. The
# versions live in scripts/go_tools.sh (SDK default ~/sdk/go1.26.10; TENSORWIRE_GO_SDK
# overrides it) and the tools from `just go-tools` in .tools/go/bin. Nothing outside the
# repo changes. G5-3: Go recipes depend on `go-sdk` (the SDK is the pinned Go) or
# `go-ensure` (also builds missing or stale tools), and tools run through
# `go_tools.sh run`, so nothing falls back to a host `go`, `staticcheck` or `govulncheck`.
go_sdk := env_var_or_default("TENSORWIRE_GO_SDK", `./scripts/go_tools.sh sdk-path`)
export TENSORWIRE_GO_SDK := go_sdk
export PATH := go_sdk + "/bin:" + env_var("PATH")
export GOTOOLCHAIN := "local"

default: check

# the full local gate
check: lint typecheck test conformance

# staticcheck and govulncheck, built with the project's Go, into .tools/go/bin
go-tools:
    ./scripts/go_tools.sh build

# Each runs at most once per `just` invocation: go-sdk for recipes that only run `go`,
# go-ensure for those that also run staticcheck / govulncheck.
[private]
go-sdk:
    if [ -f go/go.mod ]; then ./scripts/go_tools.sh ensure-sdk; fi

[private]
go-ensure:
    if [ -f go/go.mod ]; then ./scripts/go_tools.sh ensure; fi

# install the Python dev environment (all extras: redis, ntp, migrate, dev)
setup:
    cd python && uv sync --all-extras

lint: setup go-ensure
    cd python && uv run ruff check . && uv run ruff format --check . && uv run lint-imports
    cd examples/text-ops-subnet && ../../python/.venv/bin/ruff check . && ../../python/.venv/bin/ruff format --check .
    if [ -f deploy/ruff.toml ]; then cd python && uv run ruff check --config ../deploy/ruff.toml ../deploy && uv run ruff format --check --config ../deploy/ruff.toml ../deploy; else echo "skip: deploy/ not present yet"; fi
    if [ -f typescript/package.json ]; then cd typescript && npm run lint; else echo "skip: typescript/ not present yet"; fi
    if [ -f go/go.mod ]; then cd go && go vet ./... && ../scripts/go_tools.sh run staticcheck ./...; else echo "skip: go/ not present yet"; fi
    if [ -f rust/Cargo.toml ]; then cd rust && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cd fuzz && cargo fmt --check; else echo "skip: rust/ not present yet"; fi

typecheck: setup
    cd python && uv run mypy --strict src
    cd examples/text-ops-subnet && ../../python/.venv/bin/mypy text_ops tests
    if [ -f deploy/docker/healthcheck.py ]; then cd python && uv run mypy --strict ../deploy/docker/healthcheck.py; else echo "skip: deploy/ not present yet"; fi
    if [ -f typescript/package.json ]; then cd typescript && npm run typecheck; else echo "skip: typescript/ not present yet"; fi

test: setup go-sdk
    cd python && uv run pytest tests/unit tests/property tests/integration
    if [ -f typescript/package.json ]; then cd typescript && npm test; else echo "skip: typescript/ not present yet"; fi
    if [ -f go/go.mod ]; then cd go && go test -race ./...; else echo "skip: go/ not present yet"; fi
    if [ -f rust/Cargo.toml ]; then cd rust && cargo test --all-features; else echo "skip: rust/ not present yet"; fi

# Python coverage (definition of done: >= 90% on auth/ policy/ limits/ ..., >= 80% elsewhere)
coverage: setup
    cd python && uv run coverage run -m pytest tests/unit tests/property tests/integration tests/migration && uv run coverage report

# Each language's conformance runner lands in Phase 5; until then the step is skipped.
conformance: setup go-sdk
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

# spec 8.10: one real seal + open through the public drand API (not part of `just test`)
drand-test: setup
    cd python && uv run pytest -m drand tests/drand

migration-test:
    cd python && uv run pytest tests/migration

mixed-fleet:
    ./scripts/legacy_venv.sh && cd python && uv run pytest -m "localnet and mixed_fleet" tests/localnet

# spec 13.6 abuse tests against a real 2-worker miner on Redis (TENSORWIRE_TEST_REDIS_URL, default local DB 15)
test_redis := env_var_or_default("TENSORWIRE_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")

abuse: setup
    cd python && TENSORWIRE_TEST_REDIS_URL={{test_redis}} uv run pytest -m abuse tests/abuse

# spec 13.7 targets; 4 workers need Redis. Found automatically and reached directly
# (container IP / host network, not docker-proxy; D17); TENSORWIRE_BENCH_REDIS_URL overrides
bench:
    cd python && uv run tensorwire bench --duration 60

audit: setup go-ensure
    cd python && uv run pip-audit
    if [ -f typescript/package.json ]; then cd typescript && npm audit --audit-level=high; else echo "skip: typescript/ not present yet"; fi
    if [ -f go/go.mod ]; then cd go && ../scripts/go_tools.sh run govulncheck ./...; else echo "skip: go/ not present yet"; fi
    if [ -f rust/Cargo.toml ]; then cd rust && cargo audit; else echo "skip: rust/ not present yet"; fi
