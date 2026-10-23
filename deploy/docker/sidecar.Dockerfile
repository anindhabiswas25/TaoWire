# syntax=docker/dockerfile:1.7
# tensorwire-sidecar image (spec 11.6, ADR-0003): chain access for non-Python
# miners. Runs `tensorwire sidecar` as a non-root user with the miner's hotkey
# (mounted read-only at runtime, never the coldkey).
#
#   docker build -f deploy/docker/sidecar.Dockerfile -t tensorwire-sidecar .
#
# The sidecar binds 127.0.0.1 only (spec 11.6), so it must share the miner's
# network namespace: `network_mode: "service:<miner>"` in compose, or
# `--network container:<miner>` / host networking with docker run.
# The `sidecar` command itself ships in Phase 5; until then this image builds
# but its entrypoint exits with "No such command".

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src/python
COPY python/pyproject.toml python/uv.lock python/README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY python/src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

FROM ${PYTHON_IMAGE} AS runtime
ARG APP_UID=10001
RUN groupadd --system --gid "${APP_UID}" tensorwire \
 && useradd --system --uid "${APP_UID}" --gid "${APP_UID}" --no-create-home \
      --home-dir /var/lib/tensorwire --shell /usr/sbin/nologin tensorwire \
 && install -d -o tensorwire -g tensorwire -m 0700 /var/lib/tensorwire \
 && install -d -m 0755 /run/tensorwire/wallets
COPY --from=build /opt/venv /opt/venv
COPY deploy/docker/healthcheck.py /usr/local/lib/tensorwire/healthcheck.py
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TW_WALLET_PATH=/run/tensorwire/wallets \
    TW_STATE_DIR=/var/lib/tensorwire
USER ${APP_UID}:${APP_UID}
WORKDIR /var/lib/tensorwire
EXPOSE 9910
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-I", "/usr/local/lib/tensorwire/healthcheck.py", "sidecar"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["tensorwire"]
CMD ["sidecar"]
