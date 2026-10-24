# syntax=docker/dockerfile:1.7
# TaoWire validator image (spec 5.5, 16.4).
#
# Same build as miner.Dockerfile; runs the subnet's validator module as a
# non-root user. State (SQLite scores, hotkey lock) lives in the volume at
# /var/lib/taowire. The image holds no wallet: mount the hotkey file
# read-only at runtime (see deploy/README.md), never the coldkey.
#
#   docker build -f deploy/docker/validator.Dockerfile -t taowire-validator .
#
# /healthz, /readyz and /metrics are on TW_METRICS_BIND (kit default
# 127.0.0.1:9100, which is unreachable from outside a bridge-network
# container): set TW_METRICS_BIND=0.0.0.0:9100 and publish it on the host's
# loopback only (-p 127.0.0.1:9100:9100), or use host networking.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424

FROM ${UV_IMAGE} AS uv

# The subnet project to install. Default: the text-ops example. Your own:
#   --build-context subnet=path/to/your-subnet
FROM scratch AS subnet
COPY examples/text-ops-subnet/ /

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src/python
# Dependencies first (cached layer), exactly as locked; then the kit itself.
COPY python/pyproject.toml python/uv.lock python/README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --extra redis --extra ntp
COPY python/src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --extra redis --extra ntp
# The subnet project (stage "subnet" above); its dependencies must already be
# in the lock (--no-deps).
COPY --from=subnet / /src/subnet
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --python /opt/venv/bin/python --no-deps /src/subnet

FROM ${PYTHON_IMAGE} AS runtime
ARG APP_UID=10001
RUN groupadd --system --gid "${APP_UID}" taowire \
 && useradd --system --uid "${APP_UID}" --gid "${APP_UID}" --no-create-home \
      --home-dir /var/lib/taowire --shell /usr/sbin/nologin taowire \
 && install -d -o taowire -g taowire -m 0700 /var/lib/taowire \
 && install -d -m 0755 /run/taowire/wallets
COPY --from=build /opt/venv /opt/venv
COPY deploy/docker/healthcheck.py /usr/local/lib/taowire/healthcheck.py
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TW_WALLET_PATH=/run/taowire/wallets \
    TW_STATE_DIR=/var/lib/taowire
USER ${APP_UID}:${APP_UID}
WORKDIR /var/lib/taowire
VOLUME ["/var/lib/taowire"]
EXPOSE 9100
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-I", "/usr/local/lib/taowire/healthcheck.py", "validator"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m"]
CMD ["text_ops.validator"]
