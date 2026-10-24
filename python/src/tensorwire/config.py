"""Settings for every TensorWire process (spec Section 12).

All settings are ``TW_*`` environment variables (a ``.env`` file is also
supported). Each process type has one model:

- :class:`MinerSettings` (12.1 + 12.2)
- :class:`ValidatorSettings` (12.1 + 12.3)
- :class:`SidecarSettings` (12.1 + 12.4)

Rules enforced here, at startup, before anything touches the network:

- Every value is range-checked.
- An unknown ``TW_*`` variable is an error (typo protection). "Known" means
  known to *any* of the three models, so one ``.env`` file can be shared by a
  miner and a validator on the same host.
- Unsafe combinations are refused (for example several workers with a
  per-process nonce store, spec 8.4.3).

Invalid settings raise :class:`tensorwire.errors.ConfigError` naming the
variable. Input values are never echoed, because some of them (the Redis URL)
can contain credentials.
"""

from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import ipaddress
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, NamedTuple, TypeVar
from urllib.parse import urlsplit

from dotenv import dotenv_values
from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from tensorwire.errors import ConfigError

__all__ = [
    "DEFAULT_PROTOCOL_TAG",
    "LEGACY_MAX_HORIZON_DAYS",
    "STREAM_IDLE_S_RANGE",
    "STREAM_MAX_BYTES_RANGE",
    "STREAM_MAX_PER_CALLER_RANGE",
    "STREAM_MAX_S_RANGE",
    "CallerPolicySettings",
    "CommonSettings",
    "HostPort",
    "MinerSettings",
    "SidecarSettings",
    "ValidatorSettings",
    "check_environment",
    "known_variables",
]

ENV_PREFIX = "TW_"

#: Default ``ServeAxon.protocol`` tag (PM decision D1). The chain stores this
#: field as a u8, so the range is 0-255; 0x57 is "W".
DEFAULT_PROTOCOL_TAG = 0x57

#: Allowed stream limits (spec 9.2, 12.1): ``TW_STREAM_MAX_S`` (whole
#: stream), ``TW_STREAM_MAX_BYTES``, ``TW_STREAM_IDLE_S`` (gap between events).
#: Per-route and per-call overrides use the same ranges.
STREAM_MAX_S_RANGE = (1.0, 600.0)
STREAM_MAX_BYTES_RANGE = (1024, 64 * 1024 * 1024)
STREAM_IDLE_S_RANGE = (1.0, 120.0)
#: Open streams per caller hotkey per process (D36).
STREAM_MAX_PER_CALLER_RANGE = (1, 256)

#: Latest allowed legacy-bridge end date, in days after the process starts
#: (PM decision D4): the v10 bridge is time-boxed, never "forever".
LEGACY_MAX_HORIZON_DAYS = 180

#: ``TW_EXTERNAL_IP`` values the chain rejects (``127.0.0.1``) or reads back as
#: "not served" (``0.0.0.0``, ``::``); refused even on localnet (D4).
_NEVER_EXTERNAL_IPS = frozenset(
    ipaddress.ip_address(a)
    for a in ("0.0.0.0", "::", "127.0.0.1")  # noqa: S104
)

_NETWORK_NAMES = frozenset({"finney", "test", "local"})
_SS58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_SS58_PREFIX = 42

#: Settings that weaken a secure default when set to the given value (spec 16.2).
_WEAKENING: Mapping[str, object] = {
    "refuse_if_coldkey_present": False,
    "allow_private_axons": True,
    "require_permit": False,
    "sign_responses": False,
    "unsafe_allow_memory_nonce_multiworker": True,
    "verify_responses": False,
    "sidecar_unsafe_bind": True,
}

_S = TypeVar("_S", bound="CommonSettings")

CommaList = Annotated[tuple[str, ...], NoDecode]
HotkeySet = Annotated[frozenset[str], NoDecode]
CidrList = Annotated[
    tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...], NoDecode
]


class HostPort(NamedTuple):
    """A parsed ``host:port`` (IPv6 hosts are written ``[addr]:port``)."""

    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> HostPort:
        """Parse ``"127.0.0.1:9100"`` or ``"[::1]:9100"``."""
        host, sep, port_s = value.rpartition(":")
        if not sep or not host or not port_s.isdigit():
            raise ValueError("expected host:port")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
            if not isinstance(_ip(host), ipaddress.IPv6Address):
                raise ValueError("bracketed host must be an IPv6 address")
        elif ":" in host:
            raise ValueError("IPv6 hosts must be written as [addr]:port")
        else:
            _ip(host)
        port = int(port_s)
        if not 1 <= port <= 65535:
            raise ValueError("port must be 1-65535")
        return cls(host, port)


def _ip(
    value: str, what: str = "value"
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"{what} is not an IP address") from None


def _split_csv(value: Any) -> Any:
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    return value


def _base58_decode(value: str) -> bytes:
    num = 0
    for char in value:
        digit = _SS58_ALPHABET.find(char)
        if digit < 0:
            raise ValueError("not base58")
        num = num * 58 + digit
    body = num.to_bytes((num.bit_length() + 7) // 8, "big")
    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + body


def _is_ss58(address: str) -> bool:
    """Bittensor SS58 check (Appendix D): prefix 42, 32-byte key, valid checksum."""
    try:
        raw = _base58_decode(address)
    except ValueError:
        return False
    if len(raw) != 35 or raw[0] != _SS58_PREFIX:
        return False
    checksum = hashlib.blake2b(b"SS58PRE" + raw[:33], digest_size=64).digest()[:2]
    return checksum == raw[33:]


def _check_endpoint_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("ws", "wss") or not parts.hostname:
        raise ValueError("expected a ws:// or wss:// URL")
    return value


def _check_simple_name(value: str) -> str:
    if (
        not value
        or value in (".", "..")
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError("must be a plain name, not a path")
    return value


def _check_end_date(value: dt.date | None) -> dt.date | None:
    # Spec 8.11.2 / 8.11.3: an end date in the past means the process must not
    # start; D4: and one more than LEGACY_MAX_HORIZON_DAYS ahead is refused.
    if value is None:
        return None
    today = dt.datetime.now(dt.timezone.utc).date()
    if value <= today:
        raise ValueError("end date must be in the future (UTC)")
    if value > today + dt.timedelta(days=LEGACY_MAX_HORIZON_DAYS):
        raise ValueError(
            f"end date must be at most {LEGACY_MAX_HORIZON_DAYS} days from today (UTC)"
        )
    return value


class CommonSettings(BaseSettings):
    """Settings shared by every process type (spec 12.1)."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        case_sensitive=False,
        # Other models' variables are ignored here; check_environment rejects
        # names no model knows.
        extra="ignore",
        frozen=True,
        validate_default=True,
        hide_input_in_errors=True,
    )

    network: str = "test"
    chain_fallbacks: CommaList = ()
    netuid: int = Field(ge=0, le=65535)
    wallet_name: str
    wallet_hotkey: str = "default"
    wallet_path: Path = Path("~/.bittensor/wallets")
    refuse_if_coldkey_present: bool = True
    state_dir: Path = Path("~/.tensorwire")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    metrics_bind: Annotated[HostPort, NoDecode] = HostPort("127.0.0.1", 9100)
    chain_timeout_s: float = Field(default=30.0, gt=0, le=600)
    metagraph_refresh_s: float = Field(default=120.0, ge=10, le=3600)
    #: ``None`` = not set: ``StalenessThresholds.for_tempo`` applies the 900 s
    #: default, capped at half the max age on short tempos.
    metagraph_soft_age_s: float | None = Field(default=None, gt=0, le=86_400)
    #: ``None`` = 2 x the subnet's tempo in seconds, resolved by
    #: ``chain.metagraph_cache.StalenessThresholds.for_tempo``.
    metagraph_max_age_s: float | None = Field(default=None, gt=0, le=7 * 86_400)
    metagraph_strict: bool = False
    startup_timeout_s: float = Field(default=120.0, gt=0, le=3600)
    ntp_servers: CommaList = ("pool.ntp.org", "time.cloudflare.com")
    redis_url: SecretStr | None = None
    protocol_tag: int = Field(default=DEFAULT_PROTOCOL_TAG, ge=0, le=255)
    scheme_policy: Literal["http", "https", "https-if-tls-published"] = "http"
    allow_private_axons: bool = False
    #: Streaming limits (spec 9.2, 12.1); routes and calls may override them.
    stream_max_s: float = Field(
        default=60.0, ge=STREAM_MAX_S_RANGE[0], le=STREAM_MAX_S_RANGE[1]
    )
    stream_max_bytes: int = Field(
        default=4_194_304, ge=STREAM_MAX_BYTES_RANGE[0], le=STREAM_MAX_BYTES_RANGE[1]
    )
    stream_idle_s: float = Field(
        default=10.0, ge=STREAM_IDLE_S_RANGE[0], le=STREAM_IDLE_S_RANGE[1]
    )
    #: Open streams one caller hotkey may hold per miner process (9.2, D36).
    stream_max_per_caller: int = Field(
        default=16,
        ge=STREAM_MAX_PER_CALLER_RANGE[0],
        le=STREAM_MAX_PER_CALLER_RANGE[1],
    )

    def __init__(self, **values: Any) -> None:
        fields = type(self).model_fields
        unknown = sorted(k for k in values if not k.startswith("_") and k not in fields)
        if unknown:
            raise ConfigError(f"unknown setting(s): {', '.join(unknown)}")
        env_file = values.get("_env_file")
        check_environment(
            os.environ, env_file if isinstance(env_file, (str, Path)) else None
        )
        try:
            super().__init__(**values)
        except ValidationError as exc:
            raise ConfigError(_describe(exc)) from None

    @classmethod
    def from_env(cls: type[_S], env_file: str | Path | None = None) -> _S:
        """Load from the environment (and ``env_file`` if given) and validate."""
        return cls(_env_file=env_file)

    # ------------------------------------------------------------ validators

    @field_validator("chain_fallbacks", "ntp_servers", mode="before")
    @classmethod
    def _csv(cls, value: Any) -> Any:
        return _split_csv(value)

    @field_validator("network")
    @classmethod
    def _network(cls, value: str) -> str:
        return value if value in _NETWORK_NAMES else _check_endpoint_url(value)

    @field_validator("chain_fallbacks")
    @classmethod
    def _fallbacks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_check_endpoint_url(v) for v in value)

    @field_validator("wallet_name", "wallet_hotkey")
    @classmethod
    def _names(cls, value: str) -> str:
        return _check_simple_name(value)

    @field_validator("wallet_path", "state_dir", mode="after")
    @classmethod
    def _expand(cls, value: Path) -> Path:
        return value.expanduser()

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @field_validator("metrics_bind", mode="before")
    @classmethod
    def _host_port(cls, value: Any) -> Any:
        return HostPort.parse(value) if isinstance(value, str) else value

    @field_validator("ntp_servers")
    @classmethod
    def _hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for host in value:
            if any(c.isspace() for c in host) or "/" in host:
                raise ValueError("expected comma-separated host names")
        return value

    @field_validator("redis_url")
    @classmethod
    def _redis(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None or not value.get_secret_value():
            return None
        if urlsplit(value.get_secret_value()).scheme not in ("redis", "rediss", "unix"):
            raise ValueError("expected a redis://, rediss:// or unix:// URL")
        return value

    @model_validator(mode="after")
    def _ages(self) -> CommonSettings:
        if (
            self.metagraph_max_age_s is not None
            and self.metagraph_soft_age_s is not None
            and self.metagraph_max_age_s <= self.metagraph_soft_age_s
        ):
            raise ValueError(
                "TW_METAGRAPH_MAX_AGE_S must be greater than TW_METAGRAPH_SOFT_AGE_S"
            )
        return self

    # ------------------------------------------------------------ helpers

    def weakened_settings(self) -> tuple[str, ...]:
        """``TW_*`` names of active settings that weaken a secure default (spec 16.2).

        The process logs each at WARNING on startup and exports
        ``tw_unsafe_settings_active``.
        """
        return tuple(
            f"{ENV_PREFIX}{name.upper()}"
            for name in type(self).model_fields
            if name in _WEAKENING and getattr(self, name) == _WEAKENING[name]
        )


class CallerPolicySettings(CommonSettings):
    """Caller-policy settings (spec 8.5, 12.2), shared by the miner and the sidecar."""

    require_permit: bool = True
    min_caller_stake_tao: float = Field(default=0.0, ge=0, allow_inf_nan=False)
    allow_hotkeys: HotkeySet = frozenset()
    deny_hotkeys: HotkeySet = frozenset()

    @field_validator("allow_hotkeys", "deny_hotkeys", mode="before")
    @classmethod
    def _csv_policy(cls, value: Any) -> Any:
        return _split_csv(value)

    @field_validator("allow_hotkeys", "deny_hotkeys")
    @classmethod
    def _ss58(cls, value: frozenset[str]) -> frozenset[str]:
        bad = [v for v in value if not _is_ss58(v)]
        if bad:
            raise ValueError(
                f"{len(bad)} entr{'y is' if len(bad) == 1 else 'ies are'} "
                "not a valid SS58 hotkey (prefix 42)"
            )
        return value

    @model_validator(mode="after")
    def _policy_lists(self) -> CallerPolicySettings:
        overlap = self.allow_hotkeys & self.deny_hotkeys
        if overlap:
            raise ValueError(
                f"{len(overlap)} hotkey(s) are in both TW_ALLOW_HOTKEYS "
                "and TW_DENY_HOTKEYS"
            )
        return self


class MinerSettings(CallerPolicySettings):
    """Miner settings (spec 12.1 + 12.2)."""

    bind_host: str = "0.0.0.0"  # noqa: S104 - a miner must listen publicly; validators find it on chain
    bind_port: int = Field(default=8091, ge=1, le=65535)
    external_ip: str
    #: ``None`` = same as ``bind_port``.
    external_port: int | None = Field(default=None, ge=1, le=65535)
    auto_serve_axon: bool = True
    axon_publisher: bool = True
    instance_count: int = Field(default=1, ge=1, le=1024)
    workers: int = Field(default=1, ge=1, le=256)
    auth_max_age_s: float = Field(default=10.0, ge=2, le=60)
    auth_allowed_skew_s: float = Field(default=2.0, ge=0.5, le=10)
    nonce_retention_s: float = Field(default=60.0, gt=0, le=3600)
    max_body_bytes: int = Field(default=1_048_576, ge=1, le=256 * 1024 * 1024)
    rate_ip_per_s: float = Field(default=50.0, gt=0, le=1_000_000)
    rate_ip_burst: int = Field(default=100, ge=1, le=1_000_000)
    rate_hotkey_per_s: float = Field(default=20.0, gt=0, le=1_000_000)
    rate_hotkey_burst: int = Field(default=40, ge=1, le=1_000_000)
    trusted_proxies: CidrList = ()
    handler_timeout_s: float = Field(default=10.0, gt=0, le=600)
    sign_responses: bool = True
    drain_s: float = Field(default=10.0, ge=0, le=600)
    legacy_v10_until: dt.date | None = None
    compat_max_queue: int = Field(default=256, ge=1, le=65_536)
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    tls_published_cert_file: Path | None = None
    unsafe_allow_memory_nonce_multiworker: bool = False

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _cidrs(cls, value: Any) -> Any:
        value = _split_csv(value)
        if not isinstance(value, Iterable):
            return value
        networks = []
        for item in value:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except (TypeError, ValueError):
                raise ValueError("expected comma-separated CIDRs") from None
        return tuple(networks)

    @field_validator("bind_host")
    @classmethod
    def _bind(cls, value: str) -> str:
        _ip(value)
        return value

    @field_validator("legacy_v10_until")
    @classmethod
    def _legacy_until(cls, value: dt.date | None) -> dt.date | None:
        return _check_end_date(value)

    @field_validator(
        "tls_cert_file", "tls_key_file", "tls_published_cert_file", mode="after"
    )
    @classmethod
    def _file(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        value = value.expanduser()
        if not value.is_file():
            raise ValueError("file does not exist")
        return value

    @model_validator(mode="after")
    def _miner_rules(self) -> MinerSettings:
        ip = _ip(self.external_ip, "TW_EXTERNAL_IP")
        if ip.is_unspecified or ip.is_multicast or ip in _NEVER_EXTERNAL_IPS:
            raise ValueError(
                "TW_EXTERNAL_IP must be a routable address "
                "(the chain rejects 127.0.0.1 and un-serves 0.0.0.0 and ::)"
            )
        if not ip.is_global and not self.allow_private_axons:
            raise ValueError(
                "TW_EXTERNAL_IP is a private/loopback address; validators reject it "
                "(set TW_ALLOW_PRIVATE_AXONS=1 on localnet only)"
            )
        window = self.auth_max_age_s + self.auth_allowed_skew_s
        if self.nonce_retention_s < 2 * window:  # spec 8.4.3, D21
            raise ValueError(
                "TW_NONCE_RETENTION_S must be >= "
                "2 x (TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S)"
            )
        if (self.tls_cert_file is None) != (self.tls_key_file is None):
            raise ValueError(
                "set both TW_TLS_CERT_FILE and TW_TLS_KEY_FILE, or neither"
            )
        if self.tls_published_cert_file is not None:
            if self.tls_cert_file is not None:
                raise ValueError(
                    "TW_TLS_PUBLISHED_CERT_FILE (TLS at a reverse proxy) and "
                    "TW_TLS_CERT_FILE (TLS in uvicorn) are mutually exclusive"
                )
            if not self.trusted_proxies:
                raise ValueError(
                    "TW_TLS_PUBLISHED_CERT_FILE means a reverse proxy terminates "
                    "TLS: set TW_TRUSTED_PROXIES to its address (spec 16.3)"
                )
        multi = self.workers > 1 or self.instance_count > 1
        if (
            multi
            and self.redis_url is None
            and not self.unsafe_allow_memory_nonce_multiworker
        ):
            raise ValueError(
                "TW_REDIS_URL is required when TW_WORKERS > 1 or "
                "TW_INSTANCE_COUNT > 1: a per-process nonce store lets replays "
                "through (spec 8.4.3)"
            )
        return self

    @property
    def effective_external_port(self) -> int:
        """The port published on chain."""
        return self.bind_port if self.external_port is None else self.external_port


class ValidatorSettings(CommonSettings):
    """Validator settings (spec 12.1 + 12.3)."""

    round_interval_s: float = Field(default=60.0, ge=1, le=86_400)
    sample_size: int = Field(default=64, ge=1, le=65_536)
    query_timeout_s: float = Field(default=12.0, gt=0, le=600)
    max_concurrency: int = Field(default=64, ge=1, le=4096)
    max_attempts: int = Field(default=2, ge=1, le=5)
    verify_responses: bool = True
    max_response_bytes: int = Field(default=4_194_304, ge=1, le=1024 * 1024 * 1024)
    score_alpha: float = Field(default=0.1, gt=0, le=1)
    min_weight_interval_blocks: int = Field(default=100, ge=0, le=1_000_000)
    weights_version_key: int = Field(default=0, ge=0, le=2**64 - 1)
    mechid: int = Field(default=0, ge=0, le=255)
    #: Timelock (spec 8.10, 12.3): concurrent drand fetches, retries, deadline.
    timelock_concurrency: int = Field(default=8, ge=1, le=64)
    timelock_retries: int = Field(default=3, ge=0, le=10)
    timelock_timeout_s: float = Field(default=30.0, ge=1, le=300)
    query_validators: bool = False
    legacy_v10_client: Literal["auto", "off"] = "off"
    legacy_v10_client_until: dt.date | None = None

    @field_validator("legacy_v10_client_until")
    @classmethod
    def _legacy_until(cls, value: dt.date | None) -> dt.date | None:
        return _check_end_date(value)

    @model_validator(mode="after")
    def _legacy(self) -> ValidatorSettings:
        if self.legacy_v10_client == "auto" and self.legacy_v10_client_until is None:
            raise ValueError(
                "TW_LEGACY_V10_CLIENT=auto requires TW_LEGACY_V10_CLIENT_UNTIL"
            )
        return self


class SidecarSettings(CallerPolicySettings):
    """Sidecar settings (spec 12.1, 12.4; the 12.2 caller policy for ``/v1/caller``)."""

    sidecar_port: int = Field(default=9910, ge=1, le=65535)
    #: ``None`` = ``$TW_STATE_DIR/sidecar.token``.
    sidecar_token_file: Path | None = None
    sidecar_unsafe_bind: bool = False

    @field_validator("sidecar_token_file", mode="after")
    @classmethod
    def _expand_token(cls, value: Path | None) -> Path | None:
        return None if value is None else value.expanduser()

    @property
    def effective_token_file(self) -> Path:
        """Where the sidecar bearer token lives."""
        if self.sidecar_token_file is not None:
            return self.sidecar_token_file
        return self.state_dir / "sidecar.token"


_ALL_MODELS: tuple[type[CommonSettings], ...] = (
    MinerSettings,
    ValidatorSettings,
    SidecarSettings,
)


def known_variables() -> frozenset[str]:
    """Every ``TW_*`` variable name any TensorWire process understands."""
    return frozenset(
        f"{ENV_PREFIX}{name.upper()}"
        for model in _ALL_MODELS
        for name in model.model_fields
    )


def check_environment(
    environ: Mapping[str, str], env_file: str | Path | None = None
) -> None:
    """Raise :class:`ConfigError` for an unknown ``TW_*`` name.

    Both ``environ`` and, if given, ``env_file`` are checked.
    """
    names = {k for k in environ if k.upper().startswith(ENV_PREFIX)}
    if env_file is not None:
        path = Path(env_file)
        if not path.is_file():
            raise ConfigError(f"env file not found: {path}")
        names |= {k for k in dotenv_values(path) if k.upper().startswith(ENV_PREFIX)}
    known = known_variables()
    unknown = sorted(n for n in names if n.upper() not in known)
    if not unknown:
        return
    hints = []
    for name in unknown:
        close = difflib.get_close_matches(name.upper(), known, n=1)
        hints.append(f"{name} (did you mean {close[0]}?)" if close else name)
    raise ConfigError(f"unknown TW_* variable(s): {', '.join(hints)}")


def _describe(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = err["loc"]
        msg = err["msg"].removeprefix("Value error, ")
        lines.append(f"{ENV_PREFIX}{str(loc[0]).upper()}: {msg}" if loc else msg)
    return "invalid settings: " + "; ".join(lines)
