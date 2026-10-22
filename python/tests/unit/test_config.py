"""config.py: every Section 12 variable, defaults, ranges, unknown-variable check."""

from __future__ import annotations

import contextlib
import datetime as dt
import re
from pathlib import Path
from typing import Any

import pytest

from tensorwire import config as c
from tensorwire.errors import ConfigError
from tensorwire.testing.pytest_plugin import TWEnv

ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
BOB = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
TOMORROW = (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=2)).isoformat()
TODAY = dt.datetime.now(dt.timezone.utc).date().isoformat()


@pytest.fixture
def env(tw_env: TWEnv) -> TWEnv:
    """The minimum valid miner environment."""
    tw_env.set(netuid=7, wallet_name="miner", external_ip="44.1.2.3")
    return tw_env


def miner() -> c.MinerSettings:
    return c.MinerSettings.from_env()


def fails(match: str) -> Any:
    return pytest.raises(ConfigError, match=match)


# --------------------------------------------------------------- coverage of Section 12


def test_known_variables_are_exactly_section_12(spec_text: str) -> None:
    section = spec_text[spec_text.index("## 12. Configuration") : spec_text.index("## 13. Testing")]
    documented = set(re.findall(r"\bTW_[A-Z0-9_]*[A-Z0-9]", section))
    assert documented == c.known_variables()


def test_defaults_match_section_12(env: TWEnv) -> None:
    s = miner()
    assert s.network == "test"
    assert s.chain_fallbacks == ()
    assert s.wallet_hotkey == "default"
    assert s.wallet_path == Path("~/.bittensor/wallets").expanduser()
    assert s.refuse_if_coldkey_present is True
    assert s.state_dir == Path("~/.tensorwire").expanduser()
    assert s.log_level == "INFO"
    assert s.metrics_bind == c.HostPort("127.0.0.1", 9100)
    assert s.chain_timeout_s == 30
    assert s.metagraph_refresh_s == 120
    assert s.metagraph_soft_age_s == 900
    assert s.metagraph_max_age_s is None
    assert s.metagraph_max_age_for(360) == 8640
    assert s.metagraph_strict is False
    assert s.startup_timeout_s == 120
    assert s.ntp_servers == ("pool.ntp.org", "time.cloudflare.com")
    assert s.redis_url is None
    assert s.protocol_tag == c.DEFAULT_PROTOCOL_TAG
    assert s.scheme_policy == "http"
    assert s.allow_private_axons is False
    assert s.bind_host == "0.0.0.0"
    assert s.bind_port == 8091
    assert s.effective_external_port == 8091
    assert (s.auto_serve_axon, s.axon_publisher) == (True, True)
    assert (s.instance_count, s.workers) == (1, 1)
    assert (s.auth_max_age_s, s.auth_allowed_skew_s, s.nonce_retention_s) == (10, 2, 60)
    assert s.max_body_bytes == 1_048_576
    assert (s.rate_ip_per_s, s.rate_ip_burst) == (50, 100)
    assert (s.rate_hotkey_per_s, s.rate_hotkey_burst) == (20, 40)
    assert s.trusted_proxies == ()
    assert s.require_permit is True
    assert s.min_caller_stake_tao == 0
    assert s.allow_hotkeys == s.deny_hotkeys == frozenset()
    assert s.handler_timeout_s == 10
    assert s.sign_responses is True
    assert s.drain_s == 10
    assert s.legacy_v10_until is None
    assert s.compat_max_queue == 256
    assert s.tls_cert_file is s.tls_key_file is None
    assert s.unsafe_allow_memory_nonce_multiworker is False
    assert s.weakened_settings() == ()


def test_validator_defaults(tw_env: TWEnv) -> None:
    tw_env.set(netuid=1, wallet_name="v")
    s = c.ValidatorSettings.from_env()
    assert (s.round_interval_s, s.sample_size, s.query_timeout_s) == (60, 64, 12)
    assert (s.max_concurrency, s.max_attempts) == (64, 2)
    assert s.verify_responses is True
    assert s.max_response_bytes == 4_194_304
    assert s.score_alpha == 0.1
    assert s.min_weight_interval_blocks == 100
    assert (s.weights_version_key, s.mechid) == (0, 0)
    assert s.query_validators is False
    assert s.legacy_v10_client == "off"
    assert s.legacy_v10_client_until is None


def test_sidecar_defaults(tw_env: TWEnv, tmp_path: Path) -> None:
    tw_env.set(netuid=1, wallet_name="m", state_dir=tmp_path)
    s = c.SidecarSettings.from_env()
    assert s.sidecar_port == 9910
    assert s.sidecar_unsafe_bind is False
    assert s.effective_token_file == tmp_path / "sidecar.token"
    tw_env.set(sidecar_token_file="~/tok")
    assert c.SidecarSettings.from_env().effective_token_file == Path("~/tok").expanduser()


# --------------------------------------------------------------- required values


@pytest.mark.parametrize("missing", ["netuid", "wallet_name", "external_ip"])
def test_required(env: TWEnv, missing: str) -> None:
    env.unset(missing)
    with fails(f"TW_{missing.upper()}: Field required"):
        miner()


def test_validator_does_not_need_miner_fields(tw_env: TWEnv) -> None:
    tw_env.set(netuid=0, wallet_name="v")
    assert c.ValidatorSettings.from_env().netuid == 0


# --------------------------------------------------------------- ranges

RANGES = [
    # (name, too low / bad, lowest ok, highest ok, too high)
    ("netuid", -1, 0, 65535, 65536),
    ("chain_timeout_s", 0, 0.1, 600, 601),
    ("metagraph_refresh_s", 9, 10, 3600, 3601),
    ("startup_timeout_s", 0, 1, 3600, 3601),
    ("protocol_tag", -1, 0, 255, 256),
    ("bind_port", 0, 1, 65535, 65536),
    ("external_port", 0, 1, 65535, 65536),
    ("instance_count", 0, 1, 1024, 1025),
    ("workers", 0, 1, 256, 257),
    ("auth_max_age_s", 1.9, 2, 58, 61),
    ("auth_allowed_skew_s", 0.4, 0.5, 10, 10.1),
    ("max_body_bytes", 0, 1, 256 * 1024 * 1024, 256 * 1024 * 1024 + 1),
    ("rate_ip_per_s", 0, 0.001, 1_000_000, 1_000_001),
    ("rate_ip_burst", 0, 1, 1_000_000, 1_000_001),
    ("rate_hotkey_per_s", 0, 0.001, 1_000_000, 1_000_001),
    ("rate_hotkey_burst", 0, 1, 1_000_000, 1_000_001),
    ("min_caller_stake_tao", -1, 0, 1e9, "inf"),
    ("handler_timeout_s", 0, 0.01, 600, 601),
    ("drain_s", -1, 0, 600, 601),
    ("compat_max_queue", 0, 1, 65536, 65537),
]


@pytest.mark.parametrize(("name", "low", "ok_low", "ok_high", "high"), RANGES)
def test_miner_ranges(
    env: TWEnv, name: str, low: object, ok_low: object, ok_high: object, high: object
) -> None:
    if name in {"workers", "instance_count"}:
        env.set(redis_url="redis://localhost:6379/0")
    for ok in (ok_low, ok_high):
        env.set(**{name: ok})
        miner()
    for bad in (low, high):
        env.set(**{name: bad})
        with fails(f"TW_{name.upper()}"):
            miner()


VALIDATOR_RANGES = [
    ("round_interval_s", 0.5, 1, 86_400, 86_401),
    ("sample_size", 0, 1, 65_536, 65_537),
    ("query_timeout_s", 0, 0.1, 600, 601),
    ("max_concurrency", 0, 1, 4096, 4097),
    ("max_attempts", 0, 1, 5, 6),
    ("max_response_bytes", 0, 1, 1024**3, 1024**3 + 1),
    ("score_alpha", 0, 0.0001, 1, 1.01),
    ("min_weight_interval_blocks", -1, 0, 1_000_000, 1_000_001),
    ("weights_version_key", -1, 0, 2**64 - 1, 2**64),
    ("mechid", -1, 0, 255, 256),
]


@pytest.mark.parametrize(("name", "low", "ok_low", "ok_high", "high"), VALIDATOR_RANGES)
def test_validator_ranges(
    tw_env: TWEnv, name: str, low: object, ok_low: object, ok_high: object, high: object
) -> None:
    tw_env.set(netuid=1, wallet_name="v")
    for ok in (ok_low, ok_high):
        tw_env.set(**{name: ok})
        c.ValidatorSettings.from_env()
    for bad in (low, high):
        tw_env.set(**{name: bad})
        with fails(f"TW_{name.upper()}"):
            c.ValidatorSettings.from_env()


def test_sidecar_port_range(tw_env: TWEnv) -> None:
    tw_env.set(netuid=1, wallet_name="m", sidecar_port=0)
    with fails("TW_SIDECAR_PORT"):
        c.SidecarSettings.from_env()


@pytest.mark.parametrize(
    ("soft", "max_age", "ok"), [(900, 901, True), (900, 900, False), (900, 10, False)]
)
def test_max_age_must_exceed_soft_age(env: TWEnv, soft: int, max_age: int, ok: bool) -> None:
    env.set(metagraph_soft_age_s=soft, metagraph_max_age_s=max_age)
    if ok:
        assert miner().metagraph_max_age_for(360) == max_age
    else:
        with fails("TW_METAGRAPH_MAX_AGE_S must be greater"):
            miner()


def test_max_age_from_tempo(env: TWEnv) -> None:
    s = miner()
    assert s.metagraph_max_age_for(100) == 2400
    env.set(metagraph_soft_age_s=5000)
    assert miner().metagraph_max_age_for(100) == 5000  # never below the soft age
    with pytest.raises(ValueError, match="tempo"):
        s.metagraph_max_age_for(0)


def test_nonce_retention_covers_window(env: TWEnv) -> None:
    env.set(auth_max_age_s=50, auth_allowed_skew_s=10, nonce_retention_s=59)
    with fails("TW_NONCE_RETENTION_S must be >="):
        miner()
    env.set(nonce_retention_s=60)
    miner()


# --------------------------------------------------------------- formats


@pytest.mark.parametrize(
    "network", ["finney", "test", "local", "ws://127.0.0.1:9944", "wss://x.example:443"]
)
def test_network_ok(env: TWEnv, network: str) -> None:
    env.set(network=network)
    assert miner().network == network


@pytest.mark.parametrize("network", ["mainnet", "http://x", "ws://", "", "Test"])
def test_network_bad(env: TWEnv, network: str) -> None:
    env.set(network=network)
    with fails("TW_NETWORK"):
        miner()


def test_comma_lists(env: TWEnv) -> None:
    env.set(
        chain_fallbacks=" wss://a.example , ws://b.example:9944,",
        ntp_servers="",
        trusted_proxies="10.0.0.0/8, 2001:db8::/32,192.0.2.1",
        allow_hotkeys=f"{ALICE}",
        deny_hotkeys=f"{BOB} ,",
    )
    s = miner()
    assert s.chain_fallbacks == ("wss://a.example", "ws://b.example:9944")
    assert s.ntp_servers == ()
    assert [str(n) for n in s.trusted_proxies] == ["10.0.0.0/8", "2001:db8::/32", "192.0.2.1/32"]
    assert s.allow_hotkeys == {ALICE}
    assert s.deny_hotkeys == {BOB}


@pytest.mark.parametrize(
    ("name", "value", "match"),
    [
        ("chain_fallbacks", "https://a", "ws:// or wss://"),
        ("ntp_servers", "a b", "host names"),
        ("ntp_servers", "a/b", "host names"),
        ("trusted_proxies", "10.0.0.0/33", "CIDRs"),
        ("trusted_proxies", "proxy.local", "CIDRs"),
        ("allow_hotkeys", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ", "SS58"),
        ("deny_hotkeys", f"{ALICE},nope", "1 entry is not a valid SS58"),
        ("deny_hotkeys", "0OIl,abc", "2 entries are"),
        ("wallet_name", "../evil", "plain name"),
        ("wallet_hotkey", "a/b", "plain name"),
        ("wallet_hotkey", "..", "plain name"),
        ("log_level", "LOUD", "TW_LOG_LEVEL"),
        ("metrics_bind", "127.0.0.1", "host:port"),
        ("metrics_bind", "::1:9100", "IPv6 hosts"),
        ("metrics_bind", "[127.0.0.1]:9100", "bracketed host"),
        ("metrics_bind", "localhost:9100", "not an IP"),
        ("metrics_bind", "127.0.0.1:0", "1-65535"),
        ("metrics_bind", "127.0.0.1:x", "host:port"),
        ("bind_host", "my-host", "not an IP"),
        ("redis_url", "http://:secretpw@h", "redis://"),
        ("scheme_policy", "tls", "TW_SCHEME_POLICY"),
        ("external_ip", "not-an-ip", "TW_EXTERNAL_IP is not an IP"),
        ("external_ip", "0.0.0.0", "routable"),
        ("external_ip", "224.0.0.1", "routable"),
        ("external_ip", "10.0.0.5", "TW_ALLOW_PRIVATE_AXONS"),
        ("external_ip", "127.0.0.1", "TW_ALLOW_PRIVATE_AXONS"),
    ],
)
def test_bad_formats(env: TWEnv, name: str, value: str, match: str) -> None:
    env.set(**{name: value})
    with fails(match):
        miner()


def test_errors_never_echo_input(env: TWEnv) -> None:
    env.set(redis_url="http://:hunter2@h")
    with pytest.raises(ConfigError) as info:
        miner()
    assert "hunter2" not in str(info.value)


def test_redis_url_is_secret(env: TWEnv) -> None:
    env.set(redis_url="redis://:hunter2@h:6379/0")
    s = miner()
    assert s.redis_url is not None
    assert "hunter2" not in repr(s)
    assert s.redis_url.get_secret_value() == "redis://:hunter2@h:6379/0"
    env.set(redis_url="")
    assert miner().redis_url is None


def test_metrics_bind_ipv6(env: TWEnv) -> None:
    env.set(metrics_bind="[::1]:9200")
    assert miner().metrics_bind == c.HostPort("::1", 9200)


def test_log_level_case_insensitive(env: TWEnv) -> None:
    env.set(log_level="debug")
    assert miner().log_level == "DEBUG"


def test_private_external_ip_allowed_on_localnet(env: TWEnv) -> None:
    env.set(external_ip="127.0.0.1", allow_private_axons=True)
    s = miner()
    assert s.external_ip == "127.0.0.1"
    assert s.weakened_settings() == ("TW_ALLOW_PRIVATE_AXONS",)


def test_external_port_defaults_to_bind_port(env: TWEnv) -> None:
    env.set(bind_port=9000)
    assert miner().effective_external_port == 9000
    env.set(external_port=443)
    assert miner().effective_external_port == 443


def test_paths_expand_user(env: TWEnv) -> None:
    env.set(wallet_path="~/w", state_dir="~/s")
    s = miner()
    assert s.wallet_path == Path("~/w").expanduser()
    assert s.state_dir == Path("~/s").expanduser()


@pytest.mark.parametrize(
    ("raw", "value"), [("1", True), ("0", False), ("true", True), ("false", False)]
)
def test_booleans(env: TWEnv, raw: str, value: bool) -> None:
    env.set(metagraph_strict=raw)
    assert miner().metagraph_strict is value


def test_bad_boolean(env: TWEnv) -> None:
    env.set(metagraph_strict="maybe")
    with fails("TW_METAGRAPH_STRICT"):
        miner()


# --------------------------------------------------------------- cross-field rules


def test_allow_and_deny_must_not_overlap(env: TWEnv) -> None:
    env.set(allow_hotkeys=f"{ALICE},{BOB}", deny_hotkeys=ALICE)
    with fails("1 hotkey"):
        miner()


@pytest.mark.parametrize("field", ["workers", "instance_count"])
def test_multi_worker_needs_redis(env: TWEnv, field: str) -> None:
    env.set(**{field: 2})
    with fails("TW_REDIS_URL is required"):
        miner()
    env.set(redis_url="redis://localhost:6379/0")
    miner()


def test_multi_worker_unsafe_override(env: TWEnv) -> None:
    env.set(workers=4, unsafe_allow_memory_nonce_multiworker=True)
    assert miner().weakened_settings() == ("TW_UNSAFE_ALLOW_MEMORY_NONCE_MULTIWORKER",)


def test_tls_needs_both_files(env: TWEnv, tmp_path: Path) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("c")
    key.write_text("k")
    env.set(tls_cert_file=cert)
    with fails("both TW_TLS_CERT_FILE and TW_TLS_KEY_FILE"):
        miner()
    env.set(tls_key_file=key)
    s = miner()
    assert (s.tls_cert_file, s.tls_key_file) == (cert, key)
    env.set(tls_key_file=tmp_path / "missing.pem")
    with fails("TW_TLS_KEY_FILE: file does not exist"):
        miner()


@pytest.mark.parametrize("day", ["2020-01-01", TODAY])
def test_legacy_until_must_be_future(env: TWEnv, day: str) -> None:
    env.set(legacy_v10_until=day)
    with fails("TW_LEGACY_V10_UNTIL: end date must be in the future"):
        miner()


def test_legacy_until_future_ok(env: TWEnv) -> None:
    env.set(legacy_v10_until=TOMORROW)
    assert miner().legacy_v10_until == dt.date.fromisoformat(TOMORROW)


def test_validator_legacy_client(tw_env: TWEnv) -> None:
    tw_env.set(netuid=1, wallet_name="v", legacy_v10_client="auto")
    with fails("requires TW_LEGACY_V10_CLIENT_UNTIL"):
        c.ValidatorSettings.from_env()
    tw_env.set(legacy_v10_client_until="2020-01-01")
    with fails("TW_LEGACY_V10_CLIENT_UNTIL: end date"):
        c.ValidatorSettings.from_env()
    tw_env.set(legacy_v10_client_until=TOMORROW)
    assert c.ValidatorSettings.from_env().legacy_v10_client == "auto"
    tw_env.set(legacy_v10_client="always")
    with fails("TW_LEGACY_V10_CLIENT"):
        c.ValidatorSettings.from_env()


def test_weakened_settings(env: TWEnv, tw_env: TWEnv) -> None:
    env.set(require_permit=False, sign_responses=False, refuse_if_coldkey_present=False)
    assert set(miner().weakened_settings()) == {
        "TW_REQUIRE_PERMIT",
        "TW_SIGN_RESPONSES",
        "TW_REFUSE_IF_COLDKEY_PRESENT",
    }
    env.set(verify_responses=False, sidecar_unsafe_bind=True)
    assert c.ValidatorSettings.from_env().weakened_settings()[-1] == "TW_VERIFY_RESPONSES"
    assert c.SidecarSettings.from_env().weakened_settings()[-1] == "TW_SIDECAR_UNSAFE_BIND"


@pytest.mark.parametrize("name", sorted(c.known_variables()))
@pytest.mark.parametrize("garbage", ["%%not json%%", "[1,", "{}", " "])
def test_any_value_gives_settings_or_config_error(env: TWEnv, name: str, garbage: str) -> None:
    """No raw parsing error escapes (complex fields must be marked NoDecode)."""
    env.set(**{name.removeprefix("TW_").lower(): garbage})
    for model in (c.MinerSettings, c.ValidatorSettings, c.SidecarSettings):
        with contextlib.suppress(ConfigError):
            model.from_env()


# --------------------------------------------------------------- unknown variables


def test_unknown_variable_is_an_error_with_hint(
    env: TWEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TW_NETUDI", "1")
    with fails(r"unknown TW_\* variable\(s\): TW_NETUDI \(did you mean TW_NETUID\?\)"):
        miner()


def test_unknown_variable_without_hint(env: TWEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TW_ZZZZZZZZZZ", "1")
    with fails(r"TW_ZZZZZZZZZZ$"):
        miner()


def test_unknown_variable_lower_case(env: TWEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("tw_bogus_setting", "1")
    with fails("tw_bogus_setting"):
        miner()


def test_variables_of_other_process_types_are_known(env: TWEnv) -> None:
    """One .env can be shared by miner, validator and sidecar on a host."""
    env.set(sample_size=10, sidecar_port=9911)
    miner()
    c.ValidatorSettings.from_env()


def test_non_tw_variables_are_ignored(env: TWEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BT_CHAIN_ENDPOINT", "ws://x")
    monkeypatch.setenv("TWX_OTHER", "1")
    miner()


def test_unknown_keyword_argument() -> None:
    with fails("unknown setting"):
        c.ValidatorSettings(netuid=1, wallet_name="v", sampel_size=3)  # type: ignore[call-arg]


def test_direct_construction(tw_env: TWEnv) -> None:
    s = c.ValidatorSettings(netuid=1, wallet_name="v", sample_size=3)
    assert s.sample_size == 3
    with pytest.raises(Exception, match="frozen"):
        s.sample_size = 4  # type: ignore[misc]


def test_env_file(tw_env: TWEnv, tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text("TW_NETUID=3\nTW_WALLET_NAME=m\nTW_EXTERNAL_IP=44.1.2.3\nOTHER=1\n")
    assert c.MinerSettings.from_env(f).netuid == 3
    f.write_text("TW_NETUID=3\nTW_WALLET_NAME=m\nTW_EXTERNAL_IP=44.1.2.3\nTW_EXTRENAL_PORT=1\n")
    with fails("TW_EXTRENAL_PORT"):
        c.MinerSettings.from_env(f)


def test_env_file_missing(tw_env: TWEnv, tmp_path: Path) -> None:
    with fails("env file not found"):
        c.MinerSettings.from_env(tmp_path / "nope.env")


def test_check_environment_directly() -> None:
    c.check_environment({"TW_NETUID": "1", "HOME": "/"})
    with fails("TW_X"):
        c.check_environment({"TW_X": "1"})


# --------------------------------------------------------------- helpers


def test_hostport_parse() -> None:
    assert c.HostPort.parse("0.0.0.0:1") == ("0.0.0.0", 1)
    assert c.HostPort.parse("[2001:db8::1]:65535") == ("2001:db8::1", 65535)
    with pytest.raises(ValueError, match="host:port"):
        c.HostPort.parse(":80")


@pytest.mark.parametrize(
    ("address", "ok"),
    [
        (ALICE, True),
        (BOB, True),
        ("5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu", True),
        (ALICE[:-1] + "Z", False),  # checksum
        ("1" + ALICE, False),  # length
        ("15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", False),  # Polkadot prefix 0
        ("", False),
        ("0OIl", False),  # not base58
    ],
)
def test_ss58(address: str, ok: bool) -> None:
    assert c._is_ss58(address) is ok


def test_direct_construction_type_errors(tw_env: TWEnv) -> None:
    with fails("TW_TRUSTED_PROXIES"):
        c.MinerSettings(netuid=1, wallet_name="m", external_ip="44.1.2.3", trusted_proxies=5)  # type: ignore[arg-type]
    s = c.MinerSettings(
        netuid=1,
        wallet_name="m",
        external_ip="44.1.2.3",
        trusted_proxies=["10.0.0.0/8"],  # type: ignore[arg-type]
    )
    assert [str(n) for n in s.trusted_proxies] == ["10.0.0.0/8"]


ENV_EXAMPLE = Path(__file__).resolve().parents[3] / ".env.example"


def test_env_example_lists_every_variable_once() -> None:
    names = re.findall(r"^(?:# )?(TW_[A-Z0-9_]+)=", ENV_EXAMPLE.read_text(), re.M)
    assert sorted(names) == sorted(c.known_variables())


def test_env_example_loads_with_required_values(tw_env: TWEnv) -> None:
    """The example's values are the real defaults and pass validation."""
    tw_env.set(netuid=1, wallet_name="m", external_ip="44.1.2.3")
    s = c.MinerSettings.from_env(ENV_EXAMPLE)
    assert s == c.MinerSettings(netuid=1, wallet_name="m", external_ip="44.1.2.3")
    assert c.ValidatorSettings.from_env(ENV_EXAMPLE) == c.ValidatorSettings(
        netuid=1, wallet_name="m"
    )
    assert c.SidecarSettings.from_env(ENV_EXAMPLE) == c.SidecarSettings(netuid=1, wallet_name="m")
