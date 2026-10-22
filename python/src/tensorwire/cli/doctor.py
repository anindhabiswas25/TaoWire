"""``tensorwire doctor``: check a miner's or validator's setup (spec 8.14).

Reads the same ``TW_*`` settings as the process and checks, in order:
Python and SDK versions, settings, the hotkey file, coldkey absence, chain
reachability, registration, the published axon (miner) or the validator
permit (validator), reachability of the miner's port, the clock offset,
Redis, multi-worker safety and (validator) another process signing with the
same hotkey. Each check is ``ok``, ``warn``, ``fail`` or ``skip``; the exit
status is 1 when any check fails.

Nothing secret is printed: no key material and no Redis URL (it can carry
a password).
"""

from __future__ import annotations

import ipaddress
import json
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import anyio
import httpx
import typer

from tensorwire.auth.clock import ClockGuard, ClockStatus, NtpQuery
from tensorwire.auth.keys import ColdkeyState, coldkey_state, load_hotkey
from tensorwire.auth.nonce_store import RedisNonceStore
from tensorwire.auth.sdk_check import check_sdk
from tensorwire.chain.gateway import BittensorGateway, ChainGateway, GatewayError
from tensorwire.config import CommonSettings, MinerSettings, ValidatorSettings
from tensorwire.crypto import HotkeySigner
from tensorwire.errors import ConfigError, StartupError
from tensorwire.validator.lock import HotkeyLock

__all__ = ["Check", "Doctor", "doctor"]

Status = Literal["ok", "warn", "fail", "skip"]
Role = Literal["miner", "validator"]
_SUPPORTED_PYTHON = ((3, 10), (3, 15))


@dataclass(frozen=True)
class Check:
    """One line of the report."""

    name: str
    status: Status
    detail: str


class Doctor:
    """Runs the checks for one role. Parts are injectable for tests."""

    def __init__(
        self,
        role: Role,
        *,
        env_file: Path | None = None,
        probe_url: str | None = None,
        gateway_factory: Callable[[CommonSettings, Any], ChainGateway] | None = None,
        ntp_query: NtpQuery | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        redis_factory: Callable[[str], Any] | None = None,
        python_version: tuple[int, int] | None = None,
    ) -> None:
        self.role = role
        self.env_file = env_file
        self.probe_url = probe_url
        self._gateway_factory = gateway_factory or BittensorGateway.from_settings
        self._ntp_query = ntp_query
        self._transport = http_transport
        self._redis_factory = redis_factory or RedisNonceStore
        self._python = python_version or (sys.version_info[0], sys.version_info[1])
        self.checks: list[Check] = []

    def add(self, name: str, status: Status, detail: str) -> Status:
        """Record one result."""
        self.checks.append(Check(name, status, detail))
        return status

    @property
    def failed(self) -> bool:
        """Whether any check failed."""
        return any(c.status == "fail" for c in self.checks)

    async def run(self) -> list[Check]:
        """Run every check; later checks are skipped when a prerequisite fails."""
        self._python_check()
        self._sdk_check()
        settings = self._settings()
        if settings is None:
            return self.checks
        signer = self._hotkey(settings)
        self._coldkey(settings)
        gateway = await self._chain(settings, signer)
        if gateway is not None and signer is not None:
            try:
                await self._registration(settings, gateway, signer.ss58_address)
            finally:
                await gateway.close()
        if isinstance(settings, MinerSettings):
            await self._port(settings)
        await self._clock(settings)
        self._redis(settings)
        self._workers(settings)
        if isinstance(settings, ValidatorSettings) and signer is not None:
            self._lock(settings, signer.ss58_address)
        return self.checks

    # ------------------------------------------------------------ checks

    def _python_check(self) -> None:
        low, high = _SUPPORTED_PYTHON
        version = ".".join(map(str, self._python))
        if low <= self._python < high:
            self.add("python", "ok", version)
        else:
            self.add("python", "fail", f"{version}; supported: >=3.10,<3.15")

    def _sdk_check(self) -> None:
        try:
            report = check_sdk()
        except StartupError as exc:
            self.add("sdk", "fail", str(exc))
            return
        if report.tested:
            self.add("sdk", "ok", f"bittensor {report.version}")
        else:
            self.add(
                "sdk", "warn", f"bittensor {report.version} is in range but untested"
            )

    def _settings(self) -> CommonSettings | None:
        model: type[CommonSettings] = (
            MinerSettings if self.role == "miner" else ValidatorSettings
        )
        try:
            settings = model.from_env(self.env_file)
        except ConfigError as exc:
            self.add("settings", "fail", str(exc))
            return None
        weakened = settings.weakened_settings()
        if weakened:
            self.add(
                "settings", "warn", "unsafe settings active: " + ", ".join(weakened)
            )
        else:
            self.add(
                "settings", "ok", f"netuid {settings.netuid} on {settings.network}"
            )
        return settings

    def _hotkey(self, s: CommonSettings) -> HotkeySigner | None:
        try:
            keypair = load_hotkey(s.wallet_path, s.wallet_name, s.wallet_hotkey)
            signer = HotkeySigner(keypair)
        except (StartupError, OSError, ValueError, TypeError) as exc:
            self.add("hotkey", "fail", f"{s.wallet_name}/{s.wallet_hotkey}: {exc}")
            return None
        self.add("hotkey", "ok", f"{signer.ss58_address} ({signer.scheme})")
        return signer

    def _coldkey(self, s: CommonSettings) -> None:
        state = coldkey_state(s.wallet_path, s.wallet_name)
        if state is ColdkeyState.UNENCRYPTED:
            status: Status = "fail" if s.refuse_if_coldkey_present else "warn"
            self.add(
                "coldkey",
                status,
                "an unencrypted coldkey is readable on this host; move it off "
                "(only the hotkey is needed)",
            )
        elif state is ColdkeyState.ENCRYPTED:
            self.add("coldkey", "warn", "an encrypted coldkey is on this host")
        else:
            self.add("coldkey", "ok", "no coldkey on this host")

    async def _chain(
        self, s: CommonSettings, signer: HotkeySigner | None
    ) -> ChainGateway | None:
        gateway = self._gateway_factory(s, signer)
        try:
            with anyio.fail_after(s.chain_timeout_s):
                await gateway.connect()
                block = await gateway.block()
        except (GatewayError, TimeoutError, OSError) as exc:
            self.add("chain", "fail", f"{s.network}: {type(exc).__name__}: {exc}")
            await gateway.close()
            return None
        self.add("chain", "ok", f"{s.network} at block {block}")
        return gateway

    async def _registration(
        self, s: CommonSettings, gateway: ChainGateway, hotkey: str
    ) -> None:
        try:
            mg = await gateway.metagraph(s.netuid)
        except GatewayError as exc:
            self.add("registered", "fail", f"metagraph unavailable: {exc}")
            return
        me = mg.by_hotkey(hotkey)
        if me is None:
            self.add(
                "registered",
                "fail",
                f"not registered on netuid {s.netuid}: btcli tx burned-register "
                f"--netuid {s.netuid} -w {s.wallet_name} -H {s.wallet_hotkey}",
            )
            return
        self.add("registered", "ok", f"uid {me.uid} on netuid {s.netuid}")
        if isinstance(s, MinerSettings):
            axon = me.axon
            want = f"{s.external_ip}:{s.effective_external_port}"
            have = None if axon is None else f"{axon.host}:{axon.port}"
            if (
                axon is not None
                and _same_ip(axon.host, s.external_ip)
                and axon.port == s.effective_external_port
                and me.axon_protocol == s.protocol_tag
            ):
                self.add("axon", "ok", f"{want} protocol {s.protocol_tag}")
            else:
                self.add(
                    "axon",
                    "warn",
                    f"on chain {have} protocol {me.axon_protocol}, configured {want} "
                    f"protocol {s.protocol_tag}; the miner publishes it at startup",
                )
        elif me.validator_permit:
            self.add("permit", "ok", "validator permit held")
        else:
            self.add(
                "permit",
                "warn",
                "no validator permit yet: weight commits are accepted but do not count",
            )

    async def _port(self, s: MinerSettings) -> None:
        if self.probe_url is not None:
            url, what = self.probe_url, "external probe"
        else:
            host = s.external_ip
            if ":" in host:
                host = f"[{host}]"
            url = f"http://{host}:{s.effective_external_port}/healthz"
            what = "from this host only (pass --probe-url for an outside check)"
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=5.0, follow_redirects=False
            ) as http:
                r = await http.get(url)
        except httpx.HTTPError as exc:
            self.add(
                "port", "warn", f"{what}: {type(exc).__name__} (is the miner running?)"
            )
            return
        status: Status = "ok" if r.is_success else "warn"
        self.add("port", status, f"{what}: HTTP {r.status_code}")

    async def _clock(self, s: CommonSettings) -> None:
        skew = getattr(s, "auth_allowed_skew_s", 2.0)
        guard = ClockGuard(s.ntp_servers, allowed_skew_s=skew, query=self._ntp_query)
        reading = await guard.check_async()
        if reading.status is ClockStatus.UNKNOWN:
            self.add(
                "clock", "warn", "offset unknown (no NTP answer or ntplib missing)"
            )
        elif reading.status is ClockStatus.SKEWED:
            self.add("clock", "fail", f"offset {reading.offset_s:+.3f} s > {skew} s")
        elif reading.status is ClockStatus.WARN:
            self.add("clock", "warn", f"offset {reading.offset_s:+.3f} s")
        else:
            self.add("clock", "ok", f"offset {reading.offset_s:+.3f} s")

    def _redis(self, s: CommonSettings) -> None:
        if s.redis_url is None:
            self.add("redis", "skip", "TW_REDIS_URL not set (per-process nonce store)")
            return
        try:
            store = self._redis_factory(s.redis_url.get_secret_value())
            ok = bool(store.ping())
            close = getattr(store, "close", None)
            if close is not None:
                close()
        except RuntimeError as exc:  # the redis extra is missing
            self.add("redis", "fail", str(exc))
            return
        self.add("redis", "ok" if ok else "fail", "reachable" if ok else "unreachable")

    def _workers(self, s: CommonSettings) -> None:
        if not isinstance(s, MinerSettings):
            self.add("workers", "ok", "one signing process per validator hotkey")
            return
        multi = s.workers > 1 or s.instance_count > 1
        if not multi:
            self.add("workers", "ok", "single process")
        elif s.redis_url is None:
            self.add("workers", "fail", "several workers need TW_REDIS_URL (replays)")
        else:
            self.add(
                "workers",
                "warn",
                "shared nonce store; rate limits are per process until the Redis "
                "limiter",
            )

    def _lock(self, s: ValidatorSettings, hotkey: str) -> None:
        if HotkeyLock(s.state_dir, hotkey).is_held_elsewhere():
            self.add(
                "lock",
                "warn",
                "a validator with this hotkey is running on this host; run one "
                "signing process per hotkey",
            )
        else:
            self.add("lock", "ok", "no other process signs as this hotkey here")


def _same_ip(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


_MARKS = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL", "skip": "skip"}


def doctor(
    role: Annotated[
        str, typer.Option("--role", "-r", help="miner or validator.")
    ] = "miner",
    env_file: Annotated[
        Path | None, typer.Option("--env-file", help="A .env file to read too.")
    ] = None,
    probe_url: Annotated[
        str | None,
        typer.Option("--probe-url", help="External URL that checks your miner port."),
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Machine-readable output.")
    ] = False,
) -> None:
    """Check this host's miner or validator setup. Exit 1 if any check fails."""
    if role not in ("miner", "validator"):
        raise typer.BadParameter("use miner or validator", param_hint="--role")
    chosen: Role = "miner" if role == "miner" else "validator"
    doc = Doctor(chosen, env_file=env_file, probe_url=probe_url)
    checks = anyio.run(doc.run)
    if as_json:
        typer.echo(json.dumps([asdict(c) for c in checks], indent=2))
    else:
        for c in checks:
            typer.echo(f"[{_MARKS[c.status]}] {c.name:<10} {c.detail}")
    raise typer.Exit(1 if doc.failed else 0)
