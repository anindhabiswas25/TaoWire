"""auth/sdk_check.py: the startup SDK check (spec 8.7.3 step 1)."""

from __future__ import annotations

import importlib
import importlib.metadata
import types

import pytest

from tensorwire.auth.sdk_check import REQUIRED_SYMBOLS, TESTED_VERSIONS, check_sdk
from tensorwire.errors import StartupError


def test_installed_sdk_passes() -> None:
    report = check_sdk()
    assert report.version == importlib.metadata.version("bittensor")
    assert report.tested is (report.version in TESTED_VERSIONS)


@pytest.mark.parametrize(
    ("version", "tested"), [("11.3.0", True), ("11.3.1", False), ("11.9.0rc2", False)]
)
def test_in_range(version: str, tested: bool) -> None:
    report = check_sdk(version_of=lambda _: version)
    assert (report.version, report.tested) == (version, tested)


@pytest.mark.parametrize(
    "version", ["11.2.9", "11.3.0rc1", "12.0.0", "10.5.0", "eleven", "11.3"]
)
def test_out_of_range(version: str) -> None:
    with pytest.raises(StartupError, match=f"bittensor {version} is not supported"):
        check_sdk(version_of=lambda _: version)


def test_not_installed() -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    with pytest.raises(StartupError, match="not installed"):
        check_sdk(version_of=missing)


def test_missing_module_is_named() -> None:
    def no_signing(name: str) -> types.ModuleType:
        if name == "bittensor.signing":
            raise ImportError(name)
        return importlib.import_module(name)

    with pytest.raises(StartupError, match=r"no module bittensor\.signing"):
        check_sdk(import_module=no_signing)


def test_missing_symbol_is_named() -> None:
    def stripped(name: str) -> types.ModuleType:
        real = importlib.import_module(name)
        if name != "bittensor.http_auth":
            return real
        fake = types.ModuleType(name)
        for attr in REQUIRED_SYMBOLS[name]:
            if attr != "verify":
                setattr(fake, attr, getattr(real, attr))
        return fake

    with pytest.raises(
        StartupError, match=r"lacks bittensor\.http_auth\.verify.*>=11\.3\.0,<12"
    ):
        check_sdk(import_module=stripped)
