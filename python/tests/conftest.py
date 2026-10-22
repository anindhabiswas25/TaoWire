"""Shared fixtures for the TensorWire test suite."""

from __future__ import annotations

from pathlib import Path

import pytest
from bittensor.keyfiles import Keypair

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "TENSORWIRE_BUILD_SPEC.md"


@pytest.fixture(scope="session")
def spec_text() -> str:
    """The build spec, so tests can check the code against its tables."""
    return SPEC_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def alice() -> Keypair:
    """//Alice sr25519 dev key (never written to disk)."""
    return Keypair.create_from_uri("//Alice")


@pytest.fixture(scope="session")
def bob() -> Keypair:
    """//Bob sr25519 dev key (never written to disk)."""
    return Keypair.create_from_uri("//Bob")
