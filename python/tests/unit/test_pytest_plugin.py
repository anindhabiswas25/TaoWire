"""testing/pytest_plugin.py: the tw_env fixture."""

from __future__ import annotations

import os

import pytest

from taowire.testing.pytest_plugin import TWEnv


@pytest.fixture
def leaked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TW_LEAKED", "1")
    monkeypatch.setenv("tw_lower", "1")


@pytest.mark.usefixtures("leaked")
def test_tw_env_clears_inherited_variables(request: pytest.FixtureRequest) -> None:
    env: TWEnv = request.getfixturevalue("tw_env")
    assert not [k for k in os.environ if k.upper().startswith("TW_")]
    env.set(netuid=3, metagraph_strict=True, sign_responses=False)
    assert os.environ["TW_NETUID"] == "3"
    assert os.environ["TW_METAGRAPH_STRICT"] == "1"
    assert os.environ["TW_SIGN_RESPONSES"] == "0"
    env.unset("netuid", "not_set")
    assert "TW_NETUID" not in os.environ


def test_plugin_is_registered(pytestconfig: pytest.Config) -> None:
    assert pytestconfig.pluginmanager.has_plugin("taowire")
