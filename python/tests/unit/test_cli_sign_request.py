"""cli/sign_request.py: ``taowire sign-request`` (spec 8.14)."""

from __future__ import annotations

import shlex
from pathlib import Path

import httpx
import pytest
import respx
from bittensor import http_auth, sp_core
from typer.testing import CliRunner

from taowire.cli.main import app
from taowire.testing.keys import dev_key

BOB = dev_key("bob").ss58
URL = "http://44.1.2.3:8091/v1/echo%20x?q=1"


@pytest.fixture
def wallets(tmp_path: Path) -> Path:
    hotkey = tmp_path / "validator" / "hotkeys" / "default"
    hotkey.parent.mkdir(parents=True)
    hotkey.write_bytes(
        sp_core.serialized_keypair_to_keyfile_data(dev_key("alice").keypair)
    )
    return tmp_path


def invoke(wallets: Path, *args: str, stdin: str | None = None) -> object:
    base = ["sign-request", "-r", BOB, "-w", "validator", "--wallet-path", str(wallets)]
    return CliRunner().invoke(app, [*base, *args], input=stdin, env={})


def headers_of(command: str) -> dict[str, str]:
    parts = shlex.split(command)
    return dict(parts[i + 1].split(": ", 1) for i, p in enumerate(parts) if p == "-H")


def test_prints_a_verifiable_curl_command(wallets: Path) -> None:
    result = invoke(wallets, URL, "-d", '{"x": 1}')
    assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
    command = result.output.strip()  # type: ignore[attr-defined]
    parts = shlex.split(command)
    assert parts[:6] == ["curl", "-sS", "--path-as-is", "-X", "POST", URL]
    assert parts[-2:] == ["--data-binary", '{"x": 1}']
    headers = headers_of(command)
    assert headers["Content-Type"] == "application/json"
    caller = http_auth.verify(
        headers,
        b'{"x": 1}',
        method="POST",
        path="/v1/echo%20x?q=1",
        self_hotkey_ss58=BOB,
        nonce_store=http_auth.InMemoryNonceStore(),
    )
    assert caller.hotkey_ss58 == dev_key("alice").ss58


def test_body_from_file_and_stdin(wallets: Path, tmp_path: Path) -> None:
    body = tmp_path / "body.json"
    body.write_bytes(b'{"f": 1}')
    out = invoke(wallets, URL, "--data-file", str(body)).output  # type: ignore[attr-defined]
    assert shlex.split(out)[-1] == '{"f": 1}'
    out = invoke(wallets, URL, "--data-file", "-", stdin='{"s": 1}').output  # type: ignore[attr-defined]
    assert shlex.split(out)[-1] == '{"s": 1}'


def test_get_without_body(wallets: Path) -> None:
    out = invoke(wallets, URL, "-X", "get").output  # type: ignore[attr-defined]
    parts = shlex.split(out)
    assert parts[4] == "GET"
    assert "--data-binary" not in parts
    assert "Content-Type" not in headers_of(out)


@respx.mock
def test_send(wallets: Path) -> None:
    route = respx.post(URL).mock(
        return_value=httpx.Response(
            200, text='{"ok":true}', headers={"x-tw-request-id": "01X"}
        )
    )
    result = invoke(wallets, URL, "-d", "{}", "--send")
    assert result.exit_code == 0  # type: ignore[attr-defined]
    assert result.output.splitlines() == [
        "HTTP 200",
        "x-tw-request-id: 01X",
        '{"ok":true}',
    ]  # type: ignore[attr-defined]
    sent = route.calls.last.request
    assert sent.headers["x-bittensor-receiver"] == BOB
    assert sent.content == b"{}"


@respx.mock
def test_send_failure_exits_1(wallets: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(429, headers={"retry-after": "3"}))
    result = invoke(wallets, URL, "-d", "{}", "--send")
    assert result.exit_code == 1  # type: ignore[attr-defined]
    assert "retry-after: 3" in result.output  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["ftp://x/y"], "URL must be http"),
        ([URL, "-d", "x", "--data-file", "f"], "not both"),
    ],
)
def test_bad_arguments(wallets: Path, args: list[str], message: str) -> None:
    result = invoke(wallets, *args)
    assert result.exit_code == 2  # type: ignore[attr-defined]
    assert message in result.output  # type: ignore[attr-defined]


def test_missing_hotkey_file(tmp_path: Path) -> None:
    result = invoke(tmp_path, URL)
    assert result.exit_code == 1  # type: ignore[attr-defined]
    assert "hotkey file not found" in result.output  # type: ignore[attr-defined]


def test_empty_receiver_is_refused(wallets: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "sign-request",
            URL,
            "-r",
            "",
            "-w",
            "validator",
            "--wallet-path",
            str(wallets),
        ],
        env={},
    )
    assert result.exit_code == 1
    assert "receiver is required" in result.output
