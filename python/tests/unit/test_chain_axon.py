from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from taowire.chain.axon import Endpoint, parse_axon


@pytest.mark.parametrize(
    ("axon", "host", "port", "is_ipv6"),
    [
        ("203.0.113.7:8091", "203.0.113.7", 8091, False),
        ("8.8.8.8:1", "8.8.8.8", 1, False),
        ("1.1.1.1:65535", "1.1.1.1", 65535, False),
        ("[2001:db8::1]:8091", "2001:db8::1", 8091, True),
        ("[2001:DB8:0:0:0:0:0:1]:443", "2001:db8::1", 443, True),
        ("[2606:4700::1111]:80", "2606:4700::1111", 80, True),
        ("[::ffff:8.8.8.8]:80", "::ffff:8.8.8.8", 80, True),
        ("[::ffff:808:808]:80", "::ffff:8.8.8.8", 80, True),
    ],
)
def test_parses_public_endpoints(
    axon: str, host: str, port: int, is_ipv6: bool
) -> None:
    assert parse_axon(axon) == Endpoint(host=host, port=port, is_ipv6=is_ipv6)


def test_none_is_not_served() -> None:
    assert parse_axon(None) is None


@pytest.mark.parametrize(
    "axon",
    [
        "",
        "8.8.8.8",
        "8.8.8.8:",
        ":8091",
        "8.8.8.8:0",
        "8.8.8.8:65536",
        "8.8.8.8:99999",
        "8.8.8.8:080",
        "8.8.8.8:+80",
        "8.8.8.8:-1",
        "8.8.8.8: 80",
        "8.8.8.8:80 ",
        "08.8.8.8:80",
        "8.8.8:80",
        "256.1.1.1:80",
        "example.com:80",
        "http://8.8.8.8:80",
        "2001:db8::1:8091",
        "[2001:db8::1]",
        "[2001:db8::1]8091",
        "[2001:db8::1:8091",
        "[8.8.8.8]:80",
        "[fe80::1%eth0]:80",
        "[2001:db8::1]:0",
    ],
)
def test_rejects_malformed(axon: str) -> None:
    assert parse_axon(axon) is None
    assert parse_axon(axon, allow_private=True) is None


@pytest.mark.parametrize(
    "axon",
    [
        "0.0.0.0:8091",
        "0.1.2.3:8091",
        "224.0.0.1:8091",
        "239.255.255.250:1900",
        "240.0.0.1:80",
        "255.255.255.255:80",
        "[::]:8091",
        "[ff02::1]:8091",
        "[::ffff:0.0.0.0]:80",
    ],
)
def test_rejects_unreachable_even_when_private_allowed(axon: str) -> None:
    assert parse_axon(axon) is None
    assert parse_axon(axon, allow_private=True) is None


@pytest.mark.parametrize(
    "axon",
    [
        "10.0.0.5:8091",
        "100.64.1.1:8091",
        "127.0.0.1:8091",
        "169.254.169.254:80",
        "172.16.0.1:8091",
        "172.31.255.255:8091",
        "192.0.0.8:80",
        "192.168.1.10:8091",
        "198.18.0.1:80",
        "[::1]:8091",
        "[fc00::1]:8091",
        "[fd12:3456::1]:8091",
        "[fe80::1]:8091",
        "[fec0::1]:8091",
        "[::ffff:127.0.0.1]:8091",
        "[::ffff:10.0.0.1]:8091",
    ],
)
def test_private_ranges_need_explicit_opt_in(axon: str) -> None:
    assert parse_axon(axon) is None
    endpoint = parse_axon(axon, allow_private=True)
    assert endpoint is not None
    assert str(endpoint) == axon or endpoint.is_ipv6


@pytest.mark.parametrize(
    "axon", ["172.15.255.255:80", "172.32.0.0:80", "100.63.255.255:80"]
)
def test_private_range_edges_are_public(axon: str) -> None:
    assert parse_axon(axon) is not None


def test_base_url_ipv4() -> None:
    endpoint = Endpoint(host="203.0.113.7", port=8091, is_ipv6=False)
    assert endpoint.base_url("http") == "http://203.0.113.7:8091"
    assert endpoint.base_url("https") == "https://203.0.113.7:8091"


def test_base_url_ipv6_is_bracketed() -> None:
    endpoint = Endpoint(host="2001:db8::1", port=8091, is_ipv6=True)
    assert endpoint.base_url("http") == "http://[2001:db8::1]:8091"
    assert str(endpoint) == "[2001:db8::1]:8091"


def test_base_url_rejects_other_schemes() -> None:
    endpoint = Endpoint(host="203.0.113.7", port=8091, is_ipv6=False)
    with pytest.raises(ValueError, match="unsupported scheme"):
        endpoint.base_url("ftp")  # type: ignore[arg-type]


def test_endpoint_is_immutable() -> None:
    endpoint = Endpoint(host="203.0.113.7", port=8091, is_ipv6=False)
    with pytest.raises(AttributeError):
        endpoint.port = 1  # type: ignore[misc]


@given(
    ip=st.ip_addresses(),
    port=st.integers(min_value=1, max_value=65535),
)
def test_round_trip_through_axon_string(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int
) -> None:
    axon = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
    endpoint = parse_axon(axon, allow_private=True)
    if endpoint is None:
        return
    assert parse_axon(str(endpoint), allow_private=True) == endpoint
    assert ipaddress.ip_address(endpoint.host) == ip


@given(st.text(max_size=64))
def test_never_raises_on_arbitrary_text(text: str) -> None:
    parse_axon(text)
    parse_axon(text, allow_private=True)
