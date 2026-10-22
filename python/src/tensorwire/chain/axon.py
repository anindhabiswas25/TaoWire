"""Parsing of on-chain axon strings into validated endpoints (spec 8.7.2).

The v11 metagraph reports a neuron's axon as ``"a.b.c.d:port"``,
``"[v6]:port"`` or ``None``. The string carries no scheme; the kit picks
``http`` or ``https`` itself. Anything that is not a well-formed, routable
endpoint is rejected here, so a validator never connects to it. Rejecting
private and loopback ranges by default stops a registered neuron from
pointing validators at internal services (trap 16 in spec 16.1).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

__all__ = ["Endpoint", "parse_axon"]

_PORT_RE = re.compile(r"(?:[1-9][0-9]{0,4})")

# Never valid, even on localnet: nothing can be reached at these addresses.
_NEVER_V4 = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "0.0.0.0/8",  # "this network", includes the unspecified address
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, includes the limited broadcast address
    )
)
_NEVER_V6 = tuple(
    ipaddress.IPv6Network(n)
    for n in (
        "::/128",  # unspecified
        "ff00::/8",  # multicast
    )
)

# Rejected unless private axons are explicitly allowed (TW_ALLOW_PRIVATE_AXONS=1).
# An explicit list instead of ``ipaddress.is_private`` / ``is_global``: those
# change between Python versions, and the decision must be identical on every
# supported interpreter. Documentation ranges are not listed: they are not
# routable, so they cannot be used to reach internal services.
_PRIVATE_V4 = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "10.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, includes cloud metadata services
        "172.16.0.0/12",
        "192.0.0.0/24",  # IETF protocol assignments
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
    )
)
_PRIVATE_V6 = tuple(
    ipaddress.IPv6Network(n)
    for n in (
        "::1/128",  # loopback
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
    )
)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A validated miner endpoint.

    ``host`` is the IP address in canonical form, without brackets
    (``"203.0.113.7"`` or ``"2001:db8::1"``).
    """

    host: str
    port: int
    is_ipv6: bool

    def base_url(self, scheme: Literal["http", "https"]) -> str:
        """Return ``scheme://host:port`` with IPv6 hosts in brackets."""
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme {scheme!r}")
        return f"{scheme}://{self}"

    def __str__(self) -> str:
        """The axon string form: ``host:port`` or ``[host]:port``."""
        host = f"[{self.host}]" if self.is_ipv6 else self.host
        return f"{host}:{self.port}"


def parse_axon(s: str | None, *, allow_private: bool = False) -> Endpoint | None:
    """Parse an on-chain axon string into an :class:`Endpoint`.

    Accepts ``"a.b.c.d:port"`` and ``"[v6]:port"``. Returns ``None`` for
    ``None`` and for anything that must not be contacted: malformed strings,
    port 0, the unspecified address, multicast and reserved ranges, and, unless
    ``allow_private`` is set (localnet only), private, loopback and link-local
    ranges. An IPv4-mapped IPv6 address is judged by its embedded IPv4 address.
    """
    if s is None:
        return None
    if s.startswith("["):
        host_part, sep, port_part = s[1:].partition("]:")
        if not sep:
            return None
    else:
        host_part, sep, port_part = s.rpartition(":")
        if not sep or ":" in host_part:
            return None
    if not _PORT_RE.fullmatch(port_part):
        return None
    port = int(port_part)
    if port > 65535:
        return None
    ip = _parse_ip(host_part, bracketed=s.startswith("["))
    if ip is None or not _allowed(ip, allow_private=allow_private):
        return None
    return Endpoint(host=_canonical(ip), port=port, is_ipv6=ip.version == 6)


def _parse_ip(
    text: str, *, bracketed: bool
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if "%" in text:  # zone identifiers are host-local, never valid on chain
        return None
    try:
        if bracketed:
            return ipaddress.IPv6Address(text)
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def _canonical(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    # ``str()`` of an IPv4-mapped address differs between Python versions;
    # use the RFC 5952 section 5 form on all of them.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return f"::ffff:{ip.ipv4_mapped}"
    return str(ip)


def _allowed(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool
) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _allowed(ip.ipv4_mapped, allow_private=allow_private)
        if any(ip in net for net in _NEVER_V6):
            return False
        return allow_private or not any(ip in net for net in _PRIVATE_V6)
    if any(ip in net for net in _NEVER_V4):
        return False
    return allow_private or not any(ip in net for net in _PRIVATE_V4)
