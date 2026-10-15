"""Mask internal details in raw IVX responses so they can be shared safely.

Typical use: capture a raw results response during a live test, sanitise it, and attach it
to an issue so the parser can be improved without exposing the environment.

Always masked (consistent placeholders, so the structure stays readable):

* private, loopback, link-local, CGNAT and other non-public IPv4/IPv6 addresses
* MAC addresses
* e-mail addresses
* values of appliance / sensor / host attributes and JSON keys
* any extra terms you pass (host names, domains incl. their subdomains, user names)

Public IP addresses are kept by default because in malware results they are usually the
indicators you want to analyse; use ``mask_public_ips=True`` to mask them too.

This is a best-effort helper, not a guarantee: always review the output before sharing.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?![0-9A-Za-z:])"
)
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Attribute / key names whose values identify the environment rather than the sample.
_ENV_KEYS = (
    r"appliance|appliance-id|applianceid|appliance_id|sensor|sensor-ip|sensorip|sensor_ip"
    r"|host|hostname|host-name"
)
_XML_ATTR = re.compile(rf'\b({_ENV_KEYS})\s*=\s*"([^"]*)"', re.IGNORECASE)
_JSON_KEY = re.compile(rf'"({_ENV_KEYS})"\s*:\s*"([^"]*)"', re.IGNORECASE)
_XML_ELEM = re.compile(rf"<({_ENV_KEYS})>([^<]*)</\1>", re.IGNORECASE)


@dataclass
class _Masker:
    mask_public_ips: bool = False
    maps: dict[str, dict[str, str]] = field(default_factory=dict)
    counts: Counter = field(default_factory=Counter)

    def token(self, kind: str, original: str) -> str:
        table = self.maps.setdefault(kind, {})
        key = original.lower()
        if key not in table:
            table[key] = f"{kind}-redacted-{len(table) + 1}"
        self.counts[kind] += 1
        return table[key]

    def _ip_should_mask(self, text: str) -> bool:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return False
        if self.mask_public_ips:
            return True
        return not ip.is_global

    def ip(self, match: re.Match) -> str:
        value = match.group(0)
        return self.token("ip", value) if self._ip_should_mask(value) else value


def sanitize(
    text: str,
    terms: Iterable[str] = (),
    mask_public_ips: bool = False,
) -> tuple[str, dict[str, int]]:
    """Return (sanitised_text, counts_per_category)."""
    m = _Masker(mask_public_ips=mask_public_ips)

    # 0. E-mail addresses first: once their domain is masked as a host they no longer look
    #    like addresses and the user part would leak.
    text = _EMAIL.sub(lambda mt: m.token("email", mt.group(0)), text)

    # 1. Environment-identifying attribute/key values are masked in place. Distinctive
    #    values (not short or purely numeric) are also masked wherever else they appear.
    env_values: set[str] = set()

    def mask_value(match: re.Match) -> str:
        value = match.group(2).strip()
        if not value:
            return match.group(0)
        if len(value) >= 4 and not value.isdigit():
            env_values.add(value)
        start, end = match.span(2)
        offset = match.start(0)
        whole = match.group(0)
        return whole[: start - offset] + m.token("host", value) + whole[end - offset :]

    for pattern in (_XML_ATTR, _JSON_KEY, _XML_ELEM):
        text = pattern.sub(mask_value, text)

    # 2. Explicit terms: host names / domains (with subdomains) / user names.
    term_list = sorted(
        {t.strip() for t in terms if t and t.strip()} | env_values, key=len, reverse=True
    )
    for term in term_list:
        if _IPV4.fullmatch(term):
            pattern = re.compile(rf"(?<![\d.]){re.escape(term)}(?![\d.])")
        else:
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)*{re.escape(term)}(?![A-Za-z0-9_-])",
                re.IGNORECASE,
            )
        text = pattern.sub(lambda mt: m.token("host", mt.group(0)), text)

    # 3. Generic patterns.
    text = _MAC.sub(lambda mt: m.token("mac", mt.group(0)), text)
    text = _IPV4.sub(m.ip, text)
    text = _IPV6_CANDIDATE.sub(m.ip, text)
    return text, dict(m.counts)
