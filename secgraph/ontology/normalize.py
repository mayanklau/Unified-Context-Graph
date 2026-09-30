"""Identifier normalisation.

Two sources rarely spell the same entity the same way. Every identifier is
normalised before it is compared or stored, so ``WEB-01.Corp.Local.`` and
``web-01.corp.local`` are one host and ``00-1A-2B-3C-4D-5E`` and
``001a.2b3c.4d5e`` are one interface.
"""

from __future__ import annotations

import ipaddress
import re

from secgraph.errors import ValidationFailed

_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ATTACK = re.compile(r"^(T|TA|AML\.T|AML\.TA)\d{4}(\.\d{3})?$")
_HOST_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
MAX_IDENTIFIER_LENGTH = 512


def _fail(kind: str, value: str, why: str) -> ValidationFailed:
    return ValidationFailed(f"identifier {kind}={value!r} is invalid: {why}")


def normalize_identifier(normalizer: str, kind: str, value: object) -> str:
    """Return the canonical form of ``value`` or raise ``ValidationFailed``."""
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise _fail(kind, str(value), "must be a string")
    text = str(value).strip()
    if not text:
        raise _fail(kind, text, "is empty")
    if len(text) > MAX_IDENTIFIER_LENGTH:
        raise _fail(kind, text[:32] + "…", f"longer than {MAX_IDENTIFIER_LENGTH} characters")
    if any(ord(c) < 32 for c in text):
        raise _fail(kind, text, "contains control characters")

    match normalizer:
        case "none":
            return text
        case "lower":
            return text.lower()
        case "upper":
            return text.upper()
        case "hostname":
            host = text.lower().rstrip(".")
            if "." in host:  # a short name was expected; keep the first label
                host = host.split(".", 1)[0]
            if not _HOST_LABEL.match(host):
                raise _fail(kind, text, "not a valid host name")
            return host
        case "fqdn":
            fqdn = text.lower().rstrip(".")
            labels = fqdn.split(".")
            if len(labels) < 2 or not all(_HOST_LABEL.match(label) for label in labels):
                raise _fail(kind, text, "not a fully qualified domain name")
            return fqdn
        case "mac":
            hexed = re.sub(r"[^0-9a-f]", "", text.lower())
            if not _MAC_HEX.match(hexed):
                raise _fail(kind, text, "not a MAC address")
            return ":".join(hexed[i : i + 2] for i in range(0, 12, 2))
        case "ip":
            try:
                return str(ipaddress.ip_address(text))
            except ValueError as exc:
                raise _fail(kind, text, "not an IP address") from exc
        case "cidr":
            try:
                return str(ipaddress.ip_network(text, strict=False))
            except ValueError as exc:
                raise _fail(kind, text, "not a CIDR block") from exc
        case "email":
            mail = text.lower()
            if mail.count("@") != 1 or mail.startswith("@") or mail.endswith("@") or " " in mail:
                raise _fail(kind, text, "not an address of the form user@domain")
            return mail
        case "cve":
            cve = text.upper()
            if not _CVE.match(cve):
                raise _fail(kind, text, "not a CVE id")
            return cve
        case "attack_id":
            tid = text.upper()
            if not _ATTACK.match(tid):
                raise _fail(kind, text, "not an ATT&CK / ATLAS id")
            return tid
        case "purl":
            if not text.lower().startswith("pkg:"):
                raise _fail(kind, text, "package URLs start with 'pkg:'")
            scheme_type, _, rest = text.partition("/")
            return scheme_type.lower() + "/" + rest if rest else scheme_type.lower()
        case "cpe":
            cpe = text.lower()
            if not cpe.startswith("cpe:"):
                raise _fail(kind, text, "CPE names start with 'cpe:'")
            return cpe
    raise _fail(kind, text, f"unknown normalizer '{normalizer}'")  # pragma: no cover - guarded by the schema


def derive_identifier(derive: str, value: str) -> str | None:
    if derive == "first_label":
        label = value.split(".", 1)[0]
        return label or None
    return None  # pragma: no cover - guarded by the schema
