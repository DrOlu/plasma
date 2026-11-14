"""Redaction for command lines that carry credentials.

Sysmon records the full process command line. Administrative tooling puts
passwords there (`net user bob P@ss /add`, `-Password ...`), so an EDR that
stores raw command lines becomes a credential store. Redact only the
secret-bearing shapes; keep the rest of the command for investigation.
"""

from __future__ import annotations

import re

_NET_USER = re.compile(
    r"(?i)(\bnet(?:1|\.exe)?\s+user\s+\S+\s+)(?![/-])(?:\"[^\"]*\"|'[^']*'|\S+)")
_NAMED_SECRET = re.compile(
    r"(?i)((?:-|/)(?:password|passwd|pwd)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)")
_SECURE_STRING = re.compile(
    r"(?i)(ConvertTo-SecureString\s+)([\"'])(.*?)\2")
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|secret|api[_-]?key)\b\s*[:=]\s*)"
    r"([\"']?)([^\s\"';,]+)")
_BEARER = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")


def redact_text(value: str) -> str:
    if value is None:
        return value
    text = str(value)
    text = _NET_USER.sub(r"\1<redacted>", text)
    text = _NAMED_SECRET.sub(r"\1<redacted>", text)
    text = _SECURE_STRING.sub(r"\1\2<redacted>\2", text)
    text = _KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text)
    text = _BEARER.sub(r"\1<redacted>", text)
    return text


def redact_event(row: dict) -> dict:
    if not isinstance(row, dict):
        return row
    out = dict(row)
    for field in ("cmdline", "command_line", "description"):
        if out.get(field) is not None:
            out[field] = redact_text(out[field])
    return out
