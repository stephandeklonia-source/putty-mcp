"""Recognise plink/pscp/psftp host key failures and manage trusted keys.

All PuTTY tools run with -batch, so an unknown host key makes them abort
instead of prompting. The operator then decides in the dashboard; a trusted
fingerprint is passed back to PuTTY with -hostkey.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

UNKNOWN = "unknown"
MISMATCH = "mismatch"

_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?|(?:[0-9a-f]{2}:){15}[0-9a-f]{2}")
_KEY_LINE = re.compile(r"^\s*((?:ssh|ecdsa)-\S+ \d+ (?:SHA256:\S+|(?:[0-9a-f]{2}:){15}[0-9a-f]{2}))\s*$", re.M)
_UNKNOWN_MARKERS = ("host key is not cached", "cannot confirm a host key in batch mode")
_MISMATCH_MARKERS = (
    "potential security breach",
    "does not match the one putty has cached",
    "host key does not match",
    "not in manually configured list",
)


@dataclass
class HostKeyProblem:
    kind: str  # UNKNOWN or MISMATCH
    fingerprint: str | None
    key_line: str | None  # e.g. "ssh-ed25519 255 SHA256:..."


def detect(output: str) -> HostKeyProblem | None:
    lower = output.lower()
    if any(m in lower for m in _MISMATCH_MARKERS):
        return HostKeyProblem(MISMATCH, None, None)
    if any(m in lower for m in _UNKNOWN_MARKERS):
        line = _KEY_LINE.search(output)
        fp = _FINGERPRINT.search(line.group(1) if line else output)
        return HostKeyProblem(UNKNOWN, fp.group(0) if fp else None, line.group(1) if line else None)
    return None


def key_id(host: str, port: int | None) -> str:
    return f"{host.lower()}:{port or 22}"


def trusted_args(trusted: dict[str, list[str]], host: str, port: int | None) -> list[str]:
    """-hostkey arguments for the fingerprints the operator trusted."""
    args: list[str] = []
    for fp in trusted.get(key_id(host, port), []):
        args.extend(["-hostkey", fp])
    return args
