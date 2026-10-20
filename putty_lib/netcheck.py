"""Reachability checks from this computer: TCP connect and ICMP ping.

Deliberately limited to a handful of ports on one host: this is a
pre-flight check for administration, not a port scanner.
"""

from __future__ import annotations

import re
import socket
import sys
import time
from typing import Any

MAX_PORTS = 20
MAX_PINGS = 10

# Host names and IP addresses only; in particular nothing starting with "-",
# which ping would read as an option.
_HOST = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._:-]*$")

# Reply times in any language: "time=1ms", "tijd<1ms", "time=0.045 ms", "Zeit=3ms"
_REPLY_TIME = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.I)
_LOSS = re.compile(r"(\d+(?:[.,]\d+)?)\s*%")


def validate_host(host: str) -> str:
    host = host.strip()
    if not _HOST.match(host):
        raise ValueError(f"Not a valid host name or IP address: {host!r}")
    return host


def resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def tcp_check(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Try a TCP connection; read a banner if the service sends one first (SSH does)."""
    started = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "detail": "connection refused"}
    except socket.timeout:
        return {"port": port, "state": "filtered", "detail": f"no answer within {timeout:g}s"}
    except OSError as e:
        return {"port": port, "state": "error", "detail": str(e)}
    result: dict[str, Any] = {"port": port, "state": "open", "connect_ms": round((time.monotonic() - started) * 1000, 1)}
    try:
        sock.settimeout(min(1.0, timeout))
        banner = sock.recv(256).decode("utf-8", "replace").strip()
        if banner:
            result["banner"] = banner.splitlines()[0][:200]
    except OSError:
        pass  # many services wait for the client to speak first
    finally:
        sock.close()
    return result


def ping_command(host: str, count: int, timeout: float) -> list[str]:
    if sys.platform == "win32":
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    if sys.platform == "darwin":
        return ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), host]
    return ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), host]


def parse_ping(output: str, count: int) -> dict[str, Any]:
    """Language-independent summary of ping output."""
    # Only real replies carry a TTL (Windows "TTL=64", Linux "ttl=64"), in
    # every language; this skips the Windows min/max/average summary line.
    times = []
    for line in output.splitlines():
        if re.search(r"\bttl[=:]", line, re.I):
            m = _REPLY_TIME.search(line)
            times.append(float(m.group(1).replace(",", ".")) if m else 0.0)
    loss = _LOSS.findall(output)
    summary: dict[str, Any] = {
        "sent": count,
        "received": len(times),
        "reachable": bool(times),
    }
    if loss:
        summary["loss_percent"] = float(loss[-1].replace(",", "."))
    if times:
        summary.update(min_ms=min(times), avg_ms=round(sum(times) / len(times), 2), max_ms=max(times))
    return summary
