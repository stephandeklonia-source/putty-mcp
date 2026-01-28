"""Host parsing, arg building, path quoting utilities."""

from __future__ import annotations

import re
from typing import Any


def parse_host_string(host_string: str) -> dict[str, Any]:
    """Parse 'user@host:port' into components.

    Returns:
        {"username": str|None, "host": str, "port": int|None}
    """
    username = None
    port = None
    host = host_string

    if "@" in host:
        username, host = host.rsplit("@", 1)

    # Handle [IPv6]:port or host:port
    m = re.match(r"^\[(.+)\]:(\d+)$", host)
    if m:
        host = m.group(1)
        port = int(m.group(2))
    elif ":" in host and not host.startswith("["):
        # Only split on last colon if it looks like host:port (not IPv6)
        parts = host.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])

    return {"username": username, "host": host, "port": port}


def build_connection_args(
    host: str,
    port: int = 22,
    username: str | None = None,
    protocol: str = "ssh",
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    verbose: bool = False,
    compress: bool = False,
    x11_forward: bool = False,
    agent_forward: bool = False,
    local_forwards: list[str] | None = None,
    remote_forwards: list[str] | None = None,
    dynamic_forwards: list[int] | None = None,
    proxy_command: str | None = None,
    allocate_pty: bool | None = None,
    log_file: str | None = None,
    log_type: str | None = None,
    batch_mode: bool = False,
) -> list[str]:
    """Build common CLI args for plink/putty from connection parameters."""
    args: list[str] = []

    if session_name:
        args.extend(["-load", session_name])

    # Protocol
    proto_flag = {
        "ssh": "-ssh",
        "telnet": "-telnet",
        "serial": "-serial",
        "raw": "-raw",
        "rlogin": "-rlogin",
        "supdup": "-supdup",
    }.get(protocol)
    if proto_flag and protocol != "serial":
        args.append(proto_flag)

    if batch_mode:
        args.append("-batch")

    if verbose:
        args.append("-v")

    if compress:
        args.append("-C")

    # Auth
    if key_file:
        args.extend(["-i", key_file])

    if use_pageant:
        args.append("-agent")
    else:
        args.append("-noagent")

    # X11
    if x11_forward:
        args.append("-X")

    # Agent forwarding
    if agent_forward:
        args.append("-A")

    # PTY
    if allocate_pty is True:
        args.append("-t")
    elif allocate_pty is False:
        args.append("-T")

    # Port forwarding
    if local_forwards:
        for fwd in local_forwards:
            args.extend(["-L", fwd])
    if remote_forwards:
        for fwd in remote_forwards:
            args.extend(["-R", fwd])
    if dynamic_forwards:
        for port_num in dynamic_forwards:
            args.extend(["-D", str(port_num)])

    # Host keys
    if host_keys:
        for hk in host_keys:
            args.extend(["-hostkey", hk])

    # Proxy
    if proxy_command:
        args.extend(["-proxycmd", proxy_command])

    # Logging
    if log_file:
        log_flag = {
            "session": "-sessionlog",
            "ssh": "-sshlog",
            "sshraw": "-sshrawlog",
        }.get(log_type or "session", "-sessionlog")
        args.extend([log_flag, log_file])

    # Port (non-serial)
    if protocol != "serial":
        args.extend(["-P", str(port)])

    # Username
    if username:
        args.extend(["-l", username])

    # Host (last positional for plink, or -serial COMx for serial)
    if protocol == "serial":
        args.extend(["-serial", host])
    else:
        args.append(host)

    return args


def build_serial_args(
    serial_port: str,
    baud: int = 9600,
    data_bits: int = 8,
    parity: str = "n",
    stop_bits: int = 1,
    flow_control: str = "N",
) -> list[str]:
    """Build args for PuTTY serial connection."""
    sercfg = f"{baud},{data_bits},{parity},{stop_bits},{flow_control}"
    return ["-serial", serial_port, "-sercfg", sercfg]


def build_forward_args(
    local_forwards: list[str] | None = None,
    remote_forwards: list[str] | None = None,
    dynamic_forwards: list[int] | None = None,
) -> list[str]:
    """Build port-forwarding args."""
    args: list[str] = []
    if local_forwards:
        for fwd in local_forwards:
            args.extend(["-L", fwd])
    if remote_forwards:
        for fwd in remote_forwards:
            args.extend(["-R", fwd])
    if dynamic_forwards:
        for p in dynamic_forwards:
            args.extend(["-D", str(p)])
    return args


def build_proxy_chain(jump_hosts: list[str], target_host: str, target_port: int = 22) -> str:
    """Build nested -proxycmd string for multi-hop SSH.

    jump_hosts: list of "user@host:port" strings in order.
    Returns the -proxycmd value for the outermost plink call.
    """
    if not jump_hosts:
        return ""

    # Build from innermost (first jump) to outermost
    # Each layer: plink -batch [user@]host [-P port] -nc next_host:next_port
    # The outermost layer uses %host:%port placeholders for the final target

    # Parse all jumps
    parsed = [parse_host_string(jh) for jh in jump_hosts]

    # Start with the innermost jump connecting to the next hop
    # For a single jump: plink -batch user@jump -nc %host:%port
    # For two jumps:     plink -proxycmd "plink -batch user@j1 -nc j2:22" -batch user@j2 -nc %host:%port

    def _build_cmd(jump_idx: int, dest_host: str, dest_port: int, inner_proxy: str | None = None) -> str:
        j = parsed[jump_idx]
        parts = ["plink", "-batch"]
        if inner_proxy:
            # Escape quotes for nesting
            parts.extend(["-proxycmd", f'"{inner_proxy}"'])
        if j["port"]:
            parts.extend(["-P", str(j["port"])])
        target = f"{j['username']}@{j['host']}" if j["username"] else j["host"]
        parts.append(target)
        parts.extend(["-nc", f"{dest_host}:{dest_port}"])
        return " ".join(parts)

    if len(parsed) == 1:
        return _build_cmd(0, "%host", int("%port") if False else 0, None).replace(":0", ":%port")

    # Multi-jump: build inside-out
    # Innermost jump connects to second jump
    # Second jump connects to third, etc.
    # Outermost connects to %host:%port

    # For 2 jumps [j1, j2]:
    #   inner = plink -batch j1 -nc j2_host:j2_port
    #   outer = plink -proxycmd "inner" -batch j2 -nc %host:%port
    # For 3 jumps [j1, j2, j3]:
    #   cmd1 = plink -batch j1 -nc j2_host:j2_port
    #   cmd2 = plink -proxycmd "cmd1" -batch j2 -nc j3_host:j3_port
    #   cmd3 = plink -proxycmd "cmd2" -batch j3 -nc %host:%port

    # Build from inside out
    current_cmd: str | None = None

    for i in range(len(parsed)):
        j = parsed[i]
        is_last = i == len(parsed) - 1

        if is_last:
            next_host = "%host"
            next_port = "%port"
        else:
            nxt = parsed[i + 1]
            next_host = nxt["host"]
            next_port = str(nxt["port"] or 22)

        parts = ["plink", "-batch"]
        if current_cmd:
            escaped = current_cmd.replace('"', '\\"')
            parts.extend(["-proxycmd", f'"{escaped}"'])
        if j["port"]:
            parts.extend(["-P", str(j["port"])])
        target = f"{j['username']}@{j['host']}" if j["username"] else j["host"]
        parts.append(target)
        parts.extend(["-nc", f"{next_host}:{next_port}"])
        current_cmd = " ".join(parts)

    return current_cmd or ""
