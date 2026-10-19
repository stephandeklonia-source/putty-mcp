"""Host parsing, arg building, path quoting utilities."""

from __future__ import annotations

import re
from typing import Any, Callable


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
    elif host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif host.count(":") == 1:
        # Exactly one colon: host:port. More than one is a bare IPv6 address.
        parts = host.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])

    return {"username": username, "host": host, "port": port}


def build_connection_args(
    host: str,
    port: int | None = None,
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

    # Port (non-serial). Omitted when None so PuTTY uses the protocol's
    # default port, or the port stored in a loaded saved session.
    if port is not None and protocol != "serial":
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


_UNSAFE_PROXY_CHARS = re.compile(r'[\s"\'`;&|<>$^%]')


def build_proxy_chain(
    jump_hosts: list[str],
    plink: str = "plink",
    hostkey_args: Callable[[str, int | None], list[str]] | None = None,
) -> str:
    """Build nested -proxycmd string for multi-hop SSH.

    jump_hosts: list of "user@host:port" strings in hop order.
    Returns the -proxycmd value for the outermost plink call. The last
    jump connects to PuTTY's %host:%port placeholders (the final target).

    plink: path of plink.exe; backslashes become forward slashes because
    PuTTY treats backslashes in proxy commands as escapes.
    hostkey_args(host, port): extra -hostkey arguments for each jump.

    For 2 jumps [j1, j2]:
      cmd1 = plink -batch j1 -nc j2_host:j2_port
      cmd2 = plink -proxycmd "cmd1" -batch j2 -nc %host:%port
    """
    if not jump_hosts:
        return ""

    for jh in jump_hosts:
        # The chain is a single command string (run via a shell on Unix),
        # so refuse anything that could break out of it.
        if not jh or _UNSAFE_PROXY_CHARS.search(jh):
            raise ValueError(f"Invalid jump host: {jh!r}")

    parsed = [parse_host_string(jh) for jh in jump_hosts]
    plink = plink.replace("\\", "/")
    if " " in plink:
        plink = f'"{plink}"'

    # Build from inside out: each jump wraps the previous command
    current_cmd: str | None = None

    for i, j in enumerate(parsed):
        if i == len(parsed) - 1:
            next_host = "%host"
            next_port = "%port"
        else:
            nxt = parsed[i + 1]
            next_host = nxt["host"]
            next_port = str(nxt["port"] or 22)

        parts = [plink, "-batch"]
        if hostkey_args:
            parts.extend(hostkey_args(j["host"], j["port"]))
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


_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Z0-9]|\x1b[=>]|\r(?=\n)")


def strip_ansi(text: str) -> str:
    """Remove terminal escape sequences (colours, cursor moves, titles)."""
    return _ANSI.sub("", text)


def limit_text(text: str, max_chars: int) -> str:
    """Keep the start and end of long output, dropping the middle."""
    if len(text) <= max_chars:
        return text
    head = max_chars * 2 // 3
    tail = max_chars - head
    dropped = len(text) - head - tail
    return f"{text[:head]}\n\n… [{dropped} characters omitted — output limit {max_chars}] …\n\n{text[-tail:]}"
