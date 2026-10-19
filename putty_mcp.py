"""PuTTY MCP Server — full PuTTY toolchain exposed as MCP tools.

Covers: putty.exe, plink, pscp, psftp, pageant, puttygen.
30 tools total: GUI launch, command execution, persistent sessions,
file transfer, key management, saved sessions (registry), multi-hop.
"""

from __future__ import annotations

import atexit
import logging
import time

from mcp.server.fastmcp import FastMCP

from putty_lib.config import PuTTYConfig
from putty_lib.executor import PuTTYExecutor
from putty_lib.session_manager import SessionManager
from putty_lib import registry
from putty_lib.ppk import openssh_to_ppk
from putty_lib.utils import (
    build_connection_args,
    build_proxy_chain,
    build_serial_args,
)

# ---------------------------------------------------------------------------
# Initialize
# ---------------------------------------------------------------------------

config = PuTTYConfig.load()

# Logs go to stderr; stdout is reserved for the MCP stdio transport
logging.basicConfig(
    level=config.log_level.upper() if config.log_enabled else logging.WARNING,
    format="%(name)s %(levelname)s: %(message)s",
)
log = logging.getLogger("putty-mcp")

executor = PuTTYExecutor(config)
sessions = SessionManager(
    max_concurrent=config.sessions.max_concurrent,
    timeout_seconds=config.sessions.timeout_seconds,
    buffer_lines=config.sessions.buffer_lines,
)

mcp = FastMCP("putty-mcp", json_response=True)


@atexit.register
def _shutdown() -> None:
    count = sessions.close_all()
    if count:
        log.info("Shutdown: closed %d sessions", count)


# ===================================================================
# 1. PuTTY GUI Launch (3 tools)
# ===================================================================


@mcp.tool()
def putty_open(
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
    log_file: str | None = None,
    log_type: str | None = None,
) -> dict:
    """Launch PuTTY GUI session with full connection parameters."""
    args = build_connection_args(
        host=host, port=port, username=username, protocol=protocol,
        key_file=key_file, session_name=session_name, host_keys=host_keys,
        use_pageant=use_pageant, verbose=verbose, compress=compress,
        x11_forward=x11_forward, agent_forward=agent_forward,
        local_forwards=local_forwards, remote_forwards=remote_forwards,
        dynamic_forwards=dynamic_forwards, proxy_command=proxy_command,
        log_file=log_file, log_type=log_type,
    )
    return executor.launch_gui("putty", args)


@mcp.tool()
def putty_open_session(session_name: str) -> dict:
    """Launch PuTTY GUI from a saved session name."""
    return executor.launch_gui("putty", ["-load", session_name])


@mcp.tool()
def putty_serial(
    serial_port: str,
    baud: int = 9600,
    data_bits: int = 8,
    parity: str = "n",
    stop_bits: int = 1,
    flow_control: str = "N",
) -> dict:
    """Launch PuTTY GUI on a serial port."""
    args = build_serial_args(serial_port, baud, data_bits, parity, stop_bits, flow_control)
    return executor.launch_gui("putty", args)


# ===================================================================
# 2. Plink Command Execution (3 tools)
# ===================================================================


@mcp.tool()
def plink_exec(
    host: str,
    command: str,
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
    proxy_command: str | None = None,
    allocate_pty: bool | None = None,
    timeout: int = 30,
) -> dict:
    """Run a single command on a remote host via plink. Returns stdout/stderr/rc."""
    args = build_connection_args(
        host=host, port=port, username=username, protocol=protocol,
        key_file=key_file, session_name=session_name, host_keys=host_keys,
        use_pageant=use_pageant, verbose=verbose, compress=compress,
        x11_forward=x11_forward, agent_forward=agent_forward,
        proxy_command=proxy_command, allocate_pty=allocate_pty,
        batch_mode=True,
    )
    args.append(command)
    return executor.run("plink", args, timeout=timeout)


@mcp.tool()
def plink_script(
    host: str,
    script_path: str,
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    verbose: bool = False,
    compress: bool = False,
    proxy_command: str | None = None,
    timeout: int = 60,
) -> dict:
    """Run commands from a local script file via plink -m."""
    args = build_connection_args(
        host=host, port=port, username=username, protocol="ssh",
        key_file=key_file, session_name=session_name, host_keys=host_keys,
        use_pageant=use_pageant, verbose=verbose, compress=compress,
        proxy_command=proxy_command, batch_mode=True,
    )
    # Insert -m before the host arg
    args[-1:-1] = ["-m", script_path]
    return executor.run("plink", args, timeout=timeout)


@mcp.tool()
def plink_tunnel(
    host: str,
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    compress: bool = False,
    local_forwards: list[str] | None = None,
    remote_forwards: list[str] | None = None,
    dynamic_forwards: list[int] | None = None,
    proxy_command: str | None = None,
    nc_destination: str | None = None,
) -> dict:
    """Create SSH tunnel (port forward) or -nc network connection. Returns session_id."""
    args = build_connection_args(
        host=host, port=port, username=username, protocol="ssh",
        key_file=key_file, session_name=session_name, host_keys=host_keys,
        use_pageant=use_pageant, compress=compress,
        local_forwards=local_forwards, remote_forwards=remote_forwards,
        dynamic_forwards=dynamic_forwards, proxy_command=proxy_command,
        batch_mode=True,
    )
    # Options must precede the host: plink treats everything after it
    # as the remote command.
    extra = ["-nc", nc_destination] if nc_destination else ["-N"]  # -N: no shell, just tunnel
    args[-1:-1] = extra

    proc = executor.spawn("plink", args)
    session = sessions.create(
        proc, host=host, protocol="tunnel",
        forwards={
            "local": local_forwards or [],
            "remote": remote_forwards or [],
            "dynamic": dynamic_forwards or [],
            "nc": nc_destination,
        },
    )
    return {
        "session_id": session.session_id,
        "host": host,
        "success": True,
        "message": "Tunnel established",
    }


# ===================================================================
# 3. Persistent Interactive Sessions (5 tools)
# ===================================================================


@mcp.tool()
def session_open(
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
    proxy_command: str | None = None,
    serial_config: str | None = None,
) -> dict:
    """Open a persistent interactive plink session (SSH/Telnet/serial/raw). Returns session_id.

    For serial, host is the port (e.g. COM3) and serial_config is
    "baud,data_bits,parity,stop_bits,flow" (omitted fields use config defaults).
    """
    if protocol == "serial":
        parts = [p.strip() for p in serial_config.split(",")] if serial_config else []
        args = build_serial_args(
            host,
            baud=int(parts[0]) if len(parts) > 0 else config.serial.baud,
            data_bits=int(parts[1]) if len(parts) > 1 else config.serial.data_bits,
            parity=parts[2] if len(parts) > 2 else config.serial.parity,
            stop_bits=int(parts[3]) if len(parts) > 3 else config.serial.stop_bits,
            flow_control=parts[4] if len(parts) > 4 else config.serial.flow_control,
        )
    else:
        args = build_connection_args(
            host=host, port=port, username=username, protocol=protocol,
            key_file=key_file, session_name=session_name, host_keys=host_keys,
            use_pageant=use_pageant, verbose=verbose, compress=compress,
            x11_forward=x11_forward, agent_forward=agent_forward,
            proxy_command=proxy_command,
        )

    proc = executor.spawn("plink", args)
    session = sessions.create(proc, host=host, protocol=protocol)
    return {
        "session_id": session.session_id,
        "host": host,
        "protocol": protocol,
        "success": True,
    }


@mcp.tool()
def session_send(
    session_id: str,
    command: str,
    wait_seconds: float = 1.0,
) -> dict:
    """Send command to a persistent session and return new output after waiting."""
    session = sessions.get(session_id)
    if not session.alive:
        return {"success": False, "error": "Session process has exited"}

    # Clear buffer to capture only new output
    session.read(clear=True)
    session.send(command + "\n")
    time.sleep(wait_seconds)
    output = session.read()
    return {
        "success": True,
        "output": "".join(output),
        "lines": len(output),
        "alive": session.alive,
    }


@mcp.tool()
def session_read(
    session_id: str,
    last_n: int | None = None,
    clear: bool = False,
) -> dict:
    """Read output buffer from a persistent session."""
    session = sessions.get(session_id)
    lines = session.read(last_n=last_n, clear=clear)
    return {
        "output": "".join(lines),
        "lines": len(lines),
        "alive": session.alive,
    }


@mcp.tool()
def session_list() -> dict:
    """List all active persistent sessions."""
    return {"sessions": sessions.list_sessions()}


@mcp.tool()
def session_close(session_id: str) -> dict:
    """Close a persistent session and clean up."""
    closed = sessions.close(session_id)
    return {"closed": closed, "session_id": session_id}


# ===================================================================
# 4. File Transfer (5 tools)
# ===================================================================


def _transfer_args(
    port: int | None,
    key_file: str | None,
    session_name: str | None,
    host_keys: list[str] | None,
    use_pageant: bool,
) -> list[str]:
    """Connection args shared by pscp and psftp."""
    args: list[str] = []
    if key_file:
        args.extend(["-i", key_file])
    if session_name:
        args.extend(["-load", session_name])
    if host_keys:
        for hk in host_keys:
            args.extend(["-hostkey", hk])
    args.append("-agent" if use_pageant else "-noagent")
    if port is not None:
        args.extend(["-P", str(port)])
    return args


@mcp.tool()
def pscp_upload(
    local_path: str,
    remote_path: str,
    host: str,
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    recursive: bool = False,
    preserve: bool = False,
    force_protocol: str | None = None,
    timeout: int = 120,
) -> dict:
    """Upload file(s) to remote host via pscp."""
    args: list[str] = ["-batch"]
    if recursive:
        args.append("-r")
    if preserve:
        args.append("-p")
    if force_protocol == "sftp":
        args.append("-sftp")
    elif force_protocol == "scp":
        args.append("-scp")
    args.extend(_transfer_args(port, key_file, session_name, host_keys, use_pageant))

    # Source and destination
    args.append(local_path)
    remote = f"{username}@{host}:{remote_path}" if username else f"{host}:{remote_path}"
    args.append(remote)

    return executor.run("pscp", args, timeout=timeout)


@mcp.tool()
def pscp_download(
    remote_path: str,
    local_path: str,
    host: str,
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    recursive: bool = False,
    preserve: bool = False,
    force_protocol: str | None = None,
    timeout: int = 120,
) -> dict:
    """Download file(s) from remote host via pscp."""
    args: list[str] = ["-batch"]
    if recursive:
        args.append("-r")
    if preserve:
        args.append("-p")
    if force_protocol == "sftp":
        args.append("-sftp")
    elif force_protocol == "scp":
        args.append("-scp")
    args.extend(_transfer_args(port, key_file, session_name, host_keys, use_pageant))

    remote = f"{username}@{host}:{remote_path}" if username else f"{host}:{remote_path}"
    args.append(remote)
    args.append(local_path)

    return executor.run("pscp", args, timeout=timeout)


@mcp.tool()
def pscp_list(
    remote_path: str,
    host: str,
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    timeout: int = 30,
) -> dict:
    """List remote directory via pscp -ls."""
    args: list[str] = ["-batch", "-ls"]
    args.extend(_transfer_args(port, key_file, session_name, host_keys, use_pageant))

    remote = f"{username}@{host}:{remote_path}" if username else f"{host}:{remote_path}"
    args.append(remote)

    return executor.run("pscp", args, timeout=timeout)


@mcp.tool()
def psftp_batch(
    host: str,
    commands: list[str],
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    continue_on_error: bool = False,
    timeout: int = 120,
) -> dict:
    """Execute SFTP commands as a batch via psftp -b.

    Commands are passed via stdin (psftp reads from pipe when no -b file).
    """
    args: list[str] = ["-batch"]
    if continue_on_error:
        args.append("-be")
    args.extend(_transfer_args(port, key_file, session_name, host_keys, use_pageant))

    target = f"{username}@{host}" if username else host
    args.append(target)

    batch_input = "\n".join(commands) + "\nquit\n"
    return executor.run("psftp", args, input_text=batch_input, timeout=timeout)


@mcp.tool()
def psftp_interactive(
    host: str,
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
) -> dict:
    """Open a persistent PSFTP session for multi-step SFTP workflows. Returns session_id."""
    args = _transfer_args(port, key_file, session_name, host_keys, use_pageant)

    target = f"{username}@{host}" if username else host
    args.append(target)

    proc = executor.spawn("psftp", args)
    session = sessions.create(proc, host=host, protocol="sftp")
    return {
        "session_id": session.session_id,
        "host": host,
        "protocol": "sftp",
        "success": True,
    }


# ===================================================================
# 5. Key Management (6 tools)
# ===================================================================


@mcp.tool()
def keygen_create(
    output_path: str,
    key_type: str = "ed25519",
    bits: int | None = None,
    comment: str | None = None,
    passphrase: str | None = None,
) -> dict:
    """Generate a new SSH key pair (OpenSSH + PPK format).

    key_type: rsa, dsa, ecdsa, ed25519
    bits: Key size (e.g. 2048, 4096 for RSA; 256, 384, 521 for ECDSA)

    Creates: output_path (OpenSSH private), output_path.pub, output_path.ppk (PuTTY).
    The .ppk is only generated for unencrypted keys (no passphrase).
    """
    args = ["-t", key_type, "-f", output_path, "-N", passphrase or ""]
    if bits:
        args.extend(["-b", str(bits)])
    if comment:
        args.extend(["-C", comment])
    result = executor.run("ssh-keygen", args, timeout=30)

    # Auto-generate PPK for PuTTY tools (only if no passphrase)
    if result["success"] and not passphrase:
        try:
            ppk_path = openssh_to_ppk(output_path)
            result["ppk_path"] = ppk_path
        except Exception as e:
            result["ppk_error"] = str(e)

    return result


@mcp.tool()
def keygen_fingerprint(
    key_path: str,
    algorithm: str = "sha256",
) -> dict:
    """Get fingerprint of an existing key. algorithm: sha256 or md5."""
    args = ["-l", "-f", key_path, "-E", algorithm]
    return executor.run("ssh-keygen", args, timeout=10)


@mcp.tool()
def keygen_convert(
    input_path: str,
    output_path: str,
    output_format: str = "RFC4716",
    passphrase: str | None = None,
) -> dict:
    """Convert/export a key to a different format.

    output_format: RFC4716, PKCS8, PEM, PPK
    RFC4716/PKCS8/PEM export the public key (ssh-keygen -e).
    PPK converts the (unencrypted) private key natively (no GUI needed).
    """
    if output_format.upper() == "PPK":
        try:
            ppk_path = openssh_to_ppk(input_path, output_path)
            return {"success": True, "output_path": ppk_path, "format": "PPK v3"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    args = ["-e", "-f", input_path, "-m", output_format]
    if passphrase:
        args.extend(["-P", passphrase])
    result = executor.run("ssh-keygen", args, timeout=10)
    if result["success"] and output_path:
        try:
            with open(output_path, "w") as f:
                f.write(result["stdout"])
            result["output_path"] = output_path
        except OSError as e:
            result["write_error"] = str(e)
    return result


@mcp.tool()
def keygen_public_key(key_path: str) -> dict:
    """Extract public key in OpenSSH authorized_keys format."""
    args = ["-y", "-f", key_path]
    return executor.run("ssh-keygen", args, timeout=10)


@mcp.tool()
def pageant_add(
    key_paths: list[str],
    encrypted: bool = False,
) -> dict:
    """Load key(s) into Pageant (launches GUI if not running).

    encrypted: If True, uses --encrypted for deferred decryption.
    Accepts .ppk files. Pageant will prompt for passphrases via GUI.
    """
    args: list[str] = []
    if encrypted:
        args.append("--encrypted")
    args.extend(key_paths)
    return executor.launch_gui("pageant", args)


@mcp.tool()
def pageant_list() -> dict:
    """List keys currently loaded in Pageant.

    Uses ssh-add -L via Pageant's OpenSSH agent compatibility.
    Requires Pageant to be running with --openssh-config or SSH_AUTH_SOCK set.
    Falls back to opening the Pageant key list GUI window.
    """
    # Try ssh-add first (works if Pageant is bridged to OpenSSH agent)
    result = executor.run("ssh-add", ["-L"], timeout=5)
    if result["success"] and result["stdout"].strip():
        keys = [
            line.strip()
            for line in result["stdout"].strip().splitlines()
            if line.strip()
        ]
        return {"keys": keys, "count": len(keys), "source": "ssh-add"}

    # Fallback: open the Pageant key list GUI
    gui_result = executor.launch_gui("pageant", ["--keylist"])
    gui_result["note"] = (
        "Could not list keys programmatically. "
        "Opened Pageant key list GUI instead. "
        "For CLI access, start Pageant with --openssh-config <path>."
    )
    return gui_result


# ===================================================================
# 6. Saved Sessions — Registry (4 tools)
# ===================================================================


@mcp.tool()
def saved_sessions_list() -> dict:
    """List all PuTTY saved sessions from the Windows registry."""
    if not config.enable_registry:
        return {"error": "Registry operations disabled in config", "sessions": []}
    try:
        names = registry.list_sessions()
        return {"sessions": names, "count": len(names)}
    except RuntimeError as e:
        return {"error": str(e), "sessions": []}


@mcp.tool()
def saved_session_get(session_name: str) -> dict:
    """Get full config of a saved PuTTY session."""
    if not config.enable_registry:
        return {"error": "Registry operations disabled in config"}
    try:
        return registry.get_session(session_name)
    except (KeyError, RuntimeError) as e:
        return {"error": str(e)}


@mcp.tool()
def saved_session_create(
    session_name: str,
    host: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    username: str | None = None,
    key_file: str | None = None,
    x11_forward: bool | None = None,
    agent_forward: bool | None = None,
    compression: bool | None = None,
    serial_line: str | None = None,
    serial_speed: int | None = None,
    proxy_command: str | None = None,
    font_name: str | None = None,
    font_size: int | None = None,
    window_rows: int | None = None,
    window_cols: int | None = None,
    scrollback_lines: int | None = None,
) -> dict:
    """Create or update a saved PuTTY session in the registry."""
    if not config.enable_registry:
        return {"error": "Registry operations disabled in config"}

    # Build params dict from non-None values
    params: dict = {}
    local_vars = {
        "host": host, "port": port, "protocol": protocol, "username": username,
        "key_file": key_file, "x11_forward": x11_forward, "agent_forward": agent_forward,
        "compression": compression, "serial_line": serial_line, "serial_speed": serial_speed,
        "proxy_command": proxy_command, "font_name": font_name, "font_size": font_size,
        "window_rows": window_rows, "window_cols": window_cols,
        "scrollback_lines": scrollback_lines,
    }
    for k, v in local_vars.items():
        if v is not None:
            params[k] = v

    try:
        return registry.create_session(session_name, **params)
    except RuntimeError as e:
        return {"error": str(e)}


@mcp.tool()
def saved_session_delete(session_name: str) -> dict:
    """Delete a saved PuTTY session from the registry."""
    if not config.enable_registry:
        return {"error": "Registry operations disabled in config"}
    try:
        deleted = registry.delete_session(session_name)
        return {"deleted": deleted, "session_name": session_name}
    except RuntimeError as e:
        return {"error": str(e)}


# ===================================================================
# 7. Utility (2 tools)
# ===================================================================


@mcp.tool()
def test_connection(
    host: str,
    port: int | None = None,
    username: str | None = None,
    protocol: str = "ssh",
    key_file: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    timeout: int = 15,
) -> dict:
    """Test SSH/Telnet connectivity. Returns host key fingerprint on success."""
    if protocol == "ssh":
        # Use plink to run a trivial command
        args = build_connection_args(
            host=host, port=port, username=username, protocol="ssh",
            key_file=key_file, host_keys=host_keys, use_pageant=use_pageant,
            verbose=True, batch_mode=True,
        )
        args.append("echo putty-mcp-test-ok")
        result = executor.run("plink", args, timeout=timeout)
        result["test"] = "putty-mcp-test-ok" in result.get("stdout", "")
        return result
    elif protocol == "telnet":
        args = build_connection_args(
            host=host, port=port, protocol="telnet", batch_mode=True,
        )
        return executor.run("plink", args, input_text="\n", timeout=timeout)
    else:
        return {"error": f"test_connection does not support protocol '{protocol}'"}


@mcp.tool()
def get_host_key(
    host: str,
    port: int = 22,
    timeout: int = 15,
) -> dict:
    """Get SSH host key fingerprint from a server.

    Useful for obtaining the -hostkey value for batch/non-interactive use.
    Attempts connection with a dummy user; extracts key from verbose output.
    """
    args = ["-ssh", "-batch", "-v", "-P", str(port), "-noagent", host]
    result = executor.run("plink", args, timeout=timeout)
    # Even if connection fails (expected), verbose output contains host key
    return {
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "note": "Look for 'Host key fingerprint is:' or 'ssh-ed25519' in output",
    }


# ===================================================================
# 8. Multi-Hop / ProxyJump (2 tools)
# ===================================================================


@mcp.tool()
def proxy_session(
    target_host: str,
    proxy_cmd: str,
    target_port: int = 22,
    username: str | None = None,
    key_file: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    compress: bool = False,
) -> dict:
    """Open interactive session through a proxy command (-proxycmd). Returns session_id."""
    args = build_connection_args(
        host=target_host, port=target_port, username=username, protocol="ssh",
        key_file=key_file, host_keys=host_keys, use_pageant=use_pageant,
        compress=compress, proxy_command=proxy_cmd,
    )
    proc = executor.spawn("plink", args)
    session = sessions.create(proc, host=target_host, protocol="ssh-proxy")
    return {
        "session_id": session.session_id,
        "host": target_host,
        "proxy_cmd": proxy_cmd,
        "success": True,
    }


@mcp.tool()
def chain_exec(
    target_host: str,
    command: str,
    jump_hosts: list[str],
    target_username: str | None = None,
    target_port: int = 22,
    key_file: str | None = None,
    timeout: int = 60,
) -> dict:
    """Execute command on target through one or more jump hosts.

    jump_hosts: list of "user@host:port" strings in hop order.
    Builds nested plink -proxycmd chain automatically.
    """
    try:
        proxy_cmd = build_proxy_chain(jump_hosts)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    args = build_connection_args(
        host=target_host, port=target_port, username=target_username,
        protocol="ssh", key_file=key_file, proxy_command=proxy_cmd,
        batch_mode=True,
    )
    args.append(command)
    result = executor.run("plink", args, timeout=timeout)
    result["jump_hosts"] = jump_hosts
    result["proxy_cmd"] = proxy_cmd
    return result


# ===================================================================
# Entry point
# ===================================================================

def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
