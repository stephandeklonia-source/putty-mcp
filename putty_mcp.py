"""PuTTY MCP Server — full PuTTY toolchain exposed as MCP tools.

Covers: putty.exe, plink, pscp, psftp, pageant and native key management.
31 tools: GUI launch, command execution, shell runs, persistent sessions, file
transfer, keys, saved sessions (registry) and multi-hop SSH.

The local monitor dashboard is the operator's interface: it shows every
call live, asks for approval when the safety policy says so, takes
passphrases and host key decisions, holds all settings and has a kill switch.
"""

from __future__ import annotations

import atexit
import functools
import inspect
import logging
import os
import re
import time
from datetime import date
from typing import Any, Callable, TypeVar

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
except ModuleNotFoundError:  # mcp 1.x (FastMCP was renamed to MCPServer in 2.0)
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[no-redef]

from putty_lib import hostkeys, keys, policy, registry
from putty_lib.approvals import HOSTKEY, SECRET, TOOL, ApprovalQueue
from putty_lib.audit import AuditLog
from putty_lib.config import PuTTYConfig
from putty_lib.executor import PuTTYExecutor
from putty_lib.monitor import Monitor, OperatorBlocked, kill_process_tree
from putty_lib.monitor_web import MonitorServer
from putty_lib.session_manager import PAGER, InteractiveSession, SessionManager
from putty_lib.settings import Settings, SettingsStore, data_dir
from putty_lib.utils import (
    build_connection_args,
    build_proxy_chain,
    build_serial_args,
    clean_pager,
    limit_text,
    strip_ansi,
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

DATA_DIR = data_dir()
settings_store = SettingsStore(DATA_DIR / "settings.json", seed=config.seed_settings())
config.set_putty_dir(settings_store.current.putty_dir)


def current() -> Settings:
    return settings_store.current


audit = AuditLog(
    DATA_DIR / "audit",
    enabled=lambda: settings_store.current.audit_enabled,
    retention_days=lambda: settings_store.current.audit_retention_days,
)
monitor = Monitor()
monitor.event_sinks.append(audit.write)
approvals = ApprovalQueue(emit=monitor.emit)
monitor.on_kill_all.append(lambda: approvals.deny_all("kill switch engaged"))
executor = PuTTYExecutor(config, monitor)
_initial = current()
sessions = SessionManager(
    max_concurrent=_initial.max_concurrent,
    timeout_seconds=_initial.idle_timeout_seconds,
    buffer_lines=_initial.buffer_lines,
)
monitor.attach_sessions(sessions)


def _apply_settings(s: Settings) -> None:
    sessions.max_concurrent = s.max_concurrent
    sessions.timeout_seconds = s.idle_timeout_seconds
    sessions.buffer_lines = s.buffer_lines
    if str(config.executable_path or "") != s.putty_dir:
        config.set_putty_dir(s.putty_dir)
    monitor.note("Settings changed")


settings_store.on_change(_apply_settings)

monitor_server: MonitorServer | None = None
if config.monitor.enabled:
    try:
        monitor_server = MonitorServer(
            monitor, approvals, settings_store, audit, config,
            host=config.monitor.host, port=config.monitor.port,
            token_file=DATA_DIR / "dashboard-token",
        )
        monitor_server.start()
    except OSError as e:
        log.warning("Monitor dashboard disabled: %s", e)


def _on_approval_request(_approval: Any) -> None:
    # Bring the dashboard up if nobody is looking at it
    if monitor_server is not None and current().open_browser != "never" and not monitor_server.recently_viewed():
        monitor_server.open_browser(force=True)
    elif monitor_server is None:
        log.warning("Approval needed but the monitor dashboard is disabled; the request will time out")


approvals.on_request = _on_approval_request

mcp = MCPServer("putty-mcp")


@atexit.register
def _shutdown() -> None:
    approvals.deny_all("server shutting down")
    count = sessions.close_all()
    if count:
        log.info("Shutdown: closed %d sessions", count)
    if monitor_server is not None:
        monitor_server.stop()


# ---------------------------------------------------------------------------
# Tool wrapper: monitor, policy, approvals, output limits
# ---------------------------------------------------------------------------

_F = TypeVar("_F", bound=Callable[..., Any])
_OUTPUT_KEYS = ("stdout", "stderr", "output")


def _for_ai(result: Any) -> Any:
    """Strip terminal escapes and cap output size before the AI sees it."""
    if not isinstance(result, dict):
        return result
    s = current()
    out = dict(result)
    for key in _OUTPUT_KEYS:
        if isinstance(out.get(key), str):
            text = strip_ansi(out[key]) if s.strip_ansi else out[key]
            out[key] = limit_text(text, s.max_output_chars)
    return out


def _session_info(kwargs: dict[str, Any]) -> dict[str, Any] | None:
    sid = kwargs.get("session_id")
    if not sid:
        return None
    try:
        session = sessions.get(sid)
    except KeyError:
        return None
    return {"host": session.host, "protocol": session.protocol}


def tool() -> Callable[[_F], _F]:
    """Register an MCP tool behind the monitor, the policy and the kill switch.

    Every call shows up in the dashboard. Policy may deny it or make it wait
    for the operator's approval. Exceptions become ToolErrors so the client
    sees the actual message (mcp 2.x hides unexpected exceptions).
    """

    def decorator(fn: _F) -> _F:
        name = fn.__name__
        defaults = {
            pname: p.default
            for pname, p in inspect.signature(fn).parameters.items()
            if p.default is not inspect.Parameter.empty
        }

        @functools.wraps(fn)
        def wrapper(**kwargs: Any) -> Any:
            s = current()
            if monitor_server is not None and s.open_browser == "first_call":
                monitor_server.open_browser()
            # Show only what the caller actually chose
            shown = {k: v for k, v in kwargs.items() if k not in defaults or v != defaults[k]}
            try:
                call_id = monitor.call_started(name, shown)
            except OperatorBlocked as e:
                raise ToolError(str(e)) from None

            def fail(message: str) -> ToolError:
                monitor.call_finished(call_id, error=message)
                return ToolError(message)

            decision = policy.evaluate(s, name, kwargs, _session_info(kwargs))
            if decision.action == policy.DENY:
                raise fail("Denied by the PuTTY MCP safety policy: " + "; ".join(decision.reasons)
                           + ". Do not try to work around this; ask the user.")
            if decision.action == policy.ASK:
                monitor.call_waiting(call_id, decision.reasons)
                approval = approvals.request(
                    TOOL, f"{name}",
                    {"tool": name, "args": shown, "reasons": decision.reasons},
                    timeout=s.approval_timeout_seconds,
                    options=decision.options,
                )
                monitor.call_resumed(call_id)
                if not approval.approved:
                    raise fail(f"Not approved by the operator ({approval.reason}). "
                               "Do not retry this call; ask the user how to proceed.")
                if approval.remember:
                    settings_store.mutate(lambda st: policy.apply_remember(st, approval.remember))

            try:
                result = _for_ai(fn(**kwargs))
            except ToolError as e:
                raise fail(str(e)) from None
            except Exception as e:
                monitor.call_finished(call_id, error=f"{type(e).__name__}: {e}")
                raise ToolError(str(e)) from e
            monitor.call_finished(call_id, result=result)
            return result

        mcp.tool()(wrapper)
        return fn

    return decorator


def _ask_secret(title: str, purpose: str, confirm: bool) -> str:
    """Let the operator type a passphrase in the dashboard (the AI never sees it)."""
    approval = approvals.request(
        SECRET, title, {"purpose": purpose, "confirm": confirm},
        timeout=max(current().approval_timeout_seconds, 120),
    )
    if not approval.approved or not approval.secret:
        raise ToolError(f"No passphrase was entered in the dashboard ({approval.reason}).")
    return approval.secret


# ---------------------------------------------------------------------------
# Host keys
# ---------------------------------------------------------------------------


def _trusted(host: str, port: int | None) -> list[str]:
    return hostkeys.trusted_args(current().trusted_host_keys, host, port)


def _hostkey_problem(output: str, host: str, port: int | None) -> tuple[bool, str]:
    """Handle a host key failure. Returns (retry, message for the AI)."""
    problem = hostkeys.detect(output)
    if problem is None:
        return False, ""
    where = hostkeys.key_id(host, port)
    if problem.kind == hostkeys.MISMATCH:
        monitor.alert(f"HOST KEY MISMATCH for {where}: the server's key differs from the trusted key. "
                      "This can mean a man-in-the-middle attack. The connection was refused.")
        return False, (f"SECURITY: the host key of {where} does not match the trusted key. "
                       "The connection was refused. Do not retry; tell the user.")
    if current().unknown_host_key_action == "deny" or not problem.fingerprint:
        return False, (f"The host key of {where} is unknown and was not accepted. The user can trust it "
                       "in the PuTTY MCP dashboard (Settings → Trusted host keys).")
    approval = approvals.request(
        HOSTKEY, f"Unknown host key for {where}",
        {"host": host, "port": port or 22, "key": problem.key_line, "fingerprint": problem.fingerprint},
        timeout=current().approval_timeout_seconds,
    )
    if not approval.approved:
        return False, f"The operator did not trust the host key of {where} ({approval.reason})."

    def add(st: Settings) -> None:
        fps = st.trusted_host_keys.setdefault(where, [])
        if problem.fingerprint not in fps:
            fps.append(problem.fingerprint)

    settings_store.mutate(add)
    return True, ""


def _run_remote(tool_name: str, args: list[str], host: str, port: int | None, **kw: Any) -> dict:
    """Run a connecting PuTTY tool, handling unknown host keys via the dashboard."""
    for _ in range(2):
        result = executor.run(tool_name, _trusted(host, port) + args, **kw)
        if result.get("killed_by_operator"):
            return result
        retry, message = _hostkey_problem(result["stderr"] + result["stdout"], host, port)
        if not retry:
            if message:
                result["success"] = False
                result["hostkey"] = message
                result["stderr"] = result["stderr"].rstrip() + "\n" + message
            return result
    return result


def _open_session(
    tool_name: str, args: list[str], host: str, protocol: str, port: int | None = None,
    check_hostkey: bool = True, **metadata: Any,
) -> InteractiveSession:
    """Spawn a long-running process and register it as an interactive session.

    For SSH, waits briefly to see whether plink aborts on an unknown host key;
    if the operator trusts the key, the session is started again.
    """
    for _ in range(2):
        proc, proc_id = executor.spawn(tool_name, (_trusted(host, port) if check_hostkey else []) + args)
        try:
            session = sessions.create(proc, host=host, protocol=protocol, **metadata)
        except Exception:
            # e.g. max sessions reached: don't leave the process running
            kill_process_tree(proc)
            monitor.untrack(proc_id)
            raise
        monitor.link_session(proc_id, session.session_id)
        if not check_hostkey:
            return session

        deadline = time.time() + 3
        while time.time() < deadline and session.alive and not hostkeys.detect(session.peek(4000)):
            time.sleep(0.1)
        output = session.peek(4000)
        if not hostkeys.detect(output):
            return session
        sessions.close(session.session_id)
        retry, message = _hostkey_problem(output, host, port)
        if not retry:
            raise ToolError(message)
    raise ToolError(f"Could not open a session to {host}")


# ===================================================================
# 1. PuTTY GUI Launch (3 tools)
# ===================================================================


@tool()
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
    """Launch a PuTTY window for the user with full connection parameters."""
    args = build_connection_args(
        host=host, port=port, username=username, protocol=protocol,
        key_file=key_file, session_name=session_name,
        host_keys=(host_keys or []) + _trusted(host, port)[1::2],
        use_pageant=use_pageant, verbose=verbose, compress=compress,
        x11_forward=x11_forward, agent_forward=agent_forward,
        local_forwards=local_forwards, remote_forwards=remote_forwards,
        dynamic_forwards=dynamic_forwards, proxy_command=proxy_command,
        log_file=log_file, log_type=log_type,
    )
    return executor.launch_gui("putty", args)


@tool()
def putty_open_session(session_name: str) -> dict:
    """Launch a PuTTY window from a saved session name."""
    return executor.launch_gui("putty", ["-load", session_name])


@tool()
def putty_serial(
    serial_port: str,
    baud: int | None = None,
    data_bits: int | None = None,
    parity: str | None = None,
    stop_bits: int | None = None,
    flow_control: str | None = None,
) -> dict:
    """Launch a PuTTY window on a serial port (omitted settings use the dashboard defaults)."""
    s = current()
    args = build_serial_args(
        serial_port,
        baud or s.serial_baud, data_bits or s.serial_data_bits, parity or s.serial_parity,
        stop_bits or s.serial_stop_bits, flow_control or s.serial_flow_control,
    )
    return executor.launch_gui("putty", args)


# ===================================================================
# 2. Plink Command Execution (3 tools)
# ===================================================================


@tool()
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
    """Run a single command on a remote host via plink. Returns stdout/stderr/rc.

    Network devices such as Cisco IOS accept only one command per call;
    for several commands or configuration blocks use shell_run.
    Unknown host keys are shown to the user in the dashboard to trust or reject.
    """
    args = build_connection_args(
        host=host, port=port, username=username, protocol=protocol,
        key_file=key_file, session_name=session_name, host_keys=host_keys,
        use_pageant=use_pageant, verbose=verbose, compress=compress,
        x11_forward=x11_forward, agent_forward=agent_forward,
        proxy_command=proxy_command, allocate_pty=allocate_pty,
        batch_mode=True,
    )
    args.append(command)
    result = _run_remote("plink", args, host, port, timeout=timeout)
    if "invalid autocommand" in (result.get("stdout", "") + result.get("stderr", "")).lower():
        result["hint"] = ("This device (e.g. Cisco IOS) runs only one command per SSH exec channel. "
                          "Use shell_run with a list of commands, one per line.")
    return result


@tool()
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
    return _run_remote("plink", args, host, port, timeout=timeout)


@tool()
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

    session = _open_session(
        "plink", args, host=host, protocol="tunnel", port=port,
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
        "message": "Tunnel started" if session.alive else "Tunnel process exited",
        "alive": session.alive,
        "output": session.peek(4000),
    }


# ===================================================================
# 3. Persistent Interactive Sessions (5 tools)
# ===================================================================


@tool()
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

    Runs in batch mode: authentication must work without prompts (key file or
    Pageant). For serial, host is the port (e.g. COM3) and serial_config is
    "baud,data_bits,parity,stop_bits,flow" (omitted fields use the dashboard defaults).
    """
    if protocol == "serial":
        s = current()
        parts = [p.strip() for p in serial_config.split(",")] if serial_config else []
        args = build_serial_args(
            host,
            baud=int(parts[0]) if len(parts) > 0 and parts[0] else s.serial_baud,
            data_bits=int(parts[1]) if len(parts) > 1 and parts[1] else s.serial_data_bits,
            parity=parts[2] if len(parts) > 2 and parts[2] else s.serial_parity,
            stop_bits=int(parts[3]) if len(parts) > 3 and parts[3] else s.serial_stop_bits,
            flow_control=parts[4] if len(parts) > 4 and parts[4] else s.serial_flow_control,
        )
    else:
        args = build_connection_args(
            host=host, port=port, username=username, protocol=protocol,
            key_file=key_file, session_name=session_name, host_keys=host_keys,
            use_pageant=use_pageant, verbose=verbose, compress=compress,
            x11_forward=x11_forward, agent_forward=agent_forward,
            proxy_command=proxy_command, batch_mode=True,
        )

    session = _open_session("plink", args, host=host, protocol=protocol, port=port,
                            check_hostkey=protocol == "ssh")
    return {
        "session_id": session.session_id,
        "host": host,
        "protocol": protocol,
        "success": session.alive,
        "output": session.peek(4000),
    }


@tool()
def session_send(
    session_id: str,
    command: str,
    wait_seconds: float = 15.0,
    quiet_seconds: float = 2.0,
    expect: str | None = None,
    press_enter: bool = True,
) -> dict:
    """Send a command to a persistent session and return the output it produced.

    Returns when the shell prompt comes back, when `expect` (a regex) matches,
    when there is no new output for quiet_seconds, or after wait_seconds at
    most. "finished" in the result says which.
    """
    session = sessions.get(session_id)
    if not session.alive:
        return {"success": False, "alive": False, "exit_code": session.exit_code,
                "error": "The session has ended (the connection closed). Its last output is included; "
                         "open a new session or use shell_run.",
                "output": session.peek(4000)}
    pattern = re.compile(expect, re.M) if expect else None

    # Capture only output produced after this command; the buffer itself
    # is kept so the monitor dashboard still shows the full history.
    mark = session.mark()
    session.send(command + ("\n" if press_enter else ""))
    output, reason = session.wait_for_output(mark, wait_seconds, quiet_seconds, pattern, strip_ansi)
    return {
        "success": True,
        "output": output,
        "finished": reason,
        "alive": session.alive,
    }


@tool()
def shell_run(
    host: str,
    commands: list[str],
    port: int | None = None,
    username: str | None = None,
    protocol: str = "ssh",
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
    proxy_command: str | None = None,
    command_timeout: float = 30.0,
    quiet_seconds: float = 2.0,
    error_pattern: str | None = r"^% |\bInvalid input\b|\bIncomplete command\b|\bcommand not found\b",
    stop_on_error: bool = True,
) -> dict:
    """Run several commands in ONE interactive shell, then close it. No session id needed.

    Use this for network devices (Cisco IOS/NX-OS, Juniper, ...) and any
    multi-step or configuration work, e.g. ["configure terminal",
    "interface Gi0/1", "description uplink", "end", "write memory"].
    Each line is sent after the previous one's prompt returns; "--More--"
    pages are skipped automatically. A confirmation question (e.g.
    "Destination filename [startup-config]?") is answered by the next line,
    which may be "" for Enter. Output lines matching error_pattern (Cisco
    "% Invalid input", ...) mark the command as failed; with stop_on_error
    the remaining commands are not sent.
    """
    if protocol == "serial":
        raise ToolError("shell_run does not support serial; use session_open")
    args = build_connection_args(
        host=host, port=port, username=username, protocol=protocol,
        key_file=key_file, session_name=session_name, host_keys=host_keys,
        use_pageant=use_pageant, proxy_command=proxy_command, batch_mode=True,
    )
    error_re = re.compile(error_pattern, re.M | re.I) if error_pattern else None
    session = _open_session("plink", args, host=host, protocol="shell", port=port,
                            check_hostkey=protocol == "ssh")

    def wait(mark: int) -> tuple[str, str]:
        # Keep pressing space while the device shows a --More-- pager
        while True:
            out, reason = session.wait_for_output(mark, command_timeout, quiet_seconds,
                                                  clean=strip_ansi, pager=PAGER)
            if reason != "pager":
                return out, reason
            session.send(" ")

    results: list[dict[str, Any]] = []
    stopped = None
    try:
        banner, reason = wait(0)
        for command in commands:
            if not session.alive:
                stopped = "the connection closed"
                break
            mark = session.mark()
            session.send(command + "\n")
            out, reason = wait(mark)
            text = clean_pager(strip_ansi(out))
            failed = bool(error_re and error_re.search(text))
            results.append({"command": command, "output": text, "finished": reason, "error": failed})
            if failed and stop_on_error:
                stopped = f"error after: {command}"
                break
        transcript = clean_pager(strip_ansi(session.read()))
        alive = session.alive
    finally:
        sessions.close(session.session_id)

    per_command = max(2000, current().max_output_chars // max(1, len(results)))
    for r in results:
        r["output"] = limit_text(r["output"], per_command)
    return {
        "success": stopped is None and len(results) == len(commands) and not any(r["error"] for r in results),
        "completed": len(results),
        "total": len(commands),
        "stopped": stopped,
        "connected": bool(banner) or alive,
        "results": results,
        "output": transcript,
    }


@tool()
def session_read(
    session_id: str,
    last_n: int | None = None,
    clear: bool = False,
) -> dict:
    """Read the output buffer of a persistent session (optionally the last N lines)."""
    session = sessions.get(session_id)
    result = {"output": session.read(last_n=last_n, clear=clear), "alive": session.alive}
    if not session.alive:
        result["exit_code"] = session.exit_code
    return result


@tool()
def session_list() -> dict:
    """List all active persistent sessions."""
    return {"sessions": sessions.list_sessions()}


@tool()
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
    args: list[str] = ["-batch"]
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


def _pscp_flags(recursive: bool, preserve: bool, force_protocol: str | None) -> list[str]:
    flags = []
    if recursive:
        flags.append("-r")
    if preserve:
        flags.append("-p")
    if force_protocol in ("sftp", "scp"):
        flags.append(f"-{force_protocol}")
    return flags


def _remote(host: str, username: str | None, path: str) -> str:
    return f"{username}@{host}:{path}" if username else f"{host}:{path}"


@tool()
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
    args = _transfer_args(port, key_file, session_name, host_keys, use_pageant)
    args += _pscp_flags(recursive, preserve, force_protocol)
    args += [local_path, _remote(host, username, remote_path)]
    return _run_remote("pscp", args, host, port, timeout=timeout)


@tool()
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
    args = _transfer_args(port, key_file, session_name, host_keys, use_pageant)
    args += _pscp_flags(recursive, preserve, force_protocol)
    args += [_remote(host, username, remote_path), local_path]
    return _run_remote("pscp", args, host, port, timeout=timeout)


@tool()
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
    args = _transfer_args(port, key_file, session_name, host_keys, use_pageant)
    args += ["-ls", _remote(host, username, remote_path)]
    return _run_remote("pscp", args, host, port, timeout=timeout)


@tool()
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
    """Execute SFTP commands (put, get, ls, mkdir, ...) as a batch via psftp."""
    args = _transfer_args(port, key_file, session_name, host_keys, use_pageant)
    if continue_on_error:
        args.append("-be")
    args.append(f"{username}@{host}" if username else host)

    batch_input = "\n".join(commands) + "\nquit\n"
    return _run_remote("psftp", args, host, port, input_text=batch_input, timeout=timeout)


@tool()
def psftp_interactive(
    host: str,
    port: int | None = None,
    username: str | None = None,
    key_file: str | None = None,
    session_name: str | None = None,
    host_keys: list[str] | None = None,
    use_pageant: bool = True,
) -> dict:
    """Open a persistent PSFTP session for multi-step SFTP workflows (use session_send). Returns session_id."""
    args = _transfer_args(port, key_file, session_name, host_keys, use_pageant)
    args.append(f"{username}@{host}" if username else host)

    session = _open_session("psftp", args, host=host, protocol="sftp", port=port)
    return {
        "session_id": session.session_id,
        "host": host,
        "protocol": "sftp",
        "success": session.alive,
        "output": session.peek(4000),
    }


# ===================================================================
# 5. Key Management (6 tools)
# ===================================================================


@tool()
def keygen_create(
    output_path: str,
    key_type: str = "ed25519",
    bits: int | None = None,
    comment: str | None = None,
    protect_with_passphrase: bool = False,
    overwrite: bool = False,
) -> dict:
    """Generate a new SSH key pair: output_path (OpenSSH private), .pub and .ppk (PuTTY).

    key_type: ed25519 (default), rsa (bits 2048-4096, default 3072) or
    ecdsa (bits 256/384/521).
    protect_with_passphrase: the user types the passphrase in the PuTTY MCP
    dashboard; you never see it. Both private key files are then encrypted.
    """
    paths = {"private_key": output_path, "public_key": output_path + ".pub", "ppk": output_path + ".ppk"}
    if not overwrite:
        for p in paths.values():
            if os.path.exists(p):
                raise FileExistsError(f"{p} already exists (pass overwrite=true to replace it)")
    key = keys.generate(key_type, bits)
    comment = comment or f"{key_type}-key-{date.today().isoformat()}"
    passphrase = None
    if protect_with_passphrase:
        passphrase = _ask_secret(
            f"Passphrase for new {key_type} key", f"Protects {output_path} and {paths['ppk']}", confirm=True,
        )
    keys.write_openssh_private(paths["private_key"], key, passphrase, overwrite=True)
    keys.write_public(paths["public_key"], key, comment, overwrite=True)
    keys.write_ppk(paths["ppk"], key, comment, passphrase, overwrite=True)
    blob = keys.public_blob_from_key(key)
    return {
        "success": True,
        **paths,
        "encrypted": bool(passphrase),
        "fingerprint": keys.fingerprint(blob),
        "public_key_line": keys.openssh_line(blob, comment),
    }


def _load_with_passphrase(path: str) -> keys.PrivateKey:
    if not keys.is_encrypted(path):
        return keys.load_private(path)
    passphrase = _ask_secret(f"Passphrase for {os.path.basename(path)}", f"Unlocks {path}", confirm=False)
    try:
        return keys.load_private(path, passphrase)
    except keys.PassphraseRequired:
        raise ToolError("The passphrase entered in the dashboard is not correct.") from None


def _public_of(path: str) -> tuple[bytes, str]:
    try:
        return keys.public_blob(path)
    except keys.PassphraseRequired:
        return keys.public_blob_from_key(_load_with_passphrase(path)), ""


@tool()
def keygen_fingerprint(
    key_path: str,
    algorithm: str = "sha256",
) -> dict:
    """Fingerprint of a key (.pub, .ppk or private key file). algorithm: sha256 or md5."""
    blob, comment = _public_of(key_path)
    return {"fingerprint": keys.fingerprint(blob, algorithm), "type": keys.key_type_of(blob), "comment": comment}


@tool()
def keygen_convert(
    input_path: str,
    output_path: str,
    output_format: str = "PPK",
    overwrite: bool = False,
) -> dict:
    """Convert a key to another format.

    PPK: converts an OpenSSH/PEM private key to PuTTY format. An encrypted key
    stays encrypted with the same passphrase, which the user types in the
    dashboard. OPENSSH, RFC4716, PKCS8, PEM: export the public key.
    """
    fmt = output_format.upper()
    if fmt == "PPK":
        if os.path.exists(output_path) and not overwrite:
            raise FileExistsError(f"{output_path} already exists (pass overwrite=true to replace it)")
        if keys.is_encrypted(input_path):
            passphrase = _ask_secret(
                f"Passphrase for {os.path.basename(input_path)}",
                f"Unlocks {input_path}; {output_path} gets the same passphrase", confirm=False,
            )
            try:
                key = keys.load_private(input_path, passphrase)
            except keys.PassphraseRequired:
                raise ToolError("The passphrase entered in the dashboard is not correct.") from None
        else:
            key, passphrase = keys.load_private(input_path), None
        pub = input_path + ".pub"
        comment = keys.read_pub_file(pub)[1] if os.path.exists(pub) else ""
        keys.write_ppk(output_path, key, comment, passphrase, overwrite=True)
        return {"success": True, "output_path": output_path, "format": "PPK v3", "encrypted": bool(passphrase)}

    blob, comment = _public_of(input_path)
    text = keys.export_public(blob, comment, fmt)
    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError(f"{output_path} already exists (pass overwrite=true to replace it)")
    with open(output_path, "w", newline="\n") as f:
        f.write(text)
    return {"success": True, "output_path": output_path, "format": fmt, "content": text}


@tool()
def keygen_public_key(key_path: str) -> dict:
    """Public key in OpenSSH authorized_keys format (from .pub, .ppk or private key)."""
    blob, comment = _public_of(key_path)
    return {"public_key": keys.openssh_line(blob, comment), "fingerprint": keys.fingerprint(blob)}


@tool()
def pageant_add(
    key_paths: list[str],
    encrypted: bool = False,
) -> dict:
    """Load .ppk key(s) into Pageant (launches it if not running).

    Pageant asks the user for passphrases itself. encrypted=True uses
    --encrypted (decrypt on first use).
    """
    args: list[str] = []
    if encrypted:
        args.append("--encrypted")
    args.extend(key_paths)
    return executor.launch_gui("pageant", args)


@tool()
def pageant_list() -> dict:
    """List keys currently loaded in Pageant.

    Uses ssh-add -L via Pageant's OpenSSH agent compatibility
    (Pageant started with --openssh-config, or SSH_AUTH_SOCK set).
    Falls back to opening the Pageant key list window.
    """
    try:
        result = executor.run("ssh-add", ["-L"], timeout=5)
    except FileNotFoundError:
        result = {"success": False, "stdout": ""}
    if result["success"] and result["stdout"].strip():
        found = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
        return {"keys": found, "count": len(found), "source": "ssh-add"}

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

_REGISTRY_OFF = "Registry tools are turned off in the dashboard settings"


@tool()
def saved_sessions_list() -> dict:
    """List all PuTTY saved sessions from the Windows registry."""
    if not current().enable_registry:
        return {"error": _REGISTRY_OFF, "sessions": []}
    try:
        names = registry.list_sessions()
        return {"sessions": names, "count": len(names)}
    except RuntimeError as e:
        return {"error": str(e), "sessions": []}


@tool()
def saved_session_get(session_name: str) -> dict:
    """Get full config of a saved PuTTY session."""
    if not current().enable_registry:
        return {"error": _REGISTRY_OFF}
    try:
        return registry.get_session(session_name)
    except (KeyError, RuntimeError) as e:
        return {"error": str(e)}


@tool()
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
    if not current().enable_registry:
        return {"error": _REGISTRY_OFF}

    values = {
        "host": host, "port": port, "protocol": protocol, "username": username,
        "key_file": key_file, "x11_forward": x11_forward, "agent_forward": agent_forward,
        "compression": compression, "serial_line": serial_line, "serial_speed": serial_speed,
        "proxy_command": proxy_command, "font_name": font_name, "font_size": font_size,
        "window_rows": window_rows, "window_cols": window_cols,
        "scrollback_lines": scrollback_lines,
    }
    params = {k: v for k, v in values.items() if v is not None}
    try:
        return registry.create_session(session_name, **params)
    except RuntimeError as e:
        return {"error": str(e)}


@tool()
def saved_session_delete(session_name: str) -> dict:
    """Delete a saved PuTTY session from the registry."""
    if not current().enable_registry:
        return {"error": _REGISTRY_OFF}
    try:
        deleted = registry.delete_session(session_name)
        return {"deleted": deleted, "session_name": session_name}
    except RuntimeError as e:
        return {"error": str(e)}


# ===================================================================
# 7. Utility (2 tools)
# ===================================================================


@tool()
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
    """Test SSH/Telnet connectivity (SSH: logs in and runs a trivial command)."""
    if protocol == "ssh":
        args = build_connection_args(
            host=host, port=port, username=username, protocol="ssh",
            key_file=key_file, host_keys=host_keys, use_pageant=use_pageant,
            batch_mode=True,
        )
        args.append("echo putty-mcp-test-ok")
        result = _run_remote("plink", args, host, port, timeout=timeout)
        result["test"] = "putty-mcp-test-ok" in result.get("stdout", "")
        return result
    if protocol == "telnet":
        args = build_connection_args(host=host, port=port, protocol="telnet", batch_mode=True)
        return executor.run("plink", args, input_text="\n", timeout=timeout)
    return {"error": f"test_connection does not support protocol '{protocol}'"}


@tool()
def get_host_key(
    host: str,
    port: int = 22,
    timeout: int = 15,
) -> dict:
    """Get a server's SSH host key fingerprint without trusting it.

    The user can trust it in the dashboard; trusted keys are used automatically.
    """
    args = ["-ssh", "-batch", "-P", str(port), "-noagent", "-l", "putty-mcp-hostkey-probe", host]
    result = executor.run("plink", args, timeout=timeout)
    problem = hostkeys.detect(result["stderr"] + result["stdout"])
    trusted = current().trusted_host_keys.get(hostkeys.key_id(host, port), [])
    if problem and problem.kind == hostkeys.UNKNOWN:
        return {"host": host, "port": port, "fingerprint": problem.fingerprint, "key": problem.key_line,
                "trusted": False, "cached_by_putty": False}
    return {
        "host": host, "port": port, "trusted_fingerprints": trusted,
        "cached_by_putty": problem is None and not trusted,
        "note": "The key is already trusted or cached by PuTTY" if problem is None
                else "Host key does not match the trusted key",
        "stderr": result["stderr"],
    }


# ===================================================================
# 8. Multi-Hop / ProxyJump (2 tools)
# ===================================================================


@tool()
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
    """Open an interactive session through a custom local proxy command (-proxycmd). Returns session_id."""
    args = build_connection_args(
        host=target_host, port=target_port, username=username, protocol="ssh",
        key_file=key_file, host_keys=host_keys, use_pageant=use_pageant,
        compress=compress, proxy_command=proxy_cmd, batch_mode=True,
    )
    session = _open_session("plink", args, host=target_host, protocol="ssh-proxy", port=target_port)
    return {
        "session_id": session.session_id,
        "host": target_host,
        "proxy_cmd": proxy_cmd,
        "success": session.alive,
        "output": session.peek(4000),
    }


@tool()
def chain_exec(
    target_host: str,
    command: str,
    jump_hosts: list[str],
    target_username: str | None = None,
    target_port: int = 22,
    key_file: str | None = None,
    timeout: int = 60,
) -> dict:
    """Execute a command on target through one or more jump hosts.

    jump_hosts: list of "user@host:port" strings in hop order. Trusted host
    keys are applied to every hop.
    """
    try:
        proxy_cmd = build_proxy_chain(jump_hosts, plink=str(config.get_exe("plink")), hostkey_args=_trusted)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    args = build_connection_args(
        host=target_host, port=target_port, username=target_username,
        protocol="ssh", key_file=key_file, proxy_command=proxy_cmd,
        batch_mode=True,
    )
    args.append(command)
    result = _run_remote("plink", args, target_host, target_port, timeout=timeout)
    result["jump_hosts"] = jump_hosts
    return result


# ===================================================================
# Entry point
# ===================================================================


def main() -> None:
    if monitor_server is not None and current().open_browser == "start":
        monitor_server.open_browser()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
