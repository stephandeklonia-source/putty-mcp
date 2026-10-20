"""Decide whether a tool call may run, needs operator approval, or is denied."""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from putty_lib.settings import Settings
from putty_lib.utils import parse_host_string

ALLOW, ASK, DENY = "allow", "ask", "deny"

# Tools that only read state; approval_mode "all" doesn't ask for these
READ_ONLY_TOOLS = {
    "session_list", "session_read", "saved_sessions_list", "saved_session_get",
    "pageant_list", "keygen_fingerprint", "keygen_public_key", "pscp_list",
    "get_host_key", "test_connection", "net_check", "output_read",
}

# Tools that change local state worth a second look
_RISKY_TOOLS = {
    "saved_session_create": "changes a saved PuTTY session in the registry",
    "saved_session_delete": "deletes a saved PuTTY session from the registry",
}

# Tools whose "host" argument is not a network destination
_NO_HOST_CHECK = {"putty_serial", "saved_session_create", "saved_session_delete", "saved_session_get"}

_LOCAL_PATH_ARGS = ("local_path", "script_path", "output_path", "input_path", "key_path", "key_file", "log_file")

# TrainTools SSH (CCC Prodigy) commands that only read state. In approval
# mode "readonly_auto" these run without asking; everything else asks.
PRODIGY_READONLY = {"ver", "mver", "ls", "pwd", "cd", "cat", "df", "stat", "lstat", "statvfs",
                    "pathconf", "ping", "host", "infs", "pci", "help"}
# Read-only only without arguments (with arguments they set the clock)
PRODIGY_READONLY_NO_ARGS = {"date", "clock", "rtc"}


def prodigy_readonly(command: str) -> bool:
    parts = command.split()
    if not parts:
        return True  # just Enter
    verb = parts[0].lower()
    return verb in PRODIGY_READONLY or (verb in PRODIGY_READONLY_NO_ARGS and len(parts) == 1)


# psftp commands and which arguments are local paths ("all" = every argument)
_PSFTP_LOCAL = {"put": [0], "reput": [0], "mput": "all", "get": [1], "reget": [1], "mget": [], "lcd": [0]}


@dataclass
class Decision:
    action: str = ALLOW
    reasons: list[str] = field(default_factory=list)
    # "Always allow" choices offered with the approval, e.g. {"id": "host:web01", ...}
    options: list[dict[str, str]] = field(default_factory=list)

    def escalate(self, action: str, reason: str) -> None:
        order = {ALLOW: 0, ASK: 1, DENY: 2}
        if order[action] > order[self.action]:
            self.action = action
        if action != ALLOW:
            self.reasons.append(reason)

    def offer(self, option_id: str, label: str) -> None:
        if all(o["id"] != option_id for o in self.options):
            self.options.append({"id": option_id, "label": label})


def _norm(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.expanduser(path)))


def path_allowed(path: str, allowed_dirs: list[str]) -> bool:
    target = _norm(path)
    for d in allowed_dirs:
        base = _norm(d)
        try:
            if os.path.commonpath([target, base]) == base:
                return True
        except ValueError:  # different drives on Windows
            continue
    return False


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower()
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns)


def _psftp_local_paths(command: str) -> list[str]:
    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        parts = command.split()
    if not parts:
        return []
    verb = parts[0].lower()
    if verb not in _PSFTP_LOCAL:
        return []
    args = [p.strip('"') for p in parts[1:] if not p.startswith("-")]
    spec = _PSFTP_LOCAL[verb]
    if spec == "all":
        return args
    paths = [args[i] for i in spec if i < len(args)]
    if verb in ("get", "reget", "mget") and not paths:
        paths = ["."]  # downloads into the current local directory
    return paths


def _commands_of(tool: str, kwargs: dict[str, Any], session: dict[str, Any] | None) -> list[str]:
    commands: list[str] = []
    if isinstance(kwargs.get("command"), str):
        commands.append(kwargs["command"])
    if isinstance(kwargs.get("commands"), list):
        commands.extend(str(c) for c in kwargs["commands"])
    if tool == "plink_script" and kwargs.get("script_path"):
        try:
            with open(kwargs["script_path"], encoding="utf-8", errors="replace") as f:
                commands.extend(f.read(1_000_000).splitlines())
        except OSError:
            pass  # plink will report the missing file
    return commands


def evaluate(
    settings: Settings,
    tool: str,
    kwargs: dict[str, Any],
    session: dict[str, Any] | None = None,
) -> Decision:
    """session: info about the target session for session_send/read/close."""
    d = Decision()
    is_sftp = tool == "psftp_batch" or (session is not None and session.get("protocol") == "sftp")

    # -- Hosts -------------------------------------------------------------
    hosts: list[str] = []
    if tool not in _NO_HOST_CHECK and kwargs.get("protocol") != "serial":
        for key in ("host", "target_host"):
            if kwargs.get(key):
                hosts.append(parse_host_string(str(kwargs[key]))["host"])
    for jump in kwargs.get("jump_hosts") or []:
        hosts.append(parse_host_string(str(jump))["host"])

    for host in hosts:
        if host_matches(host, settings.blocked_hosts):
            d.escalate(DENY, f"host {host} is on the blocked list")
        elif not host_matches(host, settings.allowed_hosts):
            if settings.unknown_host_action != ALLOW:
                d.escalate(settings.unknown_host_action, f"host {host} is not on the allowed list")
                d.offer(f"host:{host}", f"Always allow host {host}")

    # -- Commands ----------------------------------------------------------
    for command in _commands_of(tool, kwargs, session):
        for rule in settings.command_rules:
            if re.search(rule["pattern"], command, re.IGNORECASE):
                note = f" ({rule['note']})" if rule.get("note") else ""
                d.escalate(rule["action"], f"command matches rule{note}: {command.strip()[:200]}")

    # -- Local files ---------------------------------------------------------
    paths = [str(kwargs[k]) for k in _LOCAL_PATH_ARGS if kwargs.get(k)]
    paths += [str(p) for p in kwargs.get("key_paths") or []]
    if is_sftp:
        for command in _commands_of(tool, kwargs, session):
            paths += _psftp_local_paths(command)
    if settings.local_path_action != ALLOW:
        for path in paths:
            if not path_allowed(path, settings.allowed_local_dirs):
                folder = path if Path(path).is_dir() or path == "." else str(Path(path).parent)
                folder = os.path.realpath(os.path.expanduser(folder or "."))
                d.escalate(settings.local_path_action, f"local path outside allowed folders: {path}")
                d.offer(f"dir:{folder}", f"Always allow folder {folder}")

    # -- Local proxy commands (run on this computer) -------------------------
    for key in ("proxy_command", "proxy_cmd"):
        if kwargs.get(key) and settings.proxy_command_action != ALLOW:
            d.escalate(settings.proxy_command_action,
                       f"custom proxy command runs on this computer: {kwargs[key]}")

    # -- CCC Prodigy controllers (turbomachinery control) ----------------------
    is_prodigy = tool == "ttssh_run" or (
        tool == "session_send" and session is not None and session.get("protocol") == "ttssh")
    if is_prodigy and settings.ttssh_approval == "every_command":
        d.escalate(ASK, "Prodigy controller: every command needs approval (Settings → CCC Prodigy)")
    elif is_prodigy and settings.ttssh_approval == "readonly_auto":
        changing = [c for c in _commands_of(tool, kwargs, session) if not prodigy_readonly(c)]
        if changing:
            d.escalate(ASK, "Prodigy controller: not a read-only command: " + ", ".join(changing)[:300])

    # -- Risky tools and approval mode -----------------------------------------
    if tool in _RISKY_TOOLS:
        d.escalate(ASK, _RISKY_TOOLS[tool])
    if settings.approval_mode == "all" and d.action == ALLOW and tool not in READ_ONLY_TOOLS:
        d.escalate(ASK, "approval mode is 'every call'")
    if settings.approval_mode == "off" and d.action == ASK:
        d.action = ALLOW
    return d


def apply_remember(settings: Settings, remember: list[str]) -> None:
    """Persist 'always allow' choices from an approval into settings."""
    for item in remember:
        kind, _, value = item.partition(":")
        if kind == "host" and value and value not in settings.allowed_hosts:
            settings.allowed_hosts.append(value)
        elif kind == "dir" and value and value not in settings.allowed_local_dirs:
            settings.allowed_local_dirs.append(value)
