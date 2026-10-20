"""Runtime settings, edited from the monitor dashboard.

config.toml holds start-up settings (dashboard address, logging). Everything
the operator may want to change while the server runs lives here, persisted
to settings.json in the data directory. config.toml values only seed the
first run.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

APPROVAL_MODES = ("risky", "all", "off")
ACTIONS = ("ask", "allow", "deny")
RULE_ACTIONS = ("ask", "deny")
OPEN_BROWSER = ("first_call", "start", "never")
# "Never ask" always ends after one of these durations (minutes)
APPROVAL_OFF_MINUTES = (5, 15, 30, 60, 120, 240, 480)

# Commands that ask for approval out of the box. The operator can edit or
# remove them in the dashboard.
DEFAULT_COMMAND_RULES: list[dict[str, str]] = [
    {"pattern": r"\brm\s+(-\S*\s+)*-\S*[rf]", "action": "ask", "note": "recursive/forced delete"},
    {"pattern": r"\b(shutdown|reboot|halt|poweroff|init\s+[06])\b", "action": "ask", "note": "power off / reboot"},
    {"pattern": r"\b(mkfs|fdisk|parted|wipefs)\b|\bdd\s+.*\bof=", "action": "ask", "note": "disk / filesystem change"},
    {"pattern": r"\b(systemctl|service)\s+\S*\s*(stop|restart|disable|mask)\b", "action": "ask", "note": "stops services"},
    {"pattern": r"\b(iptables|nft|ufw|firewall-cmd)\b", "action": "ask", "note": "firewall change"},
    {"pattern": r"\b(userdel|usermod|passwd|chpasswd|visudo)\b", "action": "ask", "note": "user accounts"},
    {"pattern": r"\bchmod\s+(-\S+\s+)*777\b|\bchown\s+-R\b", "action": "ask", "note": "broad permission change"},
    {"pattern": r"\bcrontab\s+-r\b", "action": "ask", "note": "removes crontab"},
    {"pattern": r"\b(drop|truncate)\s+(table|database|schema)\b", "action": "ask", "note": "destructive SQL"},
    {"pattern": r"^\s*(reload|write\s+erase|erase\s+(startup-config|nvram:|flash:)|format\s+\S+:|delete\s+(/force\s+)?\S*flash:)",
     "action": "ask", "note": "network device reload / erase"},
    {"pattern": r"^\s*(no\s+)?(shutdown|switchport\s+mode|ip\s+address|router\s+\w+|crypto\s+key\s+zeroize)\b",
     "action": "ask", "note": "network device: interface down / addressing / routing"},
    {"pattern": r"^\s*(update|reset|wmrst|restart|reboot|flash|format|cpld|mfg|tpm|load|unload|netload|run|shell|sshshell)\b",
     "action": "ask", "note": "Prodigy: firmware / restart / load / raw shell"},
    {"pattern": r":\(\)\s*\{\s*:\|:&\s*\};:", "action": "deny", "note": "fork bomb"},
]


def data_dir() -> Path:
    """Where settings.json and the audit log live (PUTTY_MCP_HOME overrides)."""
    env = os.environ.get("PUTTY_MCP_HOME")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "putty-mcp"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "putty-mcp"


@dataclass
class Settings:
    # PuTTY
    putty_dir: str = ""  # empty = auto-detect
    enable_registry: bool = True

    # Safety
    approval_mode: str = "risky"
    # "off" (never ask) is temporary: it ends at approval_off_until and the
    # mode returns to approval_mode_before_off
    approval_off_minutes: int = 30
    approval_off_until: float = 0.0
    approval_mode_before_off: str = "risky"
    approval_timeout_seconds: int = 120
    unknown_host_action: str = "ask"
    allowed_hosts: list[str] = field(default_factory=list)
    blocked_hosts: list[str] = field(default_factory=list)
    command_rules: list[dict[str, str]] = field(default_factory=lambda: copy.deepcopy(DEFAULT_COMMAND_RULES))
    local_path_action: str = "ask"
    allowed_local_dirs: list[str] = field(default_factory=list)
    proxy_command_action: str = "ask"
    unknown_host_key_action: str = "ask"  # "ask" or "deny"
    trusted_host_keys: dict[str, list[str]] = field(default_factory=dict)

    # Sessions and output
    max_concurrent: int = 10
    idle_timeout_seconds: int = 3600
    buffer_lines: int = 1000
    max_output_chars: int = 20000
    strip_ansi: bool = True

    # Serial defaults
    serial_baud: int = 9600
    serial_data_bits: int = 8
    serial_parity: str = "n"
    serial_stop_bits: int = 1
    serial_flow_control: str = "N"

    # CCC Prodigy controllers via TrainTools SSH (ttssh)
    ttssh_path: str = ""  # empty = find ttssh on PATH
    ttssh_approval: str = "every_command"  # "readonly_auto" or "rules"

    # Dashboard and audit
    open_browser: str = "first_call"
    audit_enabled: bool = True
    audit_retention_days: int = 30

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validate(data: dict[str, Any], base: Settings) -> Settings:
    """Return a new Settings with data applied; raises ValueError on bad input."""
    out = copy.deepcopy(base)
    known = {f.name: f for f in fields(Settings)}
    for key, value in data.items():
        if key not in known:
            raise ValueError(f"Unknown setting: {key}")
        current = getattr(base, key)
        if isinstance(current, bool):
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
        elif isinstance(current, float):
            try:
                value = float(value)
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a number") from None
        elif isinstance(current, int):
            if isinstance(value, bool) or not isinstance(value, int):
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    raise ValueError(f"{key} must be a number") from None
            if value < 0:
                raise ValueError(f"{key} must not be negative")
        elif isinstance(current, str):
            if not isinstance(value, str):
                raise ValueError(f"{key} must be text")
            value = value.strip()
        elif isinstance(current, list) and key != "command_rules":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"{key} must be a list of text")
            value = [v.strip() for v in value if v.strip()]
        setattr(out, key, value)

    choices = {
        "approval_mode": APPROVAL_MODES,
        "unknown_host_action": ACTIONS,
        "local_path_action": ACTIONS,
        "proxy_command_action": ACTIONS,
        "unknown_host_key_action": ("ask", "deny"),
        "open_browser": OPEN_BROWSER,
        "ttssh_approval": ("every_command", "readonly_auto", "rules"),
        "approval_mode_before_off": ("risky", "all"),
    }
    for key, allowed in choices.items():
        if getattr(out, key) not in allowed:
            raise ValueError(f"{key} must be one of: {', '.join(allowed)}")

    rules = []
    for rule in out.command_rules:
        if not isinstance(rule, dict) or not str(rule.get("pattern", "")).strip():
            raise ValueError("Every command rule needs a pattern")
        pattern = str(rule["pattern"]).strip()
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid pattern {pattern!r}: {e}") from None
        action = str(rule.get("action", "ask"))
        if action not in RULE_ACTIONS:
            raise ValueError(f"Rule action must be one of: {', '.join(RULE_ACTIONS)}")
        rules.append({"pattern": pattern, "action": action, "note": str(rule.get("note", "")).strip()})
    out.command_rules = rules

    if not isinstance(out.trusted_host_keys, dict) or not all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(x, str) for x in v)
        for k, v in out.trusted_host_keys.items()
    ):
        raise ValueError("trusted_host_keys must map 'host:port' to a list of fingerprints")
    out.trusted_host_keys = {k: v for k, v in out.trusted_host_keys.items() if v}

    if out.approval_off_minutes not in APPROVAL_OFF_MINUTES:
        raise ValueError("approval_off_minutes must be one of: " + ", ".join(map(str, APPROVAL_OFF_MINUTES)))
    if out.max_concurrent < 1:
        raise ValueError("max_concurrent must be at least 1")
    if out.buffer_lines < 10:
        raise ValueError("buffer_lines must be at least 10")
    if out.approval_timeout_seconds < 5:
        raise ValueError("approval_timeout_seconds must be at least 5")
    if out.max_output_chars < 1000:
        raise ValueError("max_output_chars must be at least 1000")
    return out


class SettingsStore:
    """Thread-safe settings holder that persists to settings.json."""

    def __init__(self, path: Path, seed: dict[str, Any] | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._listeners: list[Callable[[Settings], None]] = []
        settings = Settings()
        if seed:
            settings = _validate(seed, settings)
        if path.exists():
            try:
                stored = json.loads(path.read_text(encoding="utf-8"))
                known = {f.name for f in fields(Settings)}
                settings = _validate({k: v for k, v in stored.items() if k in known}, settings)
            except (OSError, ValueError) as e:
                log.warning("Ignoring invalid %s: %s", path, e)
        if settings.approval_mode == "off" and not settings.approval_off_until:
            # "Never ask" from before it had a time limit: give it one now
            settings.approval_off_until = time.time() + settings.approval_off_minutes * 60
        self._settings = settings

    @property
    def current(self) -> Settings:
        """A snapshot copy; mutate via update()."""
        with self._lock:
            return copy.deepcopy(self._settings)

    def on_change(self, listener: Callable[[Settings], None]) -> None:
        self._listeners.append(listener)

    def update(self, changes: dict[str, Any]) -> Settings:
        with self._lock:
            old = self._settings
            # The pause end time is managed here, not set from outside
            changes = {k: v for k, v in changes.items() if k != "approval_off_until"}
            new = _validate(changes, old)
            if new.approval_mode == "off":
                if old.approval_mode != "off":
                    new.approval_mode_before_off = old.approval_mode
                if old.approval_mode != "off" or "approval_off_minutes" in changes:
                    new.approval_off_until = time.time() + new.approval_off_minutes * 60
            else:
                new.approval_off_until = 0.0
            self._settings = new
            self._save()
            snapshot = copy.deepcopy(new)
        for listener in self._listeners:
            listener(snapshot)
        return snapshot

    def mutate(self, fn: Callable[[Settings], None]) -> Settings:
        """Apply an in-place change (e.g. append to a list) atomically."""
        with self._lock:
            draft = copy.deepcopy(self._settings)
            fn(draft)
            new = _validate({}, draft)
            self._settings = new
            self._save()
            snapshot = copy.deepcopy(new)
        for listener in self._listeners:
            listener(snapshot)
        return snapshot

    def end_pause(self, now: float | None = None, force: bool = False) -> bool:
        """End "never ask" when its time is up (or now, with force). True if it ended."""
        with self._lock:
            s = self._settings
            if s.approval_mode != "off":
                return False
            if not force and (now or time.time()) < s.approval_off_until:
                return False
            new = copy.deepcopy(s)
            new.approval_mode = new.approval_mode_before_off
            new.approval_off_until = 0.0
            self._settings = new
            self._save()
            snapshot = copy.deepcopy(new)
        for listener in self._listeners:
            listener(snapshot)
        return True

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._settings.to_dict(), indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as e:
            log.error("Could not save settings to %s: %s", self.path, e)
