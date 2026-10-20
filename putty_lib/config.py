"""Start-up configuration (config.toml) and PuTTY path auto-detection.

Settings that can change at runtime live in settings.py and are edited in
the dashboard; config.toml only seeds them on the first run.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


EXECUTABLES = ["putty", "plink", "pscp", "psftp", "pageant", "puttygen"]
# Resolved from PATH, not the PuTTY install dir (pageant_list uses ssh-add)
SYSTEM_EXECUTABLES = ["ssh-add"]

# Common install locations on Windows
_COMMON_DIRS = [
    Path(r"C:\Program Files\PuTTY"),
    Path(r"C:\Program Files (x86)\PuTTY"),
    Path(os.path.expanduser("~"), "PuTTY"),
]


@dataclass
class SerialDefaults:
    baud: int = 9600
    data_bits: int = 8
    parity: str = "n"
    stop_bits: int = 1
    flow_control: str = "N"


@dataclass
class SessionDefaults:
    max_concurrent: int = 10
    timeout_seconds: int = 3600
    buffer_lines: int = 1000


@dataclass
class MonitorSettings:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8765
    # "first_call" (default), "start" or "never"
    open_browser: str = "first_call"


@dataclass
class PuTTYConfig:
    executable_path: Path | None = None
    enable_registry: bool = True
    serial: SerialDefaults = field(default_factory=SerialDefaults)
    sessions: SessionDefaults = field(default_factory=SessionDefaults)
    monitor: MonitorSettings = field(default_factory=MonitorSettings)
    log_enabled: bool = True
    log_level: str = "INFO"

    # Resolved paths for each executable
    exe_paths: dict[str, Path] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._resolve_executables()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, config_path: Path | None = None) -> "PuTTYConfig":
        """Load config from TOML file, falling back to defaults."""
        cfg = cls()
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config.toml"
        if config_path.exists():
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
            cfg._apply_toml(data)
            cfg._resolve_executables()
        return cfg

    def _apply_toml(self, data: dict) -> None:
        putty = data.get("putty", {})
        if putty.get("executable_path"):
            self.executable_path = Path(putty["executable_path"])
        self.enable_registry = putty.get("enable_registry", self.enable_registry)

        serial = data.get("serial", {})
        for key in ("baud", "data_bits", "parity", "stop_bits", "flow_control"):
            if key in serial:
                setattr(self.serial, key, serial[key])

        sessions = data.get("sessions", {})
        for key in ("max_concurrent", "timeout_seconds", "buffer_lines"):
            if key in sessions:
                setattr(self.sessions, key, sessions[key])

        monitor = data.get("monitor", {})
        for key in ("enabled", "host", "port", "open_browser"):
            if key in monitor:
                setattr(self.monitor, key, monitor[key])

        logging_cfg = data.get("logging", {})
        self.log_enabled = logging_cfg.get("enabled", self.log_enabled)
        self.log_level = logging_cfg.get("level", self.log_level)

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def seed_settings(self) -> dict:
        """Values from config.toml used to initialise settings.json."""
        return {
            "putty_dir": str(self.executable_path or ""),
            "enable_registry": self.enable_registry,
            "max_concurrent": self.sessions.max_concurrent,
            "idle_timeout_seconds": self.sessions.timeout_seconds,
            "buffer_lines": self.sessions.buffer_lines,
            "serial_baud": self.serial.baud,
            "serial_data_bits": self.serial.data_bits,
            "serial_parity": self.serial.parity,
            "serial_stop_bits": self.serial.stop_bits,
            "serial_flow_control": self.serial.flow_control,
            "open_browser": self.monitor.open_browser,
        }

    def set_putty_dir(self, putty_dir: str) -> None:
        """Change the PuTTY directory at runtime and re-detect executables."""
        self.executable_path = Path(putty_dir) if putty_dir else None
        self._resolve_executables()

    def _resolve_executables(self) -> None:
        """Find all PuTTY executables and system tools (ssh-add)."""
        self.exe_paths = {}
        base_dir = self._find_base_dir()
        for name in EXECUTABLES:
            exe_name = f"{name}.exe" if sys.platform == "win32" else name
            if base_dir:
                candidate = base_dir / exe_name
                if candidate.exists():
                    self.exe_paths[name] = candidate
                    continue
            # Fallback: check PATH
            found = shutil.which(exe_name)
            if found:
                self.exe_paths[name] = Path(found)

        # System executables (not part of PuTTY install)
        for name in SYSTEM_EXECUTABLES:
            exe_name = f"{name}.exe" if sys.platform == "win32" else name
            found = shutil.which(exe_name)
            if found:
                self.exe_paths[name] = Path(found)

    def _find_base_dir(self) -> Path | None:
        # 1. Explicit config
        if self.executable_path and self.executable_path.is_dir():
            return self.executable_path

        # 2. PUTTY_PATH env var
        env_path = os.environ.get("PUTTY_PATH")
        if env_path:
            p = Path(env_path)
            if p.is_dir():
                return p

        # 3. Check if plink is on PATH — derive directory from it
        plink = shutil.which("plink.exe" if sys.platform == "win32" else "plink")
        if plink:
            return Path(plink).parent

        # 4. Common install directories
        for d in _COMMON_DIRS:
            if d.is_dir():
                return d

        return None

    def get_exe(self, tool: str) -> Path:
        """Get resolved path for a PuTTY executable. Raises if not found."""
        if tool not in self.exe_paths:
            raise FileNotFoundError(
                f"PuTTY executable '{tool}' not found. "
                f"Set the PuTTY folder in the monitor dashboard (Settings) or add PuTTY to PATH."
            )
        return self.exe_paths[tool]

    def command_for(self, tool: str) -> list[str]:
        """Command prefix used to run a tool (tests replace this)."""
        return [str(self.get_exe(tool))]

    def validate(self) -> dict[str, str | None]:
        """Map each executable to its resolved path (None if missing)."""
        all_names = list(EXECUTABLES) + list(SYSTEM_EXECUTABLES)
        return {name: str(self.exe_paths[name]) if name in self.exe_paths else None for name in all_names}
