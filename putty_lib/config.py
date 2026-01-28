"""Configuration loading and PuTTY path auto-detection."""

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
# ssh-keygen is resolved separately (not in PuTTY install dir)
SYSTEM_EXECUTABLES = ["ssh-keygen", "ssh-add"]

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
class PuTTYConfig:
    executable_path: Path | None = None
    enable_registry: bool = True
    default_protocol: str = "ssh"
    default_port: int = 22
    serial: SerialDefaults = field(default_factory=SerialDefaults)
    sessions: SessionDefaults = field(default_factory=SessionDefaults)
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

        defaults = data.get("defaults", {})
        self.default_protocol = defaults.get("protocol", self.default_protocol)
        self.default_port = defaults.get("port", self.default_port)

        serial = data.get("serial", {})
        for key in ("baud", "data_bits", "parity", "stop_bits", "flow_control"):
            if key in serial:
                setattr(self.serial, key, serial[key])

        sessions = data.get("sessions", {})
        for key in ("max_concurrent", "timeout_seconds", "buffer_lines"):
            if key in sessions:
                setattr(self.sessions, key, sessions[key])

        logging_cfg = data.get("logging", {})
        self.log_enabled = logging_cfg.get("enabled", self.log_enabled)
        self.log_level = logging_cfg.get("level", self.log_level)

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _resolve_executables(self) -> None:
        """Find all PuTTY executables and system tools (ssh-keygen)."""
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
                f"Set executable_path in config.toml or add PuTTY to PATH."
            )
        return self.exe_paths[tool]

    def validate(self) -> dict[str, bool]:
        """Return which executables were found."""
        all_names = list(EXECUTABLES) + list(SYSTEM_EXECUTABLES)
        return {name: name in self.exe_paths for name in all_names}
