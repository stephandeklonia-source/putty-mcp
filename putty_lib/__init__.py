"""PuTTY MCP Server library — wraps the full PuTTY toolchain."""

# Single source of the version (pyproject.toml reads it). Format YYYY.MM.rev:
# year, month and a 3-digit revision that restarts at 001 each month.
# Raise it with every change and add a CHANGELOG.md entry; CI checks both.
__version__ = "2026.10.001"

from putty_lib.config import PuTTYConfig
from putty_lib.executor import PuTTYExecutor
from putty_lib.utils import parse_host_string, build_connection_args

__all__ = ["__version__", "PuTTYConfig", "PuTTYExecutor", "parse_host_string", "build_connection_args"]
