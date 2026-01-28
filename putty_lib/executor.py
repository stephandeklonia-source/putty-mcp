"""Subprocess wrapper for all PuTTY executables."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from putty_lib.config import PuTTYConfig

log = logging.getLogger(__name__)


class PuTTYExecutor:
    """Run PuTTY-suite executables safely (never shell=True)."""

    def __init__(self, config: PuTTYConfig) -> None:
        self.config = config

    def run(
        self,
        tool: str,
        args: list[str],
        input_text: str | None = None,
        timeout: int = 30,
        **kwargs: Any,
    ) -> dict:
        """Run a PuTTY executable and return result dict.

        Returns:
            {"stdout": str, "stderr": str, "return_code": int, "success": bool}
        """
        exe = self.config.get_exe(tool)
        cmd = [str(exe)] + args
        log.info("run: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                **kwargs,
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
                "return_code": -1,
                "success": False,
            }
        except FileNotFoundError:
            return {
                "stdout": "",
                "stderr": f"Executable not found: {exe}",
                "return_code": -1,
                "success": False,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "success": False,
            }

    def spawn(
        self,
        tool: str,
        args: list[str],
        **kwargs: Any,
    ) -> subprocess.Popen:
        """Spawn a long-running PuTTY process. Returns the Popen handle."""
        exe = self.config.get_exe(tool)
        cmd = [str(exe)] + args
        log.info("spawn: %s", " ".join(cmd))

        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            **kwargs,
        )

    def launch_gui(self, tool: str, args: list[str]) -> dict:
        """Launch a GUI process (putty.exe, pageant) detached.

        Returns immediately — doesn't wait for exit.
        """
        exe = self.config.get_exe(tool)
        cmd = [str(exe)] + args
        log.info("launch_gui: %s", " ".join(cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
            )
            return {
                "pid": proc.pid,
                "success": True,
                "message": f"Launched {tool} (PID {proc.pid})",
            }
        except Exception as e:
            return {"pid": None, "success": False, "message": str(e)}
