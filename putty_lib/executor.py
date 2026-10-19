"""Subprocess wrapper for all PuTTY executables."""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

from putty_lib.config import PuTTYConfig
from putty_lib.monitor import Monitor, kill_process_tree

log = logging.getLogger(__name__)

# Flags whose following argument is a secret and must not be logged
_SECRET_FLAGS: dict[str, set[str]] = {"ssh-keygen": {"-N", "-P"}}

# Own process group on POSIX so the kill switch can take out child processes
# (e.g. plink -proxycmd chains) too. Windows uses taskkill /T instead.
_POPEN_GROUP: dict[str, Any] = {} if sys.platform == "win32" else {"start_new_session": True}


def loggable(tool: str, cmd: list[str], short: bool = False) -> str:
    """Command line with secrets masked; short=True drops the exe's directory."""
    secret_flags = _SECRET_FLAGS.get(tool, set())
    out: list[str] = [Path(cmd[0]).stem if short else cmd[0]]
    hide_next = cmd[0] in secret_flags
    for part in cmd[1:]:
        out.append("***" if hide_next else part)
        hide_next = part in secret_flags
    return " ".join(out)


def _error(message: str) -> dict:
    return {"stdout": "", "stderr": message, "return_code": -1, "success": False}


class PuTTYExecutor:
    """Run PuTTY-suite executables safely (never shell=True).

    Every process is registered with the monitor so the operator can see it
    in the dashboard and kill it.
    """

    def __init__(self, config: PuTTYConfig, monitor: Monitor | None = None) -> None:
        self.config = config
        self.monitor = monitor or Monitor()

    def run(
        self,
        tool: str,
        args: list[str],
        input_text: str | None = None,
        timeout: int = 30,
    ) -> dict:
        """Run a PuTTY executable to completion and return result dict.

        Returns:
            {"stdout": str, "stderr": str, "return_code": int, "success": bool}
            plus "killed_by_operator": True if the kill switch ended it.
        """
        exe = self.config.get_exe(tool)
        cmd = [str(exe)] + args
        log.info("run: %s", loggable(tool, cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                # Never let the child inherit our stdin: over stdio transport
                # it is the MCP protocol stream, and plink would consume it.
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                **_POPEN_GROUP,
            )
        except FileNotFoundError:
            return _error(f"Executable not found: {exe}")
        except OSError as e:
            return _error(str(e))

        proc_id = self.monitor.track(proc, "command", tool, loggable(tool, cmd, short=True))
        timed_out = False
        try:
            stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_process_tree(proc)
            stdout, stderr = proc.communicate()
        finally:
            killed = self.monitor.untrack(proc_id)

        if killed:
            return {
                "stdout": stdout,
                "stderr": stderr + "\n[Killed by operator via the PuTTY MCP monitor]",
                "return_code": proc.returncode,
                "success": False,
                "killed_by_operator": True,
            }
        if timed_out:
            return {
                "stdout": stdout,
                "stderr": stderr + f"\nCommand timed out after {timeout}s",
                "return_code": -1,
                "success": False,
            }
        return {
            "stdout": stdout,
            "stderr": stderr,
            "return_code": proc.returncode,
            "success": proc.returncode == 0,
        }

    def spawn(self, tool: str, args: list[str]) -> tuple[subprocess.Popen, str]:
        """Spawn a long-running PuTTY process.

        Returns (Popen handle, monitor proc_id). stderr is merged into stdout
        so errors (auth failures, host key problems) show up in the session
        buffer and the pipe can't fill up.
        """
        exe = self.config.get_exe(tool)
        cmd = [str(exe)] + args
        log.info("spawn: %s", loggable(tool, cmd))

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            **_POPEN_GROUP,
        )
        return proc, self.monitor.track(proc, "session", tool, loggable(tool, cmd, short=True))

    def launch_gui(self, tool: str, args: list[str]) -> dict:
        """Launch a GUI process (putty.exe, pageant) detached.

        Returns immediately — doesn't wait for exit.
        """
        exe = self.config.get_exe(tool)
        cmd = [str(exe)] + args
        log.info("launch_gui: %s", loggable(tool, cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
                **_POPEN_GROUP,
            )
        except OSError as e:
            return {"pid": None, "success": False, "message": str(e)}
        self.monitor.track(proc, "gui", tool, loggable(tool, cmd, short=True))
        return {
            "pid": proc.pid,
            "success": True,
            "message": f"Launched {tool} (PID {proc.pid})",
        }
