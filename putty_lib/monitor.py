"""Live activity monitor with an operator kill switch.

Records every tool call and every process the server starts, so a human can
watch along in the web dashboard (see monitor_web.py) and kill a connection,
or everything, when something looks wrong.
"""

from __future__ import annotations

import itertools
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from putty_lib.session_manager import SessionManager

log = logging.getLogger(__name__)

# Tool arguments that must never be shown or stored
_SECRET_ARGS = {"passphrase", "password"}

_MAX_TEXT = 4000


def _truncate(text: str, limit: int = _MAX_TEXT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [{len(text) - limit} more characters]"


def redact_args(args: dict[str, Any]) -> dict[str, Any]:
    return {k: ("***" if k in _SECRET_ARGS and v else v) for k, v in args.items()}


def kill_process_tree(proc: subprocess.Popen) -> None:
    """Kill a process and its children (e.g. plink proxy chains)."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
            )
        else:
            # Processes are started with start_new_session=True, so the
            # pid is also the process group id.
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass


@dataclass
class TrackedProcess:
    proc_id: str
    kind: str  # "command", "session", "gui"
    tool: str
    label: str
    process: subprocess.Popen
    started_at: float = field(default_factory=time.time)
    session_id: str | None = None
    killed: bool = False


class OperatorBlocked(Exception):
    """Raised when a tool call is refused because the kill switch is engaged."""


class Monitor:
    """Thread-safe store of activity events and tracked processes."""

    def __init__(self, max_events: int = 500) -> None:
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._event_seq = itertools.count(1)
        self._ids = itertools.count(1)
        self._calls: dict[int, dict[str, Any]] = {}
        self._procs: dict[str, TrackedProcess] = {}
        self._sessions: SessionManager | None = None
        self.locked = False
        self.lock_reason = ""
        self.started_at = time.time()
        # Called with each event (audit log) and on KILL ALL (deny approvals)
        self.event_sinks: list[Callable[[dict[str, Any]], None]] = []
        self.on_kill_all: list[Callable[[], Any]] = []

    def attach_sessions(self, sessions: SessionManager) -> None:
        self._sessions = sessions

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def _emit(self, kind: str, **data: Any) -> dict[str, Any]:
        """Append an event (caller must hold the lock)."""
        event = {"seq": next(self._event_seq), "time": time.time(), "kind": kind, **data}
        self._events.append(event)
        for sink in self.event_sinks:
            try:
                sink(event)
            except Exception:  # noqa: BLE001 - a broken sink must not break tools
                log.exception("event sink failed")
        return event

    def emit(self, kind: str, **data: Any) -> None:
        with self._lock:
            self._emit(kind, **data)

    def note(self, message: str) -> None:
        self.emit("operator", message=message)

    def alert(self, message: str) -> None:
        """Something the operator must notice (e.g. a changed host key)."""
        self.emit("alert", message=message)

    # ------------------------------------------------------------------
    # Tool calls
    # ------------------------------------------------------------------

    def call_started(self, tool: str, args: dict[str, Any]) -> int:
        """Record a tool call. Raises OperatorBlocked while the kill switch is on."""
        with self._lock:
            call_id = next(self._ids)
            shown = redact_args({k: v for k, v in args.items() if v is not None})
            if self.locked:
                self._emit("call", call_id=call_id, tool=tool, args=shown, status="blocked")
                raise OperatorBlocked(
                    "Blocked by operator: the PuTTY MCP kill switch is engaged"
                    + (f" ({self.lock_reason})" if self.lock_reason else "")
                    + ". Stop and ask the user what to do."
                )
            call = {"call_id": call_id, "tool": tool, "args": shown, "started_at": time.time()}
            self._calls[call_id] = call
            self._emit("call", call_id=call_id, tool=tool, args=shown, status="running")
            return call_id

    def call_waiting(self, call_id: int, reasons: list[str]) -> None:
        with self._lock:
            call = self._calls.get(call_id)
            if call is not None:
                call["waiting"] = True
                self._emit("call", call_id=call_id, tool=call["tool"], args=call["args"],
                           status="waiting", reasons=reasons)

    def call_resumed(self, call_id: int) -> None:
        with self._lock:
            call = self._calls.get(call_id)
            if call is not None:
                call["waiting"] = False
                self._emit("call", call_id=call_id, tool=call["tool"], args=call["args"], status="running")

    def call_finished(self, call_id: int, result: Any = None, error: str | None = None) -> None:
        with self._lock:
            call = self._calls.pop(call_id, None)
            if call is None:
                return
            duration = round(time.time() - call["started_at"], 2)
            if error is not None:
                self._emit("result", call_id=call_id, tool=call["tool"], status="error",
                           duration=duration, error=_truncate(error))
                return
            status = "ok"
            if isinstance(result, dict):
                if result.get("killed_by_operator"):
                    status = "killed"
                elif result.get("success") is False or result.get("error"):
                    status = "failed"
            self._emit("result", call_id=call_id, tool=call["tool"], status=status,
                       duration=duration, result=_summarize(result))

    # ------------------------------------------------------------------
    # Processes
    # ------------------------------------------------------------------

    def track(self, process: subprocess.Popen, kind: str, tool: str, label: str) -> str:
        with self._lock:
            proc_id = f"p{next(self._ids)}"
            self._procs[proc_id] = TrackedProcess(proc_id, kind, tool, label, process)
            self._emit("process", proc_id=proc_id, pid=process.pid, ptype=kind,
                       tool=tool, label=label, status="started")
            return proc_id

    def link_session(self, proc_id: str, session_id: str) -> None:
        with self._lock:
            tp = self._procs.get(proc_id)
            if tp:
                tp.session_id = session_id

    def untrack(self, proc_id: str) -> bool:
        """Stop tracking a finished process. Returns True if the operator killed it."""
        with self._lock:
            tp = self._procs.pop(proc_id, None)
            if tp is None:
                return False
            self._emit("process", proc_id=proc_id, pid=tp.process.pid, ptype=tp.kind,
                       tool=tp.tool, label=tp.label,
                       status="killed" if tp.killed else "exited",
                       return_code=tp.process.returncode)
            return tp.killed

    def was_killed(self, proc_id: str) -> bool:
        with self._lock:
            tp = self._procs.get(proc_id)
            return bool(tp and tp.killed)

    def _prune(self) -> None:
        """Forget exited sessions/GUI processes (caller must hold the lock)."""
        for proc_id, tp in list(self._procs.items()):
            if tp.kind != "command" and tp.process.poll() is not None:
                self._procs.pop(proc_id)
                self._emit("process", proc_id=proc_id, pid=tp.process.pid, ptype=tp.kind,
                           tool=tp.tool, label=tp.label,
                           status="killed" if tp.killed else "exited",
                           return_code=tp.process.returncode)

    # ------------------------------------------------------------------
    # Kill switch
    # ------------------------------------------------------------------

    def kill(self, proc_id: str) -> bool:
        with self._lock:
            tp = self._procs.get(proc_id)
            if tp is None:
                return False
            tp.killed = True
            self._emit("operator", message=f"Killed {tp.kind} {tp.label} (PID {tp.process.pid})")
        kill_process_tree(tp.process)
        if tp.session_id and self._sessions is not None:
            self._sessions.close(tp.session_id)
        return True

    def kill_all(self, lock: bool = True) -> int:
        with self._lock:
            if lock:
                self.locked = True
                self.lock_reason = "kill switch"
            targets = list(self._procs.values())
            for tp in targets:
                tp.killed = True
            self._emit("operator", message=f"KILL SWITCH: killing {len(targets)} process(es)"
                       + ("; new tool calls are blocked" if lock else ""))
        for callback in self.on_kill_all:
            callback()
        # Kill first so close_all() doesn't wait on graceful termination
        for tp in targets:
            kill_process_tree(tp.process)
        if self._sessions is not None:
            self._sessions.close_all()
        return len(targets)

    def set_locked(self, locked: bool, reason: str = "") -> None:
        with self._lock:
            self.locked = locked
            self.lock_reason = reason if locked else ""
            self._emit("operator", message="Tool calls blocked" if locked else "Tool calls allowed again")

    # ------------------------------------------------------------------
    # Snapshot for the dashboard
    # ------------------------------------------------------------------

    def snapshot(self, since: int = 0, session_chars: int = 20000) -> dict[str, Any]:
        with self._lock:
            self._prune()
            events = [e for e in self._events if e["seq"] > since]
            now = time.time()
            procs = [
                {
                    "proc_id": tp.proc_id,
                    "pid": tp.process.pid,
                    "kind": tp.kind,
                    "tool": tp.tool,
                    "label": tp.label,
                    "session_id": tp.session_id,
                    "age_seconds": round(now - tp.started_at, 1),
                }
                for tp in self._procs.values()
            ]
            running = [
                {**c, "elapsed": round(now - c["started_at"], 1)} for c in self._calls.values()
            ]
            state = {
                "locked": self.locked,
                "lock_reason": self.lock_reason,
                "pid": os.getpid(),
                "uptime": round(now - self.started_at),
            }
        sessions_out = []
        if self._sessions is not None:
            for info in self._sessions.list_sessions():
                try:
                    output = self._sessions.get(info["session_id"]).peek(session_chars)
                except KeyError:
                    continue
                sessions_out.append({**info, "output": output})
        return {
            **state,
            "events": events,
            "processes": procs,
            "running_calls": running,
            "sessions": sessions_out,
        }


def _summarize(result: Any) -> Any:
    """Keep results small enough to ship to the dashboard."""
    if isinstance(result, dict):
        return {k: (_truncate(v) if isinstance(v, str) else v) for k, v in result.items()}
    if isinstance(result, str):
        return _truncate(result)
    return result
