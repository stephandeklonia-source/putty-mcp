"""Persistent interactive session management for plink/psftp."""

from __future__ import annotations

import logging
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class InteractiveSession:
    """Wraps a Popen process with a background reader and bounded output buffer."""

    session_id: str
    process: subprocess.Popen
    host: str
    protocol: str
    created_at: float
    metadata: dict[str, Any] = field(default_factory=dict)

    _buffer: deque[str] = field(default_factory=lambda: deque(maxlen=1000))
    _reader_thread: threading.Thread | None = field(default=None, repr=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def start_reader(self, buffer_lines: int = 1000) -> None:
        """Start background thread reading stdout."""
        self._buffer = deque(maxlen=buffer_lines)
        self._reader_thread = threading.Thread(
            target=self._read_loop, daemon=True, name=f"reader-{self.session_id[:8]}"
        )
        self._reader_thread.start()

    def _read_loop(self) -> None:
        try:
            assert self.process.stdout is not None
            for line in iter(self.process.stdout.readline, ""):
                if self._stop_event.is_set():
                    break
                with self._lock:
                    self._buffer.append(line)
        except (ValueError, OSError):
            pass  # pipe closed

    def send(self, text: str) -> None:
        """Send text to the process stdin."""
        if self.process.stdin is None:
            raise RuntimeError("Session stdin not available")
        if self.process.poll() is not None:
            raise RuntimeError("Session process has exited")
        self.process.stdin.write(text)
        self.process.stdin.flush()

    def read(self, last_n: int | None = None, clear: bool = False) -> list[str]:
        """Read output buffer. Optionally return only last N lines and/or clear."""
        with self._lock:
            if last_n:
                lines = list(self._buffer)[-last_n:]
            else:
                lines = list(self._buffer)
            if clear:
                self._buffer.clear()
        return lines

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    def close(self) -> None:
        """Gracefully close the session."""
        self._stop_event.set()
        if self.process.stdin:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        # Try graceful termination
        if self.alive:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)


class SessionManager:
    """Manages multiple interactive sessions."""

    def __init__(self, max_concurrent: int = 10, timeout_seconds: int = 3600, buffer_lines: int = 1000) -> None:
        self.max_concurrent = max_concurrent
        self.timeout_seconds = timeout_seconds
        self.buffer_lines = buffer_lines
        self._sessions: dict[str, InteractiveSession] = {}
        self._lock = threading.Lock()

        # Start cleanup thread
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="session-cleanup")
        self._cleanup_thread.start()

    def create(
        self,
        process: subprocess.Popen,
        host: str,
        protocol: str = "ssh",
        **metadata: Any,
    ) -> InteractiveSession:
        """Register a new interactive session."""
        with self._lock:
            # Cleanup dead sessions first
            self._reap_dead()
            if len(self._sessions) >= self.max_concurrent:
                raise RuntimeError(
                    f"Maximum concurrent sessions ({self.max_concurrent}) reached. "
                    f"Close an existing session first."
                )

            session_id = uuid.uuid4().hex[:12]
            session = InteractiveSession(
                session_id=session_id,
                process=process,
                host=host,
                protocol=protocol,
                created_at=time.time(),
                metadata=metadata,
            )
            session.start_reader(self.buffer_lines)
            self._sessions[session_id] = session
            log.info("Session %s created: %s via %s", session_id, host, protocol)
            return session

    def get(self, session_id: str) -> InteractiveSession:
        with self._lock:
            if session_id not in self._sessions:
                raise KeyError(f"Session '{session_id}' not found")
            return self._sessions[session_id]

    def close(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session:
            session.close()
            log.info("Session %s closed", session_id)
            return True
        return False

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "session_id": s.session_id,
                    "host": s.host,
                    "protocol": s.protocol,
                    "alive": s.alive,
                    "age_seconds": round(s.age_seconds, 1),
                    **s.metadata,
                }
                for s in self._sessions.values()
            ]

    def close_all(self) -> int:
        """Close all sessions. Returns count closed."""
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for s in sessions:
            s.close()
        return len(sessions)

    def _reap_dead(self) -> None:
        """Remove sessions whose process has exited (called with lock held)."""
        dead = [sid for sid, s in self._sessions.items() if not s.alive]
        for sid in dead:
            self._sessions.pop(sid, None)

    def _cleanup_loop(self) -> None:
        """Periodically close timed-out sessions."""
        while not self._stop_event.wait(60):
            with self._lock:
                timed_out = [
                    sid
                    for sid, s in self._sessions.items()
                    if s.age_seconds > self.timeout_seconds
                ]
            for sid in timed_out:
                log.info("Session %s timed out, closing", sid)
                self.close(sid)

    def shutdown(self) -> None:
        """Shut down the manager and all sessions."""
        self._stop_event.set()
        self.close_all()
