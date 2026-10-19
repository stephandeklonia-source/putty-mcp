"""Persistent interactive session management for plink/psftp."""

from __future__ import annotations

import codecs
import logging
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger(__name__)

# Last line looks like a shell/sftp prompt: "user@host:~$ ", "# ", "psftp> ", "C:\\>"
_PROMPT = re.compile(r"(?:[$#>%]|\$\)|psftp>)\s?\Z")


@dataclass
class InteractiveSession:
    """Wraps a Popen process with a background reader and bounded output buffer.

    Output is read in chunks (not lines) so prompts without a trailing newline
    show up immediately. Positions are absolute character counts, so mark()
    and read_since() keep working after old output is trimmed.
    """

    session_id: str
    process: subprocess.Popen
    host: str
    protocol: str
    created_at: float
    metadata: dict[str, Any] = field(default_factory=dict)
    last_activity: float = field(default_factory=time.time)

    _text: str = ""
    _total_chars: int = 0  # characters ever received
    _last_output: float = 0.0
    _buffer_lines: int = 1000
    _reader_thread: threading.Thread | None = field(default=None, repr=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def start_reader(self, buffer_lines: int = 1000) -> None:
        """Start background thread reading stdout."""
        self._buffer_lines = buffer_lines
        self._reader_thread = threading.Thread(
            target=self._read_loop, daemon=True, name=f"reader-{self.session_id[:8]}"
        )
        self._reader_thread.start()

    def _read_loop(self) -> None:
        stdout = self.process.stdout
        if stdout is None:
            return
        raw = getattr(stdout, "buffer", stdout)  # binary stream under the text wrapper
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while not self._stop_event.is_set():
                chunk = raw.read1(65536) if hasattr(raw, "read1") else raw.read(1)
                if not chunk:
                    break
                text = decoder.decode(chunk) if isinstance(chunk, bytes) else chunk
                if text:
                    self._append(text)
        except (ValueError, OSError):
            pass  # pipe closed

    def _append(self, text: str) -> None:
        with self._lock:
            self._text += text
            self._total_chars += len(text)
            self._last_output = time.time()
            if self._text.count("\n") > self._buffer_lines:
                self._text = "".join(self._text.splitlines(keepends=True)[-self._buffer_lines:])

    def send(self, text: str) -> None:
        """Send text to the process stdin."""
        if self.process.stdin is None:
            raise RuntimeError("Session stdin not available")
        if self.process.poll() is not None:
            raise RuntimeError("Session process has exited")
        self.process.stdin.write(text)
        self.process.stdin.flush()
        self.last_activity = time.time()

    def read(self, last_n: int | None = None, clear: bool = False) -> str:
        """Read the output buffer, optionally only the last N lines and/or clear it."""
        self.last_activity = time.time()
        with self._lock:
            text = self._text
            if clear:
                self._text = ""
        if last_n:
            text = "".join(text.splitlines(keepends=True)[-last_n:])
        return text

    def mark(self) -> int:
        """Current output position, for read_since()."""
        with self._lock:
            return self._total_chars

    def read_since(self, mark: int) -> str:
        """Output received after mark(), without clearing the buffer."""
        self.last_activity = time.time()
        with self._lock:
            new = self._total_chars - mark
            if new <= 0:
                return ""
            return self._text[-new:] if new < len(self._text) else self._text

    def wait_for_output(
        self,
        mark: int,
        max_wait: float,
        quiet: float = 2.0,
        expect: re.Pattern[str] | None = None,
        clean: Callable[[str], str] = lambda t: t,
    ) -> tuple[str, str]:
        """Wait until output after mark settles. Returns (output, reason).

        reason: "expect" (pattern matched), "prompt" (output ends in something
        that looks like a shell prompt and paused briefly), "quiet" (no new
        output for `quiet` seconds), "exited" or "timeout".
        """
        deadline = time.time() + max_wait
        while True:
            out = self.read_since(mark)
            if expect is not None and expect.search(clean(out)):
                return out, "expect"
            if not self.alive:
                time.sleep(0.1)  # let the reader drain the pipe
                return self.read_since(mark), "exited"
            with self._lock:
                last = self._last_output
            if expect is None and out:
                idle = time.time() - last
                if idle >= 0.3 and _PROMPT.search(clean(out)):
                    return out, "prompt"
                if idle >= quiet:
                    return out, "quiet"
            if time.time() >= deadline:
                return out, "timeout"
            time.sleep(0.05)

    def peek(self, last_chars: int) -> str:
        """Return the end of the buffer without counting as activity."""
        with self._lock:
            return self._text[-last_chars:]

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_activity

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
                    "idle_seconds": round(s.idle_seconds, 1),
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
            # Process already exited, so close() only releases the pipes
            self._sessions.pop(sid).close()

    def _cleanup_loop(self) -> None:
        """Periodically close sessions idle for longer than timeout_seconds."""
        while not self._stop_event.wait(60):
            with self._lock:
                timed_out = [
                    sid
                    for sid, s in self._sessions.items()
                    if s.idle_seconds > self.timeout_seconds
                ]
            for sid in timed_out:
                log.info("Session %s timed out, closing", sid)
                self.close(sid)

    def shutdown(self) -> None:
        """Shut down the manager and all sessions."""
        self._stop_event.set()
        self.close_all()
