"""Local web dashboard: the operator's interface to the server.

Serves a single page on 127.0.0.1 with live activity, approvals, passphrase
prompts, settings and the audit log. Access requires a random token that is
part of the URL; API requests must carry it in a header, so other websites
can't read the dashboard or press its buttons (CSRF), and the Host header is
checked against DNS rebinding.

The token is stored in the data directory (owner-only) so the dashboard link
and open tabs keep working when the server restarts; the operator can reset
it from the Settings tab.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
import time
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from putty_lib import __version__
from putty_lib.approvals import ApprovalQueue
from putty_lib.audit import AuditLog
from putty_lib.monitor import Monitor
from putty_lib.settings import DEFAULT_COMMAND_RULES, Settings, SettingsStore

if TYPE_CHECKING:
    from putty_lib.config import PuTTYConfig

log = logging.getLogger(__name__)

_PAGE = Path(__file__).with_name("monitor.html")
_MAX_BODY = 1_000_000
try:
    from importlib.metadata import version as _pkg_version

    _MCP_VERSION = _pkg_version("mcp")
except Exception:  # noqa: BLE001 - informational only
    _MCP_VERSION = "?"

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")

_INVALID_TOKEN_PAGE = b"""<!doctype html><meta charset="utf-8"><title>PuTTY MCP</title>
<body style="font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px">
<h1 style="font-size:20px">This dashboard link is not valid</h1>
<p>The PuTTY MCP server on this port does not accept this link. Usually the link is from
before the dashboard link was reset, or another PuTTY MCP server answers on this port.</p>
<p>Open the dashboard from the tab the server opens on its first tool call, or copy the
"Monitor dashboard" URL from the MCP server log.</p></body>"""


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    if sys.platform == "win32":
        # On Windows SO_REUSEADDR lets a second process listen on the same
        # port, so requests could reach another server instance. Claim the
        # port exclusively instead; a second instance falls back to a free port.
        allow_reuse_address = False

        def server_bind(self) -> None:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()


def _load_token(path: Path | None) -> str:
    """Reuse the stored token, or create and store a new one."""
    if path is not None:
        try:
            token = path.read_text(encoding="ascii").strip()
            if _TOKEN_RE.match(token):
                return token
        except (OSError, UnicodeDecodeError):
            pass
    return _store_token(path, secrets.token_urlsafe(32))


def _store_token(path: Path | None, token: str) -> str:
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(token)
            os.replace(tmp, path)
        except OSError as e:
            log.warning("Could not store dashboard token in %s: %s", path, e)
    return token


class MonitorServer:
    def __init__(
        self,
        monitor: Monitor,
        approvals: ApprovalQueue,
        settings: SettingsStore,
        audit: AuditLog,
        config: PuTTYConfig,
        host: str = "127.0.0.1",
        port: int = 8765,
        token_file: Path | None = None,
    ) -> None:
        self.monitor = monitor
        self.approvals = approvals
        self.settings = settings
        self.audit = audit
        self.config = config
        self.token_file = token_file
        self.token = _load_token(token_file)
        self._opened = False
        self._open_lock = threading.Lock()
        self._last_seen = 0.0
        handler = _make_handler(self)
        try:
            self.httpd = _Server((host, port), handler)
        except OSError:
            # Port taken (e.g. a second MCP client runs its own server):
            # fall back to any free port.
            self.httpd = _Server((host, 0), handler)
        self.host, self.port = self.httpd.server_address[:2]
        self._allowed_hosts = {f"{h}:{self.port}" for h in ("127.0.0.1", "localhost", str(self.host))}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.token}"

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="monitor-web").start()
        log.info("Monitor dashboard: %s", self.url)

    def reset_token(self) -> str:
        """Invalidate the current dashboard link and return the new URL."""
        self.token = _store_token(self.token_file, secrets.token_urlsafe(32))
        self.monitor.note("Dashboard link was reset")
        return self.url

    def seen(self) -> None:
        self._last_seen = time.time()

    def recently_viewed(self, within: float = 5.0) -> bool:
        """True if a dashboard tab polled recently."""
        return time.time() - self._last_seen < within

    def open_browser(self, force: bool = False) -> None:
        """Open the dashboard (once per run, unless force)."""
        with self._open_lock:
            if self._opened and not force:
                return
            self._opened = True
        try:
            webbrowser.open(self.url)
        except Exception as e:  # noqa: BLE001 - never let this break a tool call
            log.warning("Could not open browser for monitor: %s", e)

    def stop(self) -> None:
        self.httpd.shutdown()

    # -- data for the page ---------------------------------------------------

    def settings_payload(self) -> dict[str, Any]:
        from putty_lib.settings import data_dir

        return {
            "settings": self.settings.current.to_dict(),
            "defaults": {"command_rules": DEFAULT_COMMAND_RULES, **{
                k: v for k, v in asdict(Settings()).items() if k != "command_rules"}},
            "executables": self.config.validate(),
            "data_dir": str(data_dir()),
            "settings_file": str(self.settings.path),
            "audit_dir": str(self.audit.directory),
            "dashboard": f"http://{self.host}:{self.port}/",
            "version": __version__,
        }


def _make_handler(server: MonitorServer) -> type[BaseHTTPRequestHandler]:
    monitor = server.monitor

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # keep stderr quiet; polling would flood it

        # -- helpers -------------------------------------------------------

        def _host_ok(self) -> bool:
            # Rejects DNS-rebinding requests that arrive with a foreign Host
            return self.headers.get("Host", "") in server._allowed_hosts

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: Any, status: int = 200) -> None:
            self._send(status, json.dumps(data, default=str).encode(), "application/json")

        def _header_token_ok(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Monitor-Token", ""), server.token)

        def _body(self) -> dict[str, Any] | None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > _MAX_BODY:
                return None
            try:
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except ValueError:
                return None
            return body if isinstance(body, dict) else None

        # -- routes --------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._send(403, b"Forbidden", "text/plain")
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if url.path == "/":
                token = query.get("token", [""])[0]
                if not secrets.compare_digest(token, server.token):
                    return self._send(403, _INVALID_TOKEN_PAGE, "text/html; charset=utf-8")
                return self._send(200, _PAGE.read_bytes(), "text/html; charset=utf-8")
            if not self._header_token_ok():
                return self._json({"error": "forbidden"}, 403)

            if url.path == "/api/state":
                server.seen()
                if server.settings.end_pause():
                    monitor.note(f"Approval pause ended; asking again ({server.settings.current.approval_mode})")
                since = int(query.get("since", ["0"])[0] or 0)
                state = monitor.snapshot(since=since)
                state["approvals"] = server.approvals.pending()
                state["version"] = __version__
                state["now"] = time.time()
                state["mcp_version"] = _MCP_VERSION
                current = server.settings.current
                state["approvals_paused_until"] = current.approval_off_until if current.approval_mode == "off" else None
                state["approval_mode_after_pause"] = current.approval_mode_before_off
                return self._json(state)
            if url.path == "/api/settings":
                return self._json(server.settings_payload())
            if url.path == "/api/audit/days":
                return self._json({"days": server.audit.days(), "directory": str(server.audit.directory)})
            if url.path == "/api/audit":
                return self._json({"events": server.audit.read(query.get("day", [""])[0])})
            self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok() or not self._header_token_ok():
                return self._json({"error": "forbidden"}, 403)
            body = self._body()
            if body is None:
                return self._json({"error": "invalid request body"}, 400)

            path = urlparse(self.path).path
            if path == "/api/kill":
                return self._json({"killed": monitor.kill(str(body.get("proc_id", "")))})
            if path == "/api/kill_all":
                return self._json({"killed": monitor.kill_all(lock=True)})
            if path == "/api/lock":
                monitor.set_locked(bool(body.get("locked")), reason="blocked by operator")
                return self._json({"locked": monitor.locked})
            if path == "/api/approvals/resume":
                ended = server.settings.end_pause(force=True)
                if ended:
                    monitor.note(f"Approval pause cancelled by operator; asking again "
                                 f"({server.settings.current.approval_mode})")
                return self._json({"resumed": ended})
            if path == "/api/token/reset":
                return self._json({"url": server.reset_token()})
            if path == "/api/approve":
                remember = body.get("remember") or []
                ok = server.approvals.decide(
                    str(body.get("approval_id", "")),
                    bool(body.get("approved")),
                    remember=[str(r) for r in remember] if isinstance(remember, list) else [],
                    secret=body.get("secret") if isinstance(body.get("secret"), str) else None,
                )
                return self._json({"ok": ok}, 200 if ok else 409)
            if path == "/api/settings":
                changes = body.get("changes")
                if not isinstance(changes, dict):
                    return self._json({"error": "changes must be an object"}, 400)
                try:
                    server.settings.update(changes)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                return self._json(server.settings_payload())
            self._json({"error": "not found"}, 404)

    return Handler
