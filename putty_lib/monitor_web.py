"""Local web dashboard: the operator's interface to the server.

Serves a single page on 127.0.0.1 with live activity, approvals, passphrase
prompts, settings and the audit log. Access requires a random token that is
part of the URL; API requests must carry it in a header, so other websites
can't read the dashboard or press its buttons (CSRF), and the Host header is
checked against DNS rebinding.
"""

from __future__ import annotations

import json
import logging
import secrets
import threading
import time
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from putty_lib.approvals import ApprovalQueue
from putty_lib.audit import AuditLog
from putty_lib.monitor import Monitor
from putty_lib.settings import DEFAULT_COMMAND_RULES, Settings, SettingsStore

if TYPE_CHECKING:
    from putty_lib.config import PuTTYConfig

log = logging.getLogger(__name__)

_PAGE = Path(__file__).with_name("monitor.html")
_MAX_BODY = 1_000_000


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
    ) -> None:
        self.monitor = monitor
        self.approvals = approvals
        self.settings = settings
        self.audit = audit
        self.config = config
        self.token = secrets.token_urlsafe(24)
        self._opened = False
        self._open_lock = threading.Lock()
        self._last_seen = 0.0
        handler = _make_handler(self)
        try:
            self.httpd = ThreadingHTTPServer((host, port), handler)
        except OSError:
            # Port taken (e.g. a second MCP client runs its own server):
            # fall back to any free port.
            self.httpd = ThreadingHTTPServer((host, 0), handler)
        self.httpd.daemon_threads = True
        self.host, self.port = self.httpd.server_address[:2]
        self._allowed_hosts = {f"{h}:{self.port}" for h in ("127.0.0.1", "localhost", str(self.host))}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.token}"

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="monitor-web").start()
        log.info("Monitor dashboard: %s", self.url)

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
                    return self._send(403, b"Missing or invalid token. Use the URL from the server log.",
                                      "text/plain")
                return self._send(200, _PAGE.read_bytes(), "text/html; charset=utf-8")
            if not self._header_token_ok():
                return self._json({"error": "forbidden"}, 403)

            if url.path == "/api/state":
                server.seen()
                since = int(query.get("since", ["0"])[0] or 0)
                state = monitor.snapshot(since=since)
                state["approvals"] = server.approvals.pending()
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
