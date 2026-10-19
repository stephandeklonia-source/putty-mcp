"""Local web dashboard for the activity monitor.

Serves a single page on 127.0.0.1 that shows tool calls, running processes
and live session output, with kill buttons. Access requires a random token
that is part of the URL; POST requests must also carry it in a header, so
other websites can't trigger the kill switch (or undo it) via CSRF.
"""

from __future__ import annotations

import json
import logging
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from putty_lib.monitor import Monitor

log = logging.getLogger(__name__)

_PAGE = Path(__file__).with_name("monitor.html")


class MonitorServer:
    def __init__(self, monitor: Monitor, host: str = "127.0.0.1", port: int = 8765) -> None:
        self.monitor = monitor
        self.token = secrets.token_urlsafe(24)
        self._opened = False
        self._open_lock = threading.Lock()
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
        log.info("Activity monitor: %s", self.url)

    def open_browser(self) -> None:
        """Open the dashboard once per server run."""
        with self._open_lock:
            if self._opened:
                return
            self._opened = True
        try:
            webbrowser.open(self.url)
        except Exception as e:  # noqa: BLE001 - never let this break a tool call
            log.warning("Could not open browser for monitor: %s", e)

    def stop(self) -> None:
        self.httpd.shutdown()


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
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: Any, status: int = 200) -> None:
            self._send(status, json.dumps(data, default=str).encode(), "application/json")

        def _header_token_ok(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Monitor-Token", ""), server.token)

        # -- routes --------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._send(403, b"Forbidden", "text/plain")
            url = urlparse(self.path)
            if url.path == "/":
                token = parse_qs(url.query).get("token", [""])[0]
                if not secrets.compare_digest(token, server.token):
                    return self._send(403, b"Missing or invalid token. Use the URL from the server log.",
                                      "text/plain")
                return self._send(200, _PAGE.read_bytes(), "text/html; charset=utf-8")
            if url.path == "/api/state":
                if not self._header_token_ok():
                    return self._json({"error": "forbidden"}, 403)
                since = int(parse_qs(url.query).get("since", ["0"])[0] or 0)
                return self._json(monitor.snapshot(since=since))
            self._send(404, b"Not found", "text/plain")

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok() or not self._header_token_ok():
                return self._json({"error": "forbidden"}, 403)
            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except ValueError:
                return self._json({"error": "invalid JSON"}, 400)

            path = urlparse(self.path).path
            if path == "/api/kill":
                return self._json({"killed": monitor.kill(str(body.get("proc_id", "")))})
            if path == "/api/kill_all":
                return self._json({"killed": monitor.kill_all(lock=True)})
            if path == "/api/lock":
                monitor.set_locked(bool(body.get("locked")), reason="blocked by operator")
                return self._json({"locked": monitor.locked})
            self._json({"error": "not found"}, 404)

    return Handler
