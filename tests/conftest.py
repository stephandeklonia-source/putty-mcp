"""Shared fixtures. PUTTY_MCP_HOME must be set before putty_mcp is imported."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_HOME = Path(tempfile.mkdtemp(prefix="putty-mcp-test-"))
os.environ["PUTTY_MCP_HOME"] = str(_HOME)
(_HOME / "settings.json").write_text(json.dumps({"open_browser": "never"}))

FAKE_PLINK = str(Path(__file__).with_name("fake_plink.py"))


@pytest.fixture(scope="session")
def server():
    import putty_mcp

    return putty_mcp


@pytest.fixture
def m(server, monkeypatch, tmp_path):
    """The server with fake PuTTY tools and permissive, clean settings."""
    real = server.config.command_for

    def fake(tool: str) -> list[str]:
        if tool in ("plink", "pscp", "psftp", "putty", "pageant"):
            return [sys.executable, FAKE_PLINK]
        return real(tool)

    monkeypatch.setattr(server.config, "command_for", fake)
    server.monitor.set_locked(False)
    server.approvals.deny_all("test reset")
    server.sessions.close_all()
    from putty_lib.settings import Settings

    defaults = Settings().to_dict()
    defaults.update(open_browser="never", allowed_hosts=["*"], allowed_local_dirs=[str(tmp_path)],
                    approval_timeout_seconds=10)
    server.settings_store.update(defaults)
    return server


def call(m, name: str, args: dict):
    """Call a tool like an MCP client would; returns the parsed JSON result."""
    r = asyncio.run(m.mcp.call_tool(name, args))
    r = r[0] if isinstance(r, tuple) else r
    content = r.content if hasattr(r, "content") else r
    return json.loads(content[0].text)


def tool_error_type(m):
    return m.ToolError


class Dashboard:
    """Talks to the monitor's HTTP API like the page does."""

    def __init__(self, m) -> None:
        self.srv = m.monitor_server
        self.base = f"http://127.0.0.1:{self.srv.port}"

    def request(self, path: str, body=None, headers=None):
        hdrs = {"X-Monitor-Token": self.srv.token, "Content-Type": "application/json"}
        if headers is not None:
            hdrs = headers
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=hdrs,
            method="POST" if body is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw)
        except urllib.error.HTTPError as e:
            return e.code, None

    def get(self, path: str):
        return self.request(path)[1]

    def post(self, path: str, body):
        return self.request(path, body)[1]

    def wait_approval(self, timeout: float = 10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            pending = self.get("/api/state")["approvals"]
            if pending:
                return pending[0]
            time.sleep(0.05)
        raise AssertionError("no approval appeared")

    def answer(self, approved: bool, remember_all: bool = False, secret: str | None = None, kind: str | None = None):
        a = self.wait_approval()
        if kind:
            assert a["kind"] == kind, a
        body = {"approval_id": a["approval_id"], "approved": approved, "secret": secret,
                "remember": [o["id"] for o in a["options"]] if remember_all else []}
        assert self.post("/api/approve", body)["ok"]
        return a


@pytest.fixture
def dash(server):
    return Dashboard(server)


def in_thread(fn, *args):
    """Run fn in a thread; returns (thread, result box)."""
    box: dict = {}

    def run():
        try:
            box["value"] = fn(*args)
        except Exception as e:  # noqa: BLE001
            box["error"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, box
