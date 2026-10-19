"""The MCP server end to end, with a fake plink (runs on every OS)."""

import time

import pytest

from conftest import call, in_thread


def test_tools_are_registered(server):
    import asyncio

    assert len(asyncio.run(server.mcp.list_tools())) == 30


def test_exec_and_output_cleanup(m):
    assert call(m, "plink_exec", {"host": "web", "command": "uptime"})["stdout"].strip() == "ran: uptime"
    assert call(m, "plink_exec", {"host": "web", "command": "color"})["stdout"].strip() == "green text"
    big = call(m, "plink_exec", {"host": "web", "command": "big-output"})["stdout"]
    assert len(big) < 25_000 and "omitted" in big


def test_dashboard_requires_token_and_local_host(m, dash):
    assert dash.request("/api/state", headers={})[0] == 403
    assert dash.request("/", headers={})[0] == 403
    assert dash.request("/api/state", headers={"X-Monitor-Token": dash.srv.token,
                                               "Host": f"evil.com:{dash.srv.port}"})[0] == 403
    assert dash.request("/api/kill_all", {}, headers={"Content-Type": "application/json"})[0] == 403
    assert dash.request(f"/?token={dash.srv.token}", headers={})[0] == 200


def test_unknown_host_needs_approval_and_remember(m, dash):
    m.settings_store.update({"allowed_hosts": []})
    t, box = in_thread(call, m, "plink_exec", {"host": "newbox", "command": "ls"})
    a = dash.answer(True, remember_all=True, kind="tool")
    t.join(10)
    assert box["value"]["stdout"].strip() == "ran: ls"
    assert "host newbox is not on the allowed list" in a["details"]["reasons"]
    assert m.current().allowed_hosts == ["newbox"]
    # remembered: no approval this time
    assert call(m, "plink_exec", {"host": "newbox", "command": "ls"})["success"]


def test_denied_and_policy_blocked_calls(m, dash):
    t, box = in_thread(call, m, "plink_exec", {"host": "web", "command": "rm -rf /srv"})
    dash.answer(False, kind="tool")
    t.join(10)
    assert "Not approved by the operator" in str(box["error"])
    m.settings_store.update({"blocked_hosts": ["web"]})
    with pytest.raises(m.ToolError, match="safety policy"):
        call(m, "plink_exec", {"host": "web", "command": "ls"})


def test_unknown_host_key_trust_flow(m, dash):
    t, box = in_thread(call, m, "plink_exec", {"host": "unknown-key", "command": "ls"})
    a = dash.answer(True, kind="hostkey")
    t.join(10)
    assert a["details"]["fingerprint"].startswith("SHA256:K4g+")
    assert box["value"]["stdout"].strip() == "ran: ls"
    assert m.current().trusted_host_keys == {"unknown-key:22": ["SHA256:K4g+sYHWnUD2AzQJKOsFCD5LAIUb7p7kdzG89AvEeic"]}
    assert call(m, "plink_exec", {"host": "unknown-key", "command": "ls"})["success"]


def test_rejected_host_key_and_mismatch_alert(m, dash):
    t, box = in_thread(call, m, "plink_exec", {"host": "unknown-key", "command": "ls"})
    dash.answer(False, kind="hostkey")
    t.join(10)
    assert box["value"]["success"] is False and "did not trust" in box["value"]["hostkey"]

    m.settings_store.update({"trusted_host_keys": {"unknown-key:22": ["SHA256:" + "A" * 43]}})
    r = call(m, "plink_exec", {"host": "unknown-key", "command": "ls"})
    assert r["success"] is False and r["hostkey"].startswith("SECURITY")
    assert any(e["kind"] == "alert" for e in dash.get("/api/state")["events"])


def test_interactive_session_smart_wait(m):
    sid = call(m, "session_open", {"host": "shell-1"})["session_id"]
    r = call(m, "session_send", {"session_id": sid, "command": "hello"})
    assert r["finished"] == "prompt" and "out: HELLO" in r["output"]
    r = call(m, "session_send", {"session_id": sid, "command": "sleep 1"})
    assert r["finished"] == "prompt" and "out: SLEEP 1" in r["output"]
    r = call(m, "session_send", {"session_id": sid, "command": "x", "expect": "out: X"})
    assert r["finished"] == "expect"
    # full history stays available
    assert "out: HELLO" in call(m, "session_read", {"session_id": sid})["output"]
    assert call(m, "session_close", {"session_id": sid})["closed"]


def test_kill_single_command_and_kill_all(m, dash):
    t, box = in_thread(call, m, "plink_exec", {"host": "web", "command": "spawn-child", "timeout": 60})
    for _ in range(100):
        procs = dash.get("/api/state")["processes"]
        if procs:
            break
        time.sleep(0.05)
    started = time.time()
    assert dash.post("/api/kill", {"proc_id": procs[0]["proc_id"]})["killed"]
    t.join(10)
    assert box["value"]["killed_by_operator"] and time.time() - started < 10

    call(m, "session_open", {"host": "shell-2"})
    call(m, "plink_tunnel", {"host": "web", "local_forwards": ["8080:localhost:80"]})
    assert dash.post("/api/kill_all", {})["killed"] == 2
    state = dash.get("/api/state")
    assert state["locked"] and state["processes"] == [] and state["sessions"] == []
    with pytest.raises(m.ToolError, match="Blocked by operator"):
        call(m, "plink_exec", {"host": "web", "command": "ls"})
    dash.post("/api/lock", {"locked": False})
    assert call(m, "plink_exec", {"host": "web", "command": "ls"})["success"]


def test_kill_all_denies_pending_approvals(m, dash):
    m.settings_store.update({"allowed_hosts": []})
    t, box = in_thread(call, m, "plink_exec", {"host": "other", "command": "ls"})
    dash.wait_approval()
    dash.post("/api/kill_all", {})
    t.join(10)
    assert "kill switch" in str(box["error"])


def test_keygen_passphrase_from_dashboard_never_logged(m, dash, tmp_path):
    out = str(tmp_path / "id_test")
    t, box = in_thread(call, m, "keygen_create", {"output_path": out, "protect_with_passphrase": True})
    dash.answer(True, secret="correct horse battery", kind="secret")
    t.join(30)
    r = box["value"]
    assert r["encrypted"] and open(out + ".ppk").read().count("aes256-cbc") == 1
    from putty_lib import keys

    keys.load_private(out, "correct horse battery")
    # convert keeps the passphrase (asked again in the dashboard)
    t, box = in_thread(call, m, "keygen_convert", {"input_path": out, "output_path": out + "2.ppk"})
    dash.answer(True, secret="correct horse battery", kind="secret")
    t.join(30)
    assert box["value"]["encrypted"]
    fp = call(m, "keygen_fingerprint", {"key_path": out})["fingerprint"]
    assert fp == r["fingerprint"]
    day = dash.get("/api/audit/days")["days"][0]
    audit = str(dash.get(f"/api/audit?day={day}"))
    assert "correct horse battery" not in audit and "keygen_create" in audit


def test_local_path_approval(m, dash, tmp_path):
    m.settings_store.update({"allowed_local_dirs": []})
    t, box = in_thread(call, m, "pscp_upload", {"local_path": str(tmp_path / "f"), "remote_path": "/x", "host": "web"})
    a = dash.answer(True, remember_all=True, kind="tool")
    t.join(10)
    assert a["options"][0]["id"].startswith("dir:")
    assert len(m.current().allowed_local_dirs) == 1


def test_settings_api(m, dash):
    status, _ = dash.request("/api/settings", {"changes": {"max_output_chars": 5}})
    assert status == 400
    payload = dash.post("/api/settings", {"changes": {"max_concurrent": 3}})
    assert payload["settings"]["max_concurrent"] == 3 and m.sessions.max_concurrent == 3
    assert "plink" in payload["executables"]


def test_tool_errors_keep_their_message(m):
    with pytest.raises(m.ToolError, match="Session 'nope' not found"):
        call(m, "session_read", {"session_id": "nope"})


def test_tunnel_options_come_before_host(m, dash):
    call(m, "plink_tunnel", {"host": "web", "nc_destination": "db:5432"})
    label = [e for e in dash.get("/api/state")["events"]
             if e["kind"] == "process" and e["status"] == "started"][-1]["label"]
    assert label.index("-nc db:5432") < label.index(" web")
