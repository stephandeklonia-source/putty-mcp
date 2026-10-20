"""The MCP server end to end, with a fake plink (runs on every OS)."""

import time

import pytest

from conftest import call, in_thread


def test_tools_are_registered(server):
    import asyncio

    assert len(asyncio.run(server.mcp.list_tools())) == 35


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


def test_shell_run_cisco_config_block(m):
    r = call(m, "shell_run", {"host": "ios-r1", "commands": [
        "configure terminal", "interface Gi0/1", "description uplink", "end",
        "show running-config", "copy running-config startup-config", "",
    ]})
    assert r["success"] and r["completed"] == r["total"] == 7, r
    finished = [x["finished"] for x in r["results"]]
    assert finished[:4] == ["prompt"] * 4
    assert "R1(config-if)#" in r["results"][1]["output"]
    # --More-- pages were skipped and cleaned up
    show = r["results"][4]["output"]
    assert all(f"line {i}" in show for i in range(9)) and "More" not in show and "\x08" not in show
    assert "[OK]" in r["results"][6]["output"]
    # the shell was closed afterwards
    assert all(s["protocol"] != "shell" for s in call(m, "session_list", {})["sessions"])


def test_shell_run_stops_on_device_error(m):
    r = call(m, "shell_run", {"host": "ios-r1", "commands": ["configure terminal", "bogus command", "end"]})
    assert r["success"] is False and r["completed"] == 2 and r["stopped"] == "error after: bogus command"
    assert r["results"][1]["error"]
    r = call(m, "shell_run", {"host": "ios-r1", "commands": ["bogus", "end"], "stop_on_error": False})
    assert r["completed"] == 2 and r["success"] is False


def test_shell_run_commands_go_through_policy(m, dash):
    t, box = in_thread(call, m, "shell_run", {"host": "ios-r1", "commands": ["show version", "reload"]})
    a = dash.answer(False, kind="tool")
    t.join(10)
    assert any("network device reload" in r for r in a["details"]["reasons"])
    assert "Not approved" in str(box["error"])


def test_plink_exec_multiline_on_ios_gets_hint(m):
    r = call(m, "plink_exec", {"host": "ios-r1", "command": "conf t\ninterface Gi0/1\nend"})
    assert r["success"] is False and "shell_run" in r["hint"]


def test_exited_session_is_explained_not_lost(m):
    sid = call(m, "session_open", {"host": "ios-r1"})["session_id"]
    call(m, "session_send", {"session_id": sid, "command": "exit"})
    time.sleep(0.5)
    r = call(m, "session_send", {"session_id": sid, "command": "show version"})
    assert r["success"] is False and r["alive"] is False and "ended" in r["error"]
    # opening another session does not make the ended one disappear
    call(m, "session_open", {"host": "shell-x"})
    assert call(m, "session_read", {"session_id": sid})["alive"] is False
    with pytest.raises(m.ToolError, match="Known sessions:.*shell_run"):
        call(m, "session_read", {"session_id": "doesnotexist"})


def _monitor_server(m, token_file, port=0):
    from putty_lib.monitor_web import MonitorServer

    return MonitorServer(m.monitor, m.approvals, m.settings_store, m.audit, m.config, port=port, token_file=token_file)


def test_dashboard_token_survives_restart_and_can_be_reset(m, tmp_path):
    import os
    import sys

    token_file = tmp_path / "dashboard-token"
    first = _monitor_server(m, token_file)
    second = _monitor_server(m, token_file)  # e.g. after a restart
    try:
        assert first.token == second.token and len(first.token) >= 32
        if sys.platform != "win32":
            assert oct(os.stat(token_file).st_mode & 0o777) == "0o600"
        old = first.token
        assert first.reset_token().endswith(first.token) and first.token != old
        assert _monitor_server(m, token_file).token == first.token
    finally:
        first.httpd.server_close()
        second.httpd.server_close()


def test_reset_link_via_dashboard(m, dash):
    old = dash.srv.token
    url = dash.post("/api/token/reset", {})["url"]
    assert dash.srv.token in url and dash.srv.token != old
    status, body = dash.request(f"/?token={old}", headers={})
    assert status == 403
    assert dash.request("/api/state", headers={"X-Monitor-Token": old})[0] == 403
    assert dash.get("/api/state")["locked"] is False  # the new token works


def test_second_server_cannot_share_the_port(m, tmp_path):
    first = _monitor_server(m, tmp_path / "t")
    try:
        second = _monitor_server(m, tmp_path / "t", port=first.port)
        try:
            assert second.port != first.port  # fell back to a free port
        finally:
            second.httpd.server_close()
    finally:
        first.httpd.server_close()


def test_net_check_tcp_banner_closed_port_and_ping(m):
    import shutil
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    open_port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_9.6 Prodigy-test\r\n")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    r = call(m, "net_check", {"host": "127.0.0.1", "ports": [open_port, closed_port], "count": 1})
    srv.close()
    tcp = {t["port"]: t for t in r["tcp"]}
    assert tcp[open_port]["state"] == "open" and tcp[open_port]["banner"].startswith("SSH-2.0-OpenSSH_9.6")
    assert tcp[closed_port]["state"] == "closed"
    assert r["reachable"]
    if shutil.which("ping"):
        assert "received" in r["ping"]
    else:
        assert "not available" in r["ping"]["error"]


def test_net_check_rejects_bad_input(m):
    with pytest.raises(m.ToolError, match="Not a valid host"):
        call(m, "net_check", {"host": "-c 1000 example.com"})
    with pytest.raises(m.ToolError, match="not a port scanner"):
        call(m, "net_check", {"host": "127.0.0.1", "ports": list(range(1, 30))})
    r = call(m, "net_check", {"host": "no-such-host.invalid", "ping": False})
    assert r["reachable"] is False and "resolution failed" in r["error"]


def test_net_check_respects_host_policy(m, dash):
    m.settings_store.update({"allowed_hosts": []})
    t, box = in_thread(call, m, "net_check", {"host": "127.0.0.1", "ping": False, "ports": [9]})
    a = dash.answer(False, kind="tool")
    t.join(10)
    assert "not on the allowed list" in a["details"]["reasons"][0]


def test_ttssh_trust_key_then_run_with_approvals(m, dash):
    import hashlib

    host = "10.8.100.10"
    fp = "SHA1:" + hashlib.sha1(host.encode()).hexdigest()
    t, box = in_thread(call, m, "ttssh_run", {"host": host, "commands": ["ver", "ls /"]})
    a = dash.answer(True, kind="tool")  # default: every Prodigy command needs approval
    assert "every command needs approval" in a["details"]["reasons"][0]
    k = dash.answer(True, kind="hostkey")
    t.join(20)
    assert k["details"]["fingerprint"] == fp
    r = box["value"]
    assert r["success"] and r["completed"] == 2, r
    assert "Prodigy firmware 6.2.1" in r["results"][0]["output"]
    assert m.current().trusted_host_keys[f"ttssh/{host}"] == [fp]
    # the controller session was closed afterwards
    assert all(s["protocol"] != "ttssh" for s in call(m, "session_list", {})["sessions"])


def test_ttssh_readonly_auto_mode(m, dash):
    import hashlib

    host = "prodigy-2"
    m.settings_store.update({"ttssh_approval": "readonly_auto", "trusted_host_keys": {
        f"ttssh/{host}": ["SHA1:" + hashlib.sha1(host.encode()).hexdigest()]}})
    r = call(m, "ttssh_run", {"host": host, "commands": ["ver", "date", "help"]})
    assert r["success"]  # read-only: no approval needed
    t, box = in_thread(call, m, "ttssh_run", {"host": host, "commands": ["ver", "reboot"]})
    a = dash.answer(False, kind="tool")
    t.join(10)
    assert "not a read-only command: reboot" in " ".join(a["details"]["reasons"])
    assert "Not approved" in str(box["error"])


def test_ttssh_changed_key_is_refused_before_any_command(m, dash):
    m.settings_store.update({"ttssh_approval": "rules",
                             "trusted_host_keys": {"ttssh/10.8.100.10": ["SHA1:" + "0" * 40]}})
    with pytest.raises(m.ToolError, match="SECURITY"):
        call(m, "ttssh_run", {"host": "10.8.100.10", "commands": ["ver"]})
    assert any(e["kind"] == "alert" and "Prodigy" in e["message"] for e in dash.get("/api/state")["events"])


def test_ttssh_session_and_failures(m, dash):
    import hashlib

    host = "prodigy-3"
    m.settings_store.update({"ttssh_approval": "rules", "trusted_host_keys": {
        f"ttssh/{host}": ["SHA1:" + hashlib.sha1(host.encode()).hexdigest()]}})
    sid = call(m, "ttssh_open", {"host": host})["session_id"]
    r = call(m, "session_send", {"session_id": sid, "command": "ver"})
    assert r["finished"] == "prompt" and "6.2.1" in r["output"]
    call(m, "session_close", {"session_id": sid})
    with pytest.raises(m.ToolError, match="did not reach its prompt"):
        call(m, "ttssh_open", {"host": "down", "connect_timeout": 5})
    with pytest.raises(m.ToolError, match="Not a valid host"):
        call(m, "ttssh_run", {"host": "-x 1.2.3.4", "commands": ["ver"]})


def test_approval_pause_countdown_and_cancel(m, dash):
    m.settings_store.update({"allowed_hosts": []})
    payload = dash.post("/api/settings", {"changes": {"approval_mode": "off", "approval_off_minutes": 5}})
    assert payload["settings"]["approval_mode"] == "off"
    state = dash.get("/api/state")
    assert 4 * 60 < state["approvals_paused_until"] - state["now"] <= 5 * 60
    # paused: an unknown host runs without asking
    assert call(m, "plink_exec", {"host": "anyhost", "command": "ls"})["success"]
    # cancel from the dashboard: asking again immediately
    assert dash.post("/api/approvals/resume", {})["resumed"]
    assert dash.get("/api/state")["approvals_paused_until"] is None
    t, box = in_thread(call, m, "plink_exec", {"host": "otherhost", "command": "ls"})
    dash.answer(False, kind="tool")
    t.join(10)
    assert "Not approved" in str(box["error"])


def test_approval_pause_expires_by_itself(m, dash):
    import time

    m.settings_store.update({"allowed_hosts": [], "approval_mode": "off"})
    m.settings_store._settings.approval_off_until = time.time() - 1  # time is up
    t, box = in_thread(call, m, "plink_exec", {"host": "anyhost", "command": "ls"})
    dash.answer(True, kind="tool")
    t.join(10)
    assert box["value"]["success"] and m.current().approval_mode == "risky"
    assert any("pause ended" in (e.get("message") or "") for e in dash.get("/api/state")["events"])


def test_long_output_can_be_read_in_parts(m):
    import hashlib

    host = "prodigy-debug"
    m.settings_store.update({"ttssh_approval": "rules", "trusted_host_keys": {
        f"ttssh/{host}": ["SHA1:" + hashlib.sha1(host.encode()).hexdigest()]}})
    r = call(m, "ttssh_run", {"host": host, "commands": ["debug"]})
    cmd = r["results"][0]
    assert "[00000] boot" in cmd["output"]  # the start is kept (not lost to the rolling buffer)
    assert "EtherCAT" not in cmd["output"]  # the middle was cut ...
    assert "output_read(output_id=" in cmd["output"] and cmd["output_id"]
    # ... but the full text can be searched
    found = call(m, "output_read", {"output_id": cmd["output_id"], "grep": "EtherCAT|IOP|IBS", "context_lines": 1})
    assert found["matches"] == 3 and "IOP-16DI" in found["results"][1]["text"]
    # and paged through from an offset
    page = call(m, "output_read", {"output_id": cmd["output_id"], "offset": found["results"][0]["offset"], "length": 200})
    assert page["text"].startswith("[00700] EtherCAT: bus scan started") and page["more"]
    with pytest.raises(m.ToolError, match="not found"):
        call(m, "output_read", {"output_id": "o999999"})


def test_plain_output_also_gets_an_output_id(m):
    r = call(m, "plink_exec", {"host": "web", "command": "big-output"})
    oid = r["full_output_ids"]["stdout"]
    assert call(m, "output_read", {"output_id": oid, "length": 50})["total_chars"] > 100_000


def test_never_used_sessions_are_cleaned_up(m, monkeypatch):
    from putty_lib import session_manager

    sid = call(m, "session_open", {"host": "shell-orphan"})["session_id"]
    used = call(m, "session_open", {"host": "shell-used"})["session_id"]
    call(m, "session_send", {"session_id": used, "command": "hi"})
    monkeypatch.setattr(session_manager, "UNUSED_SESSION_SECONDS", 0)
    closed = m.sessions.cleanup_once()
    assert sid in closed and used not in closed
