import os

from putty_lib import policy
from putty_lib.settings import Settings


def decide(tool="plink_exec", session=None, **kwargs):
    s = kwargs.pop("settings", None) or Settings(allowed_hosts=["*.lan"], allowed_local_dirs=[])
    return policy.evaluate(s, tool, kwargs, session)


def test_allowed_unknown_and_blocked_hosts():
    assert decide(host="web.lan", command="ls").action == "allow"
    d = decide(host="web.example.com", command="ls")
    assert d.action == "ask" and d.options == [{"id": "host:web.example.com", "label": "Always allow host web.example.com"}]
    s = Settings(allowed_hosts=["*"], blocked_hosts=["*.prod.*"])
    assert decide(settings=s, host="db.prod.lan", command="ls").action == "deny"
    assert decide(settings=s, tool="chain_exec", target_host="ok", jump_hosts=["u@x.prod.y:22"], command="ls").action == "deny"


def test_command_rules():
    d = decide(host="web.lan", command="sudo rm -rf /var/www")
    assert d.action == "ask" and "recursive/forced delete" in d.reasons[0]
    assert decide(host="web.lan", command="ls -la; uptime").action == "allow"
    assert decide(host="web.lan", command=":(){ :|:& };:").action == "deny"
    assert decide(host="web.lan", command="SYSTEMCTL restart nginx").action == "ask"


def test_session_send_checks_command_but_not_host_again():
    s = Settings(allowed_hosts=[])
    assert decide(settings=s, tool="session_send", session_id="x", command="ls",
                  session={"host": "anything", "protocol": "ssh"}).action == "allow"
    assert decide(settings=s, tool="session_send", session_id="x", command="reboot",
                  session={"host": "anything", "protocol": "ssh"}).action == "ask"


def test_local_paths(tmp_path):
    s = Settings(allowed_hosts=["*"], allowed_local_dirs=[str(tmp_path)])
    inside = str(tmp_path / "a.txt")
    outside = os.path.join(os.path.expanduser("~"), ".ssh", "id_ed25519")
    assert decide(settings=s, tool="pscp_upload", host="h", local_path=inside, remote_path="/x").action == "allow"
    d = decide(settings=s, tool="pscp_upload", host="h", local_path=outside, remote_path="/x")
    assert d.action == "ask" and d.options[0]["id"].startswith("dir:")
    # sneaky relative path out of the allowed folder
    assert decide(settings=s, tool="pscp_upload", host="h", local_path=str(tmp_path / ".." / "x"),
                  remote_path="/x").action == "ask"


def test_psftp_local_paths(tmp_path):
    s = Settings(allowed_hosts=["*"], allowed_local_dirs=[str(tmp_path)])
    ok = decide(settings=s, tool="psftp_batch", host="h", commands=[f'put "{tmp_path / "f"}" /tmp/f', "ls"])
    assert ok.action == "allow"
    bad = decide(settings=s, tool="psftp_batch", host="h", commands=["get /etc/passwd /home/me/passwd"])
    assert bad.action == "ask"
    assert policy._psftp_local_paths("mget *.log") == ["."]


def test_proxy_command_and_risky_tools():
    assert decide(host="web.lan", command="ls", proxy_command="nc %host %port").action == "ask"
    assert decide(tool="saved_session_delete", session_name="x").action == "ask"


def test_approval_modes():
    allow_all = Settings(allowed_hosts=["*"], approval_mode="all")
    assert decide(settings=allow_all, host="h", command="ls").action == "ask"
    assert decide(settings=allow_all, tool="session_list").action == "allow"
    off = Settings(allowed_hosts=[], approval_mode="off")
    assert decide(settings=off, host="h", command="reboot").action == "allow"
    off.blocked_hosts = ["h"]
    assert decide(settings=off, host="h", command="ls").action == "deny"


def test_serial_port_is_not_a_host():
    assert decide(tool="session_open", host="COM3", protocol="serial").action == "allow"


def test_apply_remember():
    s = Settings()
    policy.apply_remember(s, ["host:web01", "dir:/data", "host:web01", "bogus:x"])
    assert s.allowed_hosts == ["web01"] and s.allowed_local_dirs == ["/data"]
