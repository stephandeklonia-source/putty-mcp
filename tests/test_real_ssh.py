"""Against a real sshd with real plink. Skipped unless both are installed."""

import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from conftest import call, in_thread

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not (SSHD and shutil.which("plink") and shutil.which("ssh-keygen")),
    reason="needs sshd, plink and ssh-keygen",
)


@pytest.fixture(scope="module")
def sshd(tmp_path_factory):
    from putty_lib import keys

    d = tmp_path_factory.mktemp("sshd")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "hostkey")], check=True)
    client = keys.generate()
    keys.write_ppk(str(d / "client.ppk"), client, "client", None)
    keys.write_public(str(d / "authorized_keys"), client, "client")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    (d / "sshd_config").write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {d / 'hostkey'}\nPidFile {d / 'pid'}\n"
        f"AuthorizedKeysFile {d / 'authorized_keys'}\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nStrictModes no\nUsePAM no\nPermitRootLogin yes\n"
    )
    os.makedirs("/run/sshd", exist_ok=True)
    proc = subprocess.Popen([SSHD, "-D", "-f", str(d / "sshd_config"), "-E", str(d / "log")])
    time.sleep(1)
    fp = subprocess.run(["ssh-keygen", "-lf", str(d / "hostkey.pub")], capture_output=True, text=True).stdout.split()[1]
    yield {"port": port, "key": str(d / "client.ppk"), "fp": fp, "dir": d}
    proc.terminate()


@pytest.fixture
def real(server, sshd, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))  # empty PuTTY host key cache
    from putty_lib.settings import Settings

    s = Settings().to_dict()
    s.update(open_browser="never", allowed_local_dirs=[str(sshd["dir"])], approval_timeout_seconds=10)
    server.settings_store.update(s)
    server.monitor.set_locked(False)
    return server


def conn(sshd):
    import getpass

    return {"host": "127.0.0.1", "port": sshd["port"], "username": getpass.getuser(),
            "key_file": sshd["key"], "use_pageant": False}


def test_full_flow(real, sshd, dash):
    t, box = in_thread(call, real, "plink_exec", {**conn(sshd), "command": "echo hello"})
    dash.answer(True, remember_all=True, kind="tool")
    a = dash.answer(True, kind="hostkey")
    t.join(20)
    assert a["details"]["fingerprint"] == sshd["fp"]
    assert box["value"]["stdout"].strip() == "hello"
    # session with prompt detection
    sid = call(real, "session_open", conn(sshd))["session_id"]
    r = call(real, "session_send", {"session_id": sid, "command": "echo one; sleep 1; echo two"})
    assert "one" in r["output"] and "two" in r["output"]
    call(real, "session_close", {"session_id": sid})


def test_chain_through_jump_host(real, sshd):
    real.settings_store.update({"allowed_hosts": ["127.0.0.1", "localhost"],
                                "trusted_host_keys": {f"127.0.0.1:{sshd['port']}": [sshd["fp"]],
                                                      f"localhost:{sshd['port']}": [sshd["fp"]]}})
    import getpass

    user = getpass.getuser()
    r = call(real, "chain_exec", {
        "target_host": "localhost", "target_port": sshd["port"], "target_username": user,
        "key_file": sshd["key"], "command": "echo via-jump",
        "jump_hosts": [f"{user}@127.0.0.1:{sshd['port']}"],
    })
    assert r["stdout"].strip() == "via-jump", r


def test_shell_run_real(real, sshd):
    real.settings_store.update({"allowed_hosts": ["127.0.0.1"],
                                "trusted_host_keys": {f"127.0.0.1:{sshd['port']}": [sshd["fp"]]}})
    r = call(real, "shell_run", {**conn(sshd), "commands": ["cd /tmp", "pwd", "echo a; sleep 1; echo b", "false || echo recovered"]})
    assert r["success"], r
    assert "/tmp" in r["results"][1]["output"]
    assert "a" in r["results"][2]["output"] and "b" in r["results"][2]["output"]
