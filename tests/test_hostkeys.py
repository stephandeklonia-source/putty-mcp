from putty_lib import hostkeys

UNKNOWN = """The host key is not cached for this server:
  127.0.0.1 (port 2222)
You have no guarantee that the server is the computer you
think it is.
The server's ssh-ed25519 key fingerprint is:
  ssh-ed25519 255 SHA256:K4g+sYHWnUD2AzQJKOsFCD5LAIUb7p7kdzG89AvEeic
Connection abandoned.
FATAL ERROR: Cannot confirm a host key in batch mode
"""


def test_detect_unknown_key():
    p = hostkeys.detect(UNKNOWN)
    assert p.kind == hostkeys.UNKNOWN
    assert p.fingerprint == "SHA256:K4g+sYHWnUD2AzQJKOsFCD5LAIUb7p7kdzG89AvEeic"
    assert p.key_line == "ssh-ed25519 255 SHA256:K4g+sYHWnUD2AzQJKOsFCD5LAIUb7p7kdzG89AvEeic"


def test_detect_mismatch():
    for text in ("FATAL ERROR: Host key not in manually configured list",
                 "WARNING - POTENTIAL SECURITY BREACH!",
                 "The host key does not match the one PuTTY has cached for this server"):
        assert hostkeys.detect(text).kind == hostkeys.MISMATCH


def test_no_problem():
    assert hostkeys.detect("Access granted\nhello") is None


def test_trusted_args():
    trusted = {"web:22": ["SHA256:a", "SHA256:b"]}
    assert hostkeys.trusted_args(trusted, "WEB", None) == ["-hostkey", "SHA256:a", "-hostkey", "SHA256:b"]
    assert hostkeys.trusted_args(trusted, "web", 2222) == []
