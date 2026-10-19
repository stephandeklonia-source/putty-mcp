import sys
import uuid

import pytest

from putty_lib import registry


@pytest.mark.parametrize("name,encoded", [
    ("user@host", "user@host"),
    ("My Server", "My%20Server"),
    (".hidden", "%2Ehidden"),
    ("a.b", "a.b"),
    ("50%", "50%25"),
    ("a*b?c\\d", "a%2Ab%3Fc%5Cd"),
])
def test_session_names_are_escaped_like_putty(name, encoded):
    assert registry._encode_session_name(name) == encoded
    assert registry._decode_session_name(encoded) == name


@pytest.mark.skipif(sys.platform != "win32", reason="needs the Windows registry")
def test_registry_roundtrip():
    name = f"putty-mcp test {uuid.uuid4().hex[:6]}@x"
    try:
        registry.create_session(name, host="example.com", port=2222, compression=True)
        assert name in registry.list_sessions()
        values = registry.get_session(name)
        assert values["HostName"] == "example.com" and values["PortNumber"] == 2222 and values["Compression"] == 1
    finally:
        assert registry.delete_session(name)
    assert name not in registry.list_sessions()
