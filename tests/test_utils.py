import pytest

from putty_lib.utils import build_connection_args, build_proxy_chain, limit_text, parse_host_string, strip_ansi


def test_parse_host_string():
    assert parse_host_string("bob@web:2222") == {"username": "bob", "host": "web", "port": 2222}
    assert parse_host_string("[::1]:22") == {"username": None, "host": "::1", "port": 22}
    assert parse_host_string("fe80::1") == {"username": None, "host": "fe80::1", "port": None}


def test_port_is_omitted_when_not_given():
    args = build_connection_args("h", protocol="telnet")
    assert "-P" not in args and args[-1] == "h"
    assert build_connection_args("h", port=2222)[-3:] == ["-P", "2222", "h"]


def test_proxy_chain_single_and_multi_hop():
    assert build_proxy_chain(["a@j1"]) == "plink -batch a@j1 -nc %host:%port"
    chain = build_proxy_chain(["a@j1", "j2:2200"])
    assert chain == 'plink -batch -proxycmd "plink -batch a@j1 -nc j2:2200" -P 2200 j2 -nc %host:%port'


def test_proxy_chain_uses_forward_slashes_and_host_keys():
    chain = build_proxy_chain(
        ["j1"], plink=r"C:\Program Files\PuTTY\plink.exe",
        hostkey_args=lambda h, p: ["-hostkey", "SHA256:abc"],
    )
    assert chain.startswith('"C:/Program Files/PuTTY/plink.exe" -batch -hostkey SHA256:abc j1')


@pytest.mark.parametrize("bad", ["j1;calc", "j 1", 'j"1', "j$(x)", "j|x", "j%x"])
def test_proxy_chain_rejects_unsafe_hosts(bad):
    with pytest.raises(ValueError):
        build_proxy_chain([bad])


def test_strip_ansi():
    raw = "\x1b[01;32muser@h\x1b[00m:~$ ls\r\n\x1b]0;title\x07ok"
    assert strip_ansi(raw) == "user@h:~$ ls\nok"


def test_limit_text_keeps_head_and_tail():
    text = "a" * 5000 + "b" * 5000
    out = limit_text(text, 1000)
    assert out.startswith("a" * 600) and out.endswith("b" * 300) and "omitted" in out
    assert limit_text("short", 1000) == "short"


def test_parse_ping_dutch_windows_and_linux():
    from putty_lib.netcheck import parse_ping

    dutch = (
        "Antwoord van 10.0.0.1: bytes=32 tijd=2ms TTL=64\n"
        "Antwoord van 10.0.0.5: Doelhost onbereikbaar.\n"
        "Antwoord van 10.0.0.1: bytes=32 tijd<1ms TTL=64\n"
        "    Pakketten: verzonden = 3, ontvangen = 2, verloren = 1 (33% verlies),\n"
        "    Minimum = 0ms, Maximum = 2ms, Gemiddeld = 1ms\n"
    )
    r = parse_ping(dutch, 3)
    assert r["received"] == 2 and r["loss_percent"] == 33.0 and r["max_ms"] == 2.0
    linux = ("64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n"
             "1 packets transmitted, 1 received, 0% packet loss, time 0ms\n")
    r = parse_ping(linux, 1)
    assert r["received"] == 1 and r["loss_percent"] == 0.0 and r["min_ms"] == r["max_ms"] == 0.045
    assert parse_ping("Request timed out.\n", 1)["reachable"] is False
