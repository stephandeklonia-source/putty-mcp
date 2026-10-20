import base64
import os
import shutil
import subprocess
import sys

import pytest

from putty_lib import keys
from putty_lib.ppk import ppk_public_blob

KEY_TYPES = [("ed25519", None), ("rsa", 2048), ("ecdsa", 256), ("ecdsa", 384), ("ecdsa", 521)]
PUTTYGEN = shutil.which("puttygen")
SSH_KEYGEN = shutil.which("ssh-keygen")


@pytest.mark.parametrize("key_type,bits", KEY_TYPES)
def test_generate_and_write_files(tmp_path, key_type, bits):
    key = keys.generate(key_type, bits)
    base = str(tmp_path / "k")
    keys.write_openssh_private(base, key, None)
    keys.write_public(base + ".pub", key, "c")
    keys.write_ppk(base + ".ppk", key, "c", None)
    blob = keys.public_blob_from_key(key)
    # every file yields the same public key
    for path in (base, base + ".pub", base + ".ppk"):
        assert keys.public_blob(path)[0] == blob
    if sys.platform != "win32":
        assert oct(os.stat(base).st_mode & 0o777) == "0o600"
        assert oct(os.stat(base + ".ppk").st_mode & 0o777) == "0o600"


def test_refuses_to_overwrite(tmp_path):
    key = keys.generate()
    keys.write_public(str(tmp_path / "k.pub"), key, "")
    with pytest.raises(FileExistsError):
        keys.write_public(str(tmp_path / "k.pub"), key, "")


def test_encrypted_openssh_roundtrip(tmp_path):
    key = keys.generate()
    path = str(tmp_path / "k")
    keys.write_openssh_private(path, key, "pw")
    assert keys.is_encrypted(path)
    with pytest.raises(keys.PassphraseRequired):
        keys.load_private(path)
    with pytest.raises(keys.PassphraseRequired):
        keys.load_private(path, "wrong")
    assert keys.public_blob_from_key(keys.load_private(path, "pw")) == keys.public_blob_from_key(key)
    # the public part is readable without the passphrase
    assert keys.public_blob(path)[0] == keys.public_blob_from_key(key)


def test_ppk_encrypted_header(tmp_path):
    key = keys.generate()
    path = str(tmp_path / "k.ppk")
    keys.write_ppk(path, key, "comment", "pw")
    text = open(path).read()
    assert "Encryption: aes256-cbc" in text and "Key-Derivation: Argon2id" in text
    assert ppk_public_blob(text) == (keys.public_blob_from_key(key), "comment")


def test_fingerprint_and_exports():
    key = keys.generate("rsa", 2048)
    blob = keys.public_blob_from_key(key)
    assert keys.fingerprint(blob).startswith("SHA256:") and len(keys.fingerprint(blob)) == 50
    assert keys.fingerprint(blob, "md5").count(":") == 16
    assert "BEGIN SSH2 PUBLIC KEY" in keys.export_public(blob, "c", "RFC4716")
    assert "BEGIN PUBLIC KEY" in keys.export_public(blob, "c", "PKCS8")
    assert "BEGIN RSA PUBLIC KEY" in keys.export_public(blob, "c", "PEM")
    with pytest.raises(ValueError):
        keys.export_public(keys.public_blob_from_key(keys.generate()), "", "PEM")


@pytest.mark.skipif(not SSH_KEYGEN, reason="ssh-keygen not installed")
def test_fingerprint_matches_ssh_keygen(tmp_path):
    key = keys.generate()
    keys.write_public(str(tmp_path / "k.pub"), key, "c")
    out = subprocess.run([SSH_KEYGEN, "-lf", str(tmp_path / "k.pub")], capture_output=True, text=True).stdout
    assert out.split()[1] == keys.fingerprint(keys.public_blob_from_key(key))


@pytest.mark.skipif(not PUTTYGEN, reason="puttygen not installed")
@pytest.mark.parametrize("key_type,bits", KEY_TYPES)
@pytest.mark.parametrize("passphrase", [None, "s3cret pw"])
def test_puttygen_accepts_our_ppk(tmp_path, key_type, bits, passphrase):
    key = keys.generate(key_type, bits)
    ppk = tmp_path / "k.ppk"
    keys.write_ppk(str(ppk), key, "c", passphrase)
    (tmp_path / "pw").write_text((passphrase or "") + "\n")
    (tmp_path / "empty").write_text("")
    (tmp_path / "wrong").write_text("wrong\n")
    out = tmp_path / "k.openssh"

    def puttygen(pwfile):
        return subprocess.run(
            [PUTTYGEN, str(ppk), "--old-passphrase", str(pwfile), "--new-passphrase", str(tmp_path / "empty"),
             "-O", "private-openssh", "-o", str(out)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
        )

    result = puttygen(tmp_path / "pw")
    assert result.returncode == 0, result.stderr
    # puttygen verified the MAC over the decrypted private part and exported
    # the same key (compared via puttygen: cryptography rejects puttygen's
    # minimal-length EC scalars when they happen to start with a zero byte)
    pub = subprocess.run([PUTTYGEN, str(out), "-O", "public-openssh"], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, timeout=60).stdout.split()[1]
    assert base64.b64decode(pub) == keys.public_blob_from_key(key)
    if passphrase:
        assert puttygen(tmp_path / "wrong").returncode != 0
