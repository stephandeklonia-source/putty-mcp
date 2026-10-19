"""Write PuTTY PPK v3 private key files, optionally passphrase-protected.

Encrypted files use PuTTY's v3 scheme: Argon2id derives the AES-256-CBC key,
IV and HMAC-SHA-256 key from the passphrase. Supports RSA, Ed25519, ECDSA.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

PrivateKey = rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey

# PuTTY's defaults are 8192 KiB and a passes count calibrated to ~100ms
_ARGON2_MEMORY = 8192
_ARGON2_PASSES = 21
_ARGON2_PARALLELISM = 1

_CURVES = {"secp256r1": "nistp256", "secp384r1": "nistp384", "secp521r1": "nistp521"}


def _string(data: bytes) -> bytes:
    """SSH string: uint32 length prefix + data."""
    return struct.pack(">I", len(data)) + data


def _mpint(n: int) -> bytes:
    """SSH mpint: big-endian two's complement, minimal length."""
    if n == 0:
        return _string(b"")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _string(raw)


def key_blobs(key: PrivateKey) -> tuple[str, bytes, bytes]:
    """Return (algorithm name, public blob, private blob) in PuTTY's layout."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return "ssh-ed25519", _string(b"ssh-ed25519") + _string(pub), _string(seed)

    if isinstance(key, rsa.RSAPrivateKey):
        nums = key.private_numbers()
        pub = nums.public_numbers
        public = _string(b"ssh-rsa") + _mpint(pub.e) + _mpint(pub.n)
        # PuTTY: d, p, q, iqmp (= q^-1 mod p, same as cryptography's iqmp)
        private = _mpint(nums.d) + _mpint(nums.p) + _mpint(nums.q) + _mpint(nums.iqmp)
        return "ssh-rsa", public, private

    if isinstance(key, ec.EllipticCurvePrivateKey):
        curve = _CURVES.get(key.curve.name)
        if curve is None:
            raise ValueError(f"Unsupported ECDSA curve: {key.curve.name}")
        alg = f"ecdsa-sha2-{curve}"
        point = key.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.UncompressedPoint)
        public = _string(alg.encode()) + _string(curve.encode()) + _string(point)
        return alg, public, _mpint(key.private_numbers().private_value)

    raise ValueError(f"Unsupported key type: {type(key).__name__}")


def _wrap(data: bytes) -> list[str]:
    text = base64.b64encode(data).decode()
    return [text[i : i + 64] for i in range(0, len(text), 64)]


def _argon2(passphrase: bytes, salt: bytes) -> bytes:
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=_ARGON2_PASSES,
        memory_cost=_ARGON2_MEMORY,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=80,
        type=Type.ID,
    )


def ppk_text(key: PrivateKey, comment: str = "", passphrase: str | None = None) -> str:
    """Render a key as PPK v3 text; encrypted when passphrase is non-empty."""
    alg, public_blob, private_blob = key_blobs(key)
    header_lines: list[str] = []

    if passphrase:
        encryption = "aes256-cbc"
        salt = os.urandom(16)
        derived = _argon2(passphrase.encode("utf-8"), salt)
        cipher_key, iv, mac_key = derived[:32], derived[32:48], derived[48:80]
        # Pad to the AES block size with random bytes (as PuTTY does)
        pad = -len(private_blob) % 16
        private_plain = private_blob + os.urandom(pad)
        enc = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).encryptor()
        private_out = enc.update(private_plain) + enc.finalize()
        header_lines = [
            "Key-Derivation: Argon2id",
            f"Argon2-Memory: {_ARGON2_MEMORY}",
            f"Argon2-Passes: {_ARGON2_PASSES}",
            f"Argon2-Parallelism: {_ARGON2_PARALLELISM}",
            f"Argon2-Salt: {salt.hex()}",
        ]
    else:
        encryption = "none"
        private_plain = private_out = private_blob
        mac_key = b""  # unencrypted v3 files use an empty MAC key

    mac = hmac.new(
        mac_key,
        _string(alg.encode()) + _string(encryption.encode()) + _string(comment.encode())
        + _string(public_blob) + _string(private_plain),
        hashlib.sha256,
    ).hexdigest()

    pub_lines = _wrap(public_blob)
    priv_lines = _wrap(private_out)
    lines = [
        f"PuTTY-User-Key-File-3: {alg}",
        f"Encryption: {encryption}",
        f"Comment: {comment}",
        f"Public-Lines: {len(pub_lines)}",
        *pub_lines,
        *header_lines,
        f"Private-Lines: {len(priv_lines)}",
        *priv_lines,
        f"Private-MAC: {mac}",
    ]
    return "\n".join(lines) + "\n"


def ppk_public_blob(text: str) -> tuple[bytes, str]:
    """Read the (always unencrypted) public blob and comment from a PPK file."""
    lines = text.splitlines()
    comment = ""
    for i, line in enumerate(lines):
        if line.startswith("Comment: "):
            comment = line[len("Comment: "):]
        if line.startswith("Public-Lines: "):
            count = int(line.split(":", 1)[1])
            return base64.b64decode("".join(lines[i + 1 : i + 1 + count])), comment
    raise ValueError("Not a PuTTY key file (no Public-Lines)")
