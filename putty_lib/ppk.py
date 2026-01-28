"""Convert OpenSSH private keys to PuTTY PPK v3 format (unencrypted).

This avoids needing the puttygen GUI on Windows for key conversion.
Supports: RSA, Ed25519, ECDSA.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import struct
import subprocess
from pathlib import Path


def _read_openssh_private(path: str) -> bytes:
    """Read an OpenSSH private key file and return raw bytes."""
    with open(path, "r") as f:
        text = f.read()
    # Strip PEM/OpenSSH header/footer
    lines = [
        line
        for line in text.strip().splitlines()
        if not line.startswith("-----")
    ]
    return base64.b64decode("".join(lines))


def _read_openssh_public(path: str) -> tuple[str, str, str]:
    """Read OpenSSH .pub file. Returns (key_type, base64_blob, comment)."""
    with open(path, "r") as f:
        line = f.read().strip()
    parts = line.split(None, 2)
    key_type = parts[0]
    blob_b64 = parts[1]
    comment = parts[2] if len(parts) > 2 else ""
    return key_type, blob_b64, comment


def _ssh_string(data: bytes) -> bytes:
    """Encode as SSH string (uint32 length prefix + data)."""
    return struct.pack(">I", len(data)) + data


def _read_ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read an SSH string from data at offset. Returns (value, new_offset)."""
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    value = data[offset + 4 : offset + 4 + length]
    return value, offset + 4 + length


def _parse_openssh_new_format(raw: bytes) -> tuple[str, bytes, bytes]:
    """Parse OpenSSH new-format private key.

    Returns: (key_type, public_blob, private_blob) where the blobs
    are in PuTTY's expected format.
    """
    # Magic: "openssh-key-v1\0"
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        raise ValueError("Not an OpenSSH new-format private key")

    offset = len(magic)
    cipher_name, offset = _read_ssh_string(raw, offset)
    kdf_name, offset = _read_ssh_string(raw, offset)
    kdf_options, offset = _read_ssh_string(raw, offset)
    num_keys = struct.unpack(">I", raw[offset : offset + 4])[0]
    offset += 4

    if cipher_name != b"none":
        raise ValueError(
            f"Encrypted OpenSSH keys not supported (cipher={cipher_name.decode()}). "
            "Generate without a passphrase or decrypt first."
        )
    if num_keys != 1:
        raise ValueError(f"Expected 1 key, got {num_keys}")

    # Public key blob
    pub_blob_raw, offset = _read_ssh_string(raw, offset)

    # Private section (contains check ints + private key data)
    priv_section, offset = _read_ssh_string(raw, offset)

    # Parse private section
    poff = 0
    check1 = struct.unpack(">I", priv_section[poff : poff + 4])[0]
    poff += 4
    check2 = struct.unpack(">I", priv_section[poff : poff + 4])[0]
    poff += 4
    if check1 != check2:
        raise ValueError("Check integers don't match (wrong passphrase?)")

    # Key type
    key_type_bytes, poff = _read_ssh_string(priv_section, poff)
    key_type = key_type_bytes.decode()

    if key_type == "ssh-ed25519":
        # Ed25519: public (32 bytes), private (64 bytes = seed + public)
        ed_pub, poff = _read_ssh_string(priv_section, poff)
        ed_priv, poff = _read_ssh_string(priv_section, poff)
        comment_bytes, poff = _read_ssh_string(priv_section, poff)

        # PuTTY public blob: type + pub
        public_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(ed_pub)
        # PuTTY private blob: just the 64-byte expanded key
        private_blob = _ssh_string(ed_priv)

    elif key_type == "ssh-rsa":
        # RSA: n, e, d, iqmp, p, q
        n, poff = _read_ssh_string(priv_section, poff)
        e, poff = _read_ssh_string(priv_section, poff)
        d, poff = _read_ssh_string(priv_section, poff)
        iqmp, poff = _read_ssh_string(priv_section, poff)
        p, poff = _read_ssh_string(priv_section, poff)
        q, poff = _read_ssh_string(priv_section, poff)
        comment_bytes, poff = _read_ssh_string(priv_section, poff)

        # PuTTY public blob: type, e, n
        public_blob = _ssh_string(b"ssh-rsa") + _ssh_string(e) + _ssh_string(n)
        # PuTTY private blob: d, p, q, iqmp
        private_blob = (
            _ssh_string(d) + _ssh_string(p) + _ssh_string(q) + _ssh_string(iqmp)
        )

    elif key_type.startswith("ecdsa-sha2-"):
        # ECDSA: curve_name, public_point, private_scalar
        curve, poff = _read_ssh_string(priv_section, poff)
        pub_point, poff = _read_ssh_string(priv_section, poff)
        priv_scalar, poff = _read_ssh_string(priv_section, poff)
        comment_bytes, poff = _read_ssh_string(priv_section, poff)

        # PuTTY public blob: type, curve, point
        public_blob = (
            _ssh_string(key_type.encode())
            + _ssh_string(curve)
            + _ssh_string(pub_point)
        )
        # PuTTY private blob: scalar
        private_blob = _ssh_string(priv_scalar)

    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    return key_type, public_blob, private_blob


def openssh_to_ppk(
    private_key_path: str,
    output_path: str | None = None,
) -> str:
    """Convert an OpenSSH private key to PuTTY PPK v3 format (no passphrase).

    Args:
        private_key_path: Path to the OpenSSH private key.
        output_path: Output .ppk path. Defaults to private_key_path + ".ppk".

    Returns:
        Path to the written PPK file.
    """
    if output_path is None:
        output_path = private_key_path + ".ppk"

    # Read public key for comment
    pub_path = private_key_path + ".pub"
    if Path(pub_path).exists():
        _, _, comment = _read_openssh_public(pub_path)
    else:
        comment = ""

    # Parse private key
    raw = _read_openssh_private(private_key_path)
    key_type, public_blob, private_blob = _parse_openssh_new_format(raw)

    # PPK type mapping
    ppk_type = key_type  # ssh-ed25519, ssh-rsa, ecdsa-sha2-*

    # Encode blobs
    pub_b64 = base64.b64encode(public_blob).decode()
    priv_b64 = base64.b64encode(private_blob).decode()

    # Split into 64-char lines
    def _wrap(s: str) -> str:
        return "\n".join(s[i : i + 64] for i in range(0, len(s), 64))

    pub_lines = _wrap(pub_b64)
    priv_lines = _wrap(priv_b64)

    # PPK v3 MAC (HMAC-SHA-256)
    # For unencrypted keys (Encryption: none), the MAC key is zero-length.
    # For encrypted keys, the MAC key is derived from Argon2 output.
    mac_key = b""

    # MAC covers: key_type, encryption, comment, public_blob, private_blob
    mac_data = (
        _ssh_string(ppk_type.encode())
        + _ssh_string(b"none")  # encryption
        + _ssh_string(comment.encode())
        + _ssh_string(public_blob)
        + _ssh_string(private_blob)
    )
    mac_hex = hmac.new(mac_key, mac_data, hashlib.sha256).hexdigest()

    pub_line_count = pub_lines.count("\n") + 1
    priv_line_count = priv_lines.count("\n") + 1

    ppk_content = (
        f"PuTTY-User-Key-File-3: {ppk_type}\n"
        f"Encryption: none\n"
        f"Comment: {comment}\n"
        f"Public-Lines: {pub_line_count}\n"
        f"{pub_lines}\n"
        f"Private-Lines: {priv_line_count}\n"
        f"{priv_lines}\n"
        f"Private-MAC: {mac_hex}\n"
    )

    with open(output_path, "w", newline="\n") as f:
        f.write(ppk_content)

    return output_path
