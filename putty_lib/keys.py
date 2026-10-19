"""SSH key operations in pure Python (replaces ssh-keygen).

Passphrases never appear on a command line. The tools in putty_mcp.py get
them from the operator through the dashboard, not from the AI.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from putty_lib.ppk import PrivateKey, ppk_public_blob, ppk_text

KEY_TYPES = ("ed25519", "rsa", "ecdsa")
_ECDSA_CURVES = {256: ec.SECP256R1(), 384: ec.SECP384R1(), 521: ec.SECP521R1()}


class PassphraseRequired(Exception):
    """The private key is encrypted and no (or a wrong) passphrase was given."""


# ---------------------------------------------------------------------------
# Generating and loading
# ---------------------------------------------------------------------------


def generate(key_type: str = "ed25519", bits: int | None = None) -> PrivateKey:
    key_type = key_type.lower()
    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if key_type == "rsa":
        bits = bits or 3072
        if bits < 2048:
            raise ValueError("RSA keys must be at least 2048 bits")
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    if key_type == "ecdsa":
        curve = _ECDSA_CURVES.get(bits or 256)
        if curve is None:
            raise ValueError("ECDSA bits must be 256, 384 or 521")
        return ec.generate_private_key(curve)
    raise ValueError(f"key_type must be one of: {', '.join(KEY_TYPES)} (DSA is no longer supported)")


def is_encrypted(path: str) -> bool:
    data = Path(path).read_bytes()
    if b"openssh-key-v1" in data or b"OPENSSH PRIVATE KEY" in data:
        raw = _openssh_raw(data)
        cipher, _ = _read_string(raw, len(b"openssh-key-v1\0"))
        return cipher != b"none"
    return b"ENCRYPTED" in data


def load_private(path: str, passphrase: str | None = None) -> PrivateKey:
    """Load an OpenSSH or PEM/PKCS8 private key."""
    data = Path(path).read_bytes()
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        if b"OPENSSH PRIVATE KEY" in data:
            key = serialization.load_ssh_private_key(data, password)
        else:
            key = serialization.load_pem_private_key(data, password)
    except TypeError as e:  # encrypted key without password, or vice versa
        raise PassphraseRequired(str(e)) from None
    except ValueError:
        if b"PuTTY-User-Key-File" in data:
            raise ValueError("PPK files can't be used as input here; convert from the OpenSSH key") from None
        if passphrase and is_encrypted(path):
            # A wrong passphrase shows up as corrupt data after decryption
            raise PassphraseRequired("Wrong passphrase") from None
        raise
    if not isinstance(key, (rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError(f"Unsupported key type: {type(key).__name__}")
    return key


# ---------------------------------------------------------------------------
# Public keys and fingerprints
# ---------------------------------------------------------------------------


def _read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack(">I", data[offset : offset + 4])
    return data[offset + 4 : offset + 4 + length], offset + 4 + length


def _openssh_raw(data: bytes) -> bytes:
    lines = [ln for ln in data.decode("ascii", "replace").splitlines() if ln and not ln.startswith("-----")]
    raw = base64.b64decode("".join(lines))
    if not raw.startswith(b"openssh-key-v1\0"):
        raise ValueError("Not an OpenSSH private key")
    return raw


def _openssh_public_blob(data: bytes) -> bytes:
    """The public key is stored unencrypted in an OpenSSH private key file."""
    raw = _openssh_raw(data)
    offset = len(b"openssh-key-v1\0")
    for _ in range(3):  # cipher, kdf, kdf options
        _, offset = _read_string(raw, offset)
    offset += 4  # number of keys
    blob, _ = _read_string(raw, offset)
    return blob


def public_blob_from_key(key: PrivateKey) -> bytes:
    line = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return base64.b64decode(line.split()[1])


def public_blob(path: str) -> tuple[bytes, str]:
    """Return (public blob, comment) for a .pub, .ppk or private key file."""
    data = Path(path).read_bytes()
    text = data.decode("utf-8", "replace")
    if text.startswith("PuTTY-User-Key-File"):
        return ppk_public_blob(text)
    if "OPENSSH PRIVATE KEY" in text:
        pub = Path(path + ".pub")
        comment = read_pub_file(str(pub))[1] if pub.exists() else ""
        return _openssh_public_blob(data), comment
    if "PRIVATE KEY" in text:
        # PEM keys carry no plaintext public part
        pub = Path(path + ".pub")
        if pub.exists():
            return read_pub_file(str(pub))
        raise PassphraseRequired("PEM private key: public part needs the key to be loaded")
    return read_pub_file(path)


def read_pub_file(path: str) -> tuple[bytes, str]:
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    if text.startswith("---- BEGIN SSH2 PUBLIC KEY ----"):
        body, comment = [], ""
        for line in text.splitlines()[1:-1]:
            if line.lower().startswith("comment:"):
                comment = line.split(":", 1)[1].strip().strip('"')
            elif ":" not in line:
                body.append(line.strip())
        return base64.b64decode("".join(body)), comment
    parts = text.split(None, 2)
    if len(parts) < 2:
        raise ValueError(f"Not a public key file: {path}")
    return base64.b64decode(parts[1]), parts[2] if len(parts) > 2 else ""


def key_type_of(blob: bytes) -> str:
    return _read_string(blob, 0)[0].decode()


def openssh_line(blob: bytes, comment: str = "") -> str:
    line = f"{key_type_of(blob)} {base64.b64encode(blob).decode()}"
    return f"{line} {comment}" if comment else line


def fingerprint(blob: bytes, algorithm: str = "sha256") -> str:
    if algorithm.lower() == "md5":
        digest = hashlib.md5(blob).hexdigest()  # noqa: S324 - fingerprint format, not security
        return "MD5:" + ":".join(digest[i : i + 2] for i in range(0, 32, 2))
    if algorithm.lower() != "sha256":
        raise ValueError("algorithm must be sha256 or md5")
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def export_public(blob: bytes, comment: str, fmt: str) -> str:
    fmt = fmt.upper()
    if fmt == "OPENSSH":
        return openssh_line(blob, comment) + "\n"
    if fmt == "RFC4716":
        body = base64.b64encode(blob).decode()
        lines = ["---- BEGIN SSH2 PUBLIC KEY ----"]
        if comment:
            lines.append(f'Comment: "{comment}"')
        lines += [body[i : i + 70] for i in range(0, len(body), 70)]
        lines.append("---- END SSH2 PUBLIC KEY ----")
        return "\n".join(lines) + "\n"
    key = serialization.load_ssh_public_key(openssh_line(blob).encode())
    if fmt == "PKCS8":
        return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    if fmt == "PEM":
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("PEM (PKCS#1) export is only possible for RSA keys; use PKCS8")
        return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1).decode()
    raise ValueError("output_format must be PPK, OPENSSH, RFC4716, PKCS8 or PEM")


# ---------------------------------------------------------------------------
# Writing files
# ---------------------------------------------------------------------------


def _write(path: str, text: str, private: bool, overwrite: bool) -> None:
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(f"{path} already exists (pass overwrite=true to replace it)")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "w", newline="\n") as f:
        f.write(text)


def write_openssh_private(path: str, key: PrivateKey, passphrase: str | None, overwrite: bool = False) -> None:
    encryption = (serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
                  if passphrase else serialization.NoEncryption())
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption)
    _write(path, data.decode(), private=True, overwrite=overwrite)


def write_public(path: str, key: PrivateKey, comment: str, overwrite: bool = False) -> None:
    _write(path, openssh_line(public_blob_from_key(key), comment) + "\n", private=False, overwrite=overwrite)


def write_ppk(path: str, key: PrivateKey, comment: str, passphrase: str | None, overwrite: bool = False) -> None:
    _write(path, ppk_text(key, comment, passphrase), private=True, overwrite=overwrite)
