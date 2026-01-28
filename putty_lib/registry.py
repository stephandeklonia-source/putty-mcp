"""Windows Registry CRUD for PuTTY saved sessions."""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any

log = logging.getLogger(__name__)

_SESSIONS_KEY = r"Software\SimonTatham\PuTTY\Sessions"

try:
    import winreg

    _HAS_WINREG = True
except ImportError:
    _HAS_WINREG = False


def _check_available() -> None:
    if not _HAS_WINREG:
        raise RuntimeError("Registry operations require Windows (winreg not available)")


def _encode_session_name(name: str) -> str:
    """PuTTY URL-encodes session names in the registry."""
    return urllib.parse.quote(name, safe="")


def _decode_session_name(encoded: str) -> str:
    return urllib.parse.unquote(encoded)


# -- Registry value name mapping --
# Maps friendly parameter names to PuTTY's actual registry value names.
_PARAM_TO_REG: dict[str, tuple[str, type]] = {
    "host": ("HostName", str),
    "port": ("PortNumber", int),
    "protocol": ("Protocol", str),
    "username": ("UserName", str),
    "key_file": ("PublicKeyFile", str),
    "x11_forward": ("X11Forward", int),  # 0/1
    "agent_forward": ("AgentFwd", int),  # 0/1
    "serial_line": ("SerialLine", str),
    "serial_speed": ("SerialSpeed", int),
    "serial_data_bits": ("SerialDataBits", int),
    "serial_parity": ("SerialParity", int),  # 0=none,1=odd,2=even,3=mark,4=space
    "serial_stop_bits": ("SerialStopHalfbits", int),  # 2=1stop, 4=2stop
    "serial_flow_control": ("SerialFlowControl", int),  # 0=none,1=xon,2=rts,3=dsr
    "proxy_type": ("ProxyMethod", int),
    "proxy_host": ("ProxyHost", str),
    "proxy_port": ("ProxyPort", int),
    "proxy_command": ("ProxyTelnetCommand", str),
    "compression": ("Compression", int),
    "ssh_version": ("SshProt", int),  # 0=1only, 3=2only, etc.
    "local_port_acceptall": ("LocalPortAcceptAll", int),
    "remote_port_acceptall": ("RemotePortAcceptAll", int),
    "font_name": ("Font", str),
    "font_size": ("FontHeight", int),
    "window_rows": ("TermHeight", int),
    "window_cols": ("TermWidth", int),
    "scrollback_lines": ("ScrollbackLines", int),
    "log_type": ("LogType", int),
    "log_filename": ("LogFileName", str),
}


def list_sessions() -> list[str]:
    """List all saved PuTTY session names."""
    _check_available()
    sessions: list[str] = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SESSIONS_KEY)  # type: ignore[name-defined]
        i = 0
        while True:
            try:
                name = winreg.EnumKey(key, i)  # type: ignore[name-defined]
                sessions.append(_decode_session_name(name))
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)  # type: ignore[name-defined]
    except OSError:
        pass
    return sessions


def get_session(name: str) -> dict[str, Any]:
    """Get all values from a saved session."""
    _check_available()
    encoded = _encode_session_name(name)
    result: dict[str, Any] = {"session_name": name}
    try:
        key = winreg.OpenKey(  # type: ignore[name-defined]
            winreg.HKEY_CURRENT_USER, f"{_SESSIONS_KEY}\\{encoded}"  # type: ignore[name-defined]
        )
        i = 0
        while True:
            try:
                val_name, val_data, val_type = winreg.EnumValue(key, i)  # type: ignore[name-defined]
                result[val_name] = val_data
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)  # type: ignore[name-defined]
    except OSError as e:
        raise KeyError(f"Session '{name}' not found") from e
    return result


def create_session(name: str, **params: Any) -> dict[str, Any]:
    """Create or update a saved session.

    Accepts friendly param names (host, port, protocol, etc.)
    and maps them to PuTTY's registry values.
    """
    _check_available()
    encoded = _encode_session_name(name)
    key_path = f"{_SESSIONS_KEY}\\{encoded}"

    key = winreg.CreateKey(  # type: ignore[name-defined]
        winreg.HKEY_CURRENT_USER, key_path  # type: ignore[name-defined]
    )

    written: dict[str, Any] = {}
    for param_name, value in params.items():
        if param_name in _PARAM_TO_REG:
            reg_name, reg_type = _PARAM_TO_REG[param_name]
            # Convert booleans to int for registry
            if isinstance(value, bool):
                value = int(value)
            if reg_type is int:
                winreg.SetValueEx(key, reg_name, 0, winreg.REG_DWORD, int(value))  # type: ignore[name-defined]
            else:
                winreg.SetValueEx(key, reg_name, 0, winreg.REG_SZ, str(value))  # type: ignore[name-defined]
            written[reg_name] = value
        else:
            # Direct registry value name — pass through
            if isinstance(value, int):
                winreg.SetValueEx(key, param_name, 0, winreg.REG_DWORD, value)  # type: ignore[name-defined]
            else:
                winreg.SetValueEx(key, param_name, 0, winreg.REG_SZ, str(value))  # type: ignore[name-defined]
            written[param_name] = value

    winreg.CloseKey(key)  # type: ignore[name-defined]
    return {"session_name": name, "values_written": written}


def delete_session(name: str) -> bool:
    """Delete a saved session. Returns True if deleted."""
    _check_available()
    encoded = _encode_session_name(name)
    try:
        winreg.DeleteKey(  # type: ignore[name-defined]
            winreg.HKEY_CURRENT_USER, f"{_SESSIONS_KEY}\\{encoded}"  # type: ignore[name-defined]
        )
        return True
    except OSError:
        return False
