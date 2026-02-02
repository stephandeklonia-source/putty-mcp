# PuTTY MCP Server

The full PuTTY toolchain exposed as a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server. Gives AI assistants like Claude complete access to SSH, SCP, SFTP, serial, key management, and more — all through PuTTY's battle-tested Windows tools.

**30 tools** across 8 categories. Windows-native. Covers every PuTTY executable.

## What Makes This Different

Most SSH MCP servers give you basic `ssh` and `scp` wrappers. This one wraps the **entire PuTTY suite** with features you won't find elsewhere:

- **Persistent interactive sessions** — Open a shell, send commands, read output over multiple turns. Background reader threads keep output flowing.
- **Native PPK v3 key conversion** — Converts OpenSSH keys to PuTTY's PPK format in pure Python. No GUI puttygen needed.
- **Windows Registry integration** — Full CRUD for PuTTY saved sessions. Create, read, update, delete sessions programmatically.
- **Multi-hop SSH** — Chain through jump hosts with automatically constructed proxy commands.
- **Serial port support** — Open PuTTY on COM ports with configurable baud, parity, stop bits.
- **Pageant integration** — Load keys into PuTTY's SSH agent.

## Covered Executables

| Executable | Purpose |
|-----------|---------|
| `putty.exe` | GUI terminal sessions (SSH, Telnet, serial, raw) |
| `plink` | Command-line SSH/Telnet/serial execution |
| `pscp` | SCP/SFTP file transfer |
| `psftp` | Interactive SFTP sessions |
| `pageant` | SSH key agent |
| `puttygen` | Key generation (via `ssh-keygen` + native PPK converter) |

## Quick Start

### Prerequisites

- Python 3.10+
- [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) installed (all tools)
- Windows (PuTTY is Windows-native; registry tools require Windows)

### Install

```bash
git clone https://github.com/wgthomas/putty-mcp.git
cd putty-mcp
pip install -r requirements.txt
```

### Configure Claude Code / Claude Desktop

Add to your MCP config (`~/.claude.json` or Claude Desktop settings):

```json
{
  "mcpServers": {
    "putty": {
      "command": "python",
      "args": ["/path/to/putty-mcp/putty_mcp.py"],
      "env": {}
    }
  }
}
```

PuTTY executables are auto-detected from `C:\Program Files\PuTTY`, PATH, or `PUTTY_PATH` env var.

## Tools (30)

### GUI Launch (3)

| Tool | Description |
|------|-------------|
| `putty_open` | Launch PuTTY with full connection parameters |
| `putty_open_session` | Launch PuTTY from a saved session name |
| `putty_serial` | Launch PuTTY on a serial port |

### Command Execution (3)

| Tool | Description |
|------|-------------|
| `plink_exec` | Run a single command on a remote host via plink |
| `plink_script` | Run commands from a local script file via plink |
| `plink_tunnel` | Create SSH tunnel (port forward) or `-nc` connection |

### Persistent Sessions (5)

| Tool | Description |
|------|-------------|
| `session_open` | Open persistent interactive session (SSH/Telnet/serial/raw) |
| `session_send` | Send command to a session and return new output |
| `session_read` | Read output buffer from a session |
| `session_list` | List all active sessions |
| `session_close` | Close a session and clean up |

### File Transfer (5)

| Tool | Description |
|------|-------------|
| `pscp_upload` | Upload file(s) to remote host via pscp |
| `pscp_download` | Download file(s) from remote host via pscp |
| `pscp_list` | List remote directory via pscp |
| `psftp_batch` | Execute SFTP commands as a batch via psftp |
| `psftp_interactive` | Open persistent PSFTP session for multi-step workflows |

### Key Management (6)

| Tool | Description |
|------|-------------|
| `keygen_create` | Generate SSH key pair (OpenSSH + PPK format) |
| `keygen_fingerprint` | Get fingerprint of an existing key |
| `keygen_convert` | Convert key to different format (RFC4716, PKCS8, PEM, PPK) |
| `keygen_public_key` | Extract public key in authorized_keys format |
| `pageant_add` | Load key(s) into Pageant |
| `pageant_list` | List keys loaded in Pageant |

### Saved Sessions — Registry (4)

| Tool | Description |
|------|-------------|
| `saved_sessions_list` | List all PuTTY saved sessions |
| `saved_session_get` | Get full config of a saved session |
| `saved_session_create` | Create or update a saved session |
| `saved_session_delete` | Delete a saved session |

### Utility (2)

| Tool | Description |
|------|-------------|
| `test_connection` | Test SSH/Telnet connectivity, returns host key |
| `get_host_key` | Get SSH host key fingerprint from a server |

### Multi-Hop (2)

| Tool | Description |
|------|-------------|
| `proxy_session` | Open interactive session through a proxy command |
| `chain_exec` | Execute command on target through one or more jump hosts |

## Configuration

Copy `config.template.toml` to `config.toml` and adjust as needed:

| Setting | Default | Description |
|---------|---------|-------------|
| `putty.executable_path` | Auto-detected | Path to PuTTY install directory |
| `putty.enable_registry` | `true` | Enable Windows Registry session tools |
| `defaults.protocol` | `ssh` | Default connection protocol |
| `defaults.port` | `22` | Default port |
| `sessions.max_concurrent` | `10` | Max simultaneous interactive sessions |
| `sessions.timeout_seconds` | `3600` | Session idle timeout |
| `sessions.buffer_lines` | `1000` | Output buffer size per session |
| `serial.*` | Standard | Default serial parameters (9600/8/N/1) |

## Architecture

```
putty_mcp.py              # FastMCP server, all 30 tool definitions
putty_lib/
  config.py               # Path resolution, TOML config loading
  executor.py             # Subprocess wrapper (run, spawn, launch_gui)
  session_manager.py      # Persistent sessions with background readers
  registry.py             # Windows Registry CRUD for saved sessions
  utils.py                # Arg building, host parsing, proxy chains
  ppk.py                  # Native Python PPK v3 writer
```

## Key Design Decisions

- **No `shell=True`** — All subprocess calls use argument lists
- **`ssh-keygen` over `puttygen`** — Windows puttygen.exe is GUI-only with no batch CLI. All key generation uses Windows OpenSSH's `ssh-keygen`, then auto-converts to PPK.
- **Native PPK conversion** — `putty_lib/ppk.py` writes PPK v3 format from scratch in Python. Supports Ed25519, RSA, ECDSA. No GUI dependency.
- **Thread-safe sessions** — Background reader threads with bounded deque buffers and automatic cleanup of timed-out sessions.

## Known Limitations

- **Pageant key listing**: Pageant has no reliable CLI flag to list loaded keys as text. The tool tries `ssh-add -L` first (requires Pageant started with `--openssh-config`), falls back to opening the GUI key list window.
- **PPK converter**: Handles unencrypted keys only. Passphrase-protected keys need manual puttygen GUI conversion.
- **Persistent sessions**: Return raw ANSI escape codes from remote shells. Functional but noisy.
- **Windows only**: PuTTY is Windows-native. The registry tools require Windows. Core SSH functionality works anywhere plink is available.

## Security

- **No shell=True** — All commands use `subprocess` with argument lists
- **No credential storage** — Keys and passwords are passed per-call, never persisted by the server
- **Registry scoped** — Only reads/writes PuTTY's own registry keys under `HKCU\Software\SimonTatham\PuTTY`

## License

MIT
