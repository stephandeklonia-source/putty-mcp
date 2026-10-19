# PuTTY MCP Server

An [MCP](https://modelcontextprotocol.io/) server that gives AI assistants (Claude Code, Claude Desktop, …) the full PuTTY toolchain: SSH, Telnet, serial, SCP/SFTP, port forwarding, jump hosts, key management and PuTTY's saved sessions. It has 30 tools.

Each tool call is shown live in a local **monitor dashboard**. From there you can kill one connection, or everything at once.

## Requirements

- Python 3.10+
- [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) (plink, pscp, psftp, pageant, putty)
- OpenSSH `ssh-keygen` for key generation (built into Windows 10+)
- Windows for the registry and GUI tools. The plink, pscp and psftp tools also work on Linux and macOS.

## Installation

```bash
git clone https://github.com/stephandeklonia-source/putty-mcp.git
cd putty-mcp
pip install .
```

Add the server to your MCP client, for example in `~/.claude.json` or the Claude Desktop settings:

```json
{
  "mcpServers": {
    "putty": {
      "command": "putty-mcp"
    }
  }
}
```

If you'd rather not install it, use `"command": "python", "args": ["C:/path/to/putty-mcp/putty_mcp.py"]` after `pip install -r requirements.txt`.

The server works with `mcp` 1.25+ and 2.x. 2.x is recommended: it runs tool calls in parallel, while 1.x runs them one at a time. To upgrade, use the same Python that your MCP client starts:

```powershell
python -m pip install --upgrade "mcp[cli]>=2.2,<3"
python -c "import mcp.server.mcpserver; print('mcp 2.x OK')"
```

The server looks for PuTTY in this order: `executable_path` in `config.toml`, the `PUTTY_PATH` environment variable, `PATH`, then `C:\Program Files\PuTTY`.

## Monitor and kill switch

![Monitor dashboard](docs/monitor.png)

The first time a tool is called, the server opens a dashboard in your browser. It shows:

- **Active connections and processes**: interactive sessions, tunnels, running commands and PuTTY windows, each with a **Kill** button
- **Running tool calls**: what is in progress right now and for how long
- **Live session output**: what the remote shell returns, in each session
- **Activity log**: every tool call with its arguments (commands are highlighted), result, duration and status

**KILL ALL** stops every process the server started, process trees included (for example plink proxy chains). It also **blocks all new tool calls**. While blocked, the AI gets the error "Blocked by operator… Stop and ask the user what to do". Click **Allow tool calls** to lift the block. **Block new tool calls** blocks without killing anything.

The dashboard listens only on `127.0.0.1` and needs a random token that is in its URL. It is new on every server start and appears in the server log. Other websites can't read the dashboard or press its buttons. Passphrases are shown as `***`.

> **Note:** the kill switch protects you against tool calls through this server. It is no sandbox. An assistant that also has shell access (like Claude Code) can still run other programs itself.

## Tools

| Category | Tool | Description |
|---|---|---|
| **GUI** | `putty_open` | Open a PuTTY window with connection parameters |
| | `putty_open_session` | Open a PuTTY window from a saved session |
| | `putty_serial` | Open a PuTTY window on a serial port |
| **Commands** | `plink_exec` | Run a single command on a remote host |
| | `plink_script` | Run a local script file remotely (`plink -m`) |
| | `plink_tunnel` | Port forwarding (`-L`/`-R`/`-D`) or `-nc` connection |
| **Sessions** | `session_open` | Open a persistent interactive session (SSH/Telnet/serial/raw) |
| | `session_send` | Send a command and return the new output |
| | `session_read` | Read the output buffer |
| | `session_list` | List active sessions |
| | `session_close` | Close a session |
| **File transfer** | `pscp_upload` / `pscp_download` | Copy files via pscp |
| | `pscp_list` | List a remote directory |
| | `psftp_batch` | Run SFTP commands as a batch |
| | `psftp_interactive` | Persistent SFTP session (use with `session_send`) |
| **Keys** | `keygen_create` | Generate a key pair (OpenSSH + `.ppk`) |
| | `keygen_fingerprint` | Fingerprint of a key |
| | `keygen_convert` | Export the public key (RFC4716/PKCS8/PEM) or convert the private key to PPK |
| | `keygen_public_key` | Public key in `authorized_keys` format |
| | `pageant_add` | Load keys into Pageant |
| | `pageant_list` | List keys in Pageant |
| **Saved sessions** | `saved_sessions_list` | List PuTTY sessions from the registry |
| | `saved_session_get` | Read a saved session |
| | `saved_session_create` | Create or update a saved session |
| | `saved_session_delete` | Delete a saved session |
| **Utility** | `test_connection` | Test an SSH or Telnet connection |
| | `get_host_key` | Get a server's host key fingerprint (for `host_keys`) |
| **Multi-hop** | `proxy_session` | Interactive session via a custom `-proxycmd` |
| | `chain_exec` | Run a command via one or more jump hosts (`user@host:port`) |

If you leave out `port`, PuTTY picks the protocol's default port (22 for SSH, 23 for Telnet) or the port stored in the loaded saved session.

## Configuration

Copy `config.template.toml` to `config.toml`. All settings are optional.

| Setting | Default | Description |
|---|---|---|
| `putty.executable_path` | auto | PuTTY install directory |
| `putty.enable_registry` | `true` | Turn the saved-sessions tools on or off |
| `serial.*` | 9600/8/n/1/N | Default serial settings |
| `sessions.max_concurrent` | `10` | Maximum number of interactive sessions at once |
| `sessions.timeout_seconds` | `3600` | Close a session after this many seconds without activity |
| `sessions.buffer_lines` | `1000` | Output buffer size per session |
| `monitor.enabled` | `true` | Turn the dashboard on or off |
| `monitor.port` | `8765` | Dashboard port (falls back to a free port if taken) |
| `monitor.open_browser` | `first_call` | `first_call`, `start` or `never` |
| `logging.enabled` / `logging.level` | `true` / `INFO` | Server logging to stderr |

## Security

- Commands are passed as argument lists, never through a shell (`shell=False`)
- Processes never inherit the server's stdin (the MCP protocol stream)
- Jump host strings containing shell or quote characters are rejected
- Generated `.ppk` files without a passphrase get owner-only file permissions
- The server stores no passwords or keys. Registry access is limited to `HKCU\Software\SimonTatham\PuTTY\Sessions`.
- Non-interactive tools use `-batch`, so an unknown host key fails instead of being accepted silently. Pass `host_keys` (from `get_host_key`) for hosts you haven't connected to yet.

## Known limitations

- **Passphrases** for `keygen_create`/`keygen_convert` go to `ssh-keygen` on the command line, so they briefly show up in the process list. They also pass through the AI conversation.
- **PPK conversion** only supports keys without a passphrase (Ed25519, RSA, ECDSA in OpenSSH format).
- **Pageant** has no CLI for listing keys. `pageant_list` uses `ssh-add -L` (Pageant must run with `--openssh-config`) and otherwise opens the Pageant window.
- **Interactive sessions** pass ANSI escape codes from the remote shell through unchanged. The dashboard filters them out.
- **Interactive sessions without `-batch`** can stop at a password or host key prompt. You'll see that in the dashboard and can kill the session there.

## Project layout

```
putty_mcp.py              MCP server and all tool definitions
putty_lib/
  config.py               Configuration and PuTTY path detection
  executor.py             Running, tracking and killing processes
  session_manager.py      Interactive sessions with background readers
  monitor.py              Activity log, process registry, kill switch
  monitor_web.py          Local dashboard (HTTP + token auth)
  monitor.html            Dashboard page
  registry.py             Saved PuTTY sessions in the Windows registry
  ppk.py                  OpenSSH → PPK v3 conversion in pure Python
  utils.py                Argument building, host parsing, proxy chains
```

## License

MIT
