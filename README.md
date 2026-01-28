# PuTTY MCP Server

MCP server exposing the full PuTTY toolchain as 30 tools for Claude Code and other MCP clients.

## Covered Executables

- **putty.exe** — GUI terminal sessions
- **plink** — Command-line SSH/Telnet/serial
- **pscp** — SCP/SFTP file transfer
- **psftp** — Interactive SFTP
- **pageant** — SSH agent (key management)
- **puttygen** — Key generation and conversion

## Setup

1. Install PuTTY (all tools) and ensure they're on PATH or set `executable_path` in config.
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Copy `config.template.toml` to `config.toml` and adjust paths if needed.
4. Add to your MCP client config:
   ```json
   {
     "mcpServers": {
       "putty-mcp": {
         "command": "python",
         "args": ["D:/MCP_servers/putty-mcp/putty_mcp.py"]
       }
     }
   }
   ```

## Tool Categories

| Category | Count | Tools |
|----------|-------|-------|
| GUI Launch | 3 | putty_open, putty_open_session, putty_serial |
| Command Exec | 3 | plink_exec, plink_script, plink_tunnel |
| Sessions | 5 | session_open/send/read/list/close |
| File Transfer | 5 | pscp_upload/download/list, psftp_batch/interactive |
| Key Mgmt | 6 | keygen_create/fingerprint/convert/public_key, pageant_add/list |
| Registry | 4 | saved_sessions_list/get/create/delete |
| Utility | 2 | test_connection, get_host_key |
| Multi-Hop | 2 | proxy_session, chain_exec |

## Configuration

See `config.template.toml` for all options. Key settings:

- `putty.executable_path` — Override auto-detection
- `putty.enable_registry` — Disable for non-Windows or air-gapped systems
- `sessions.max_concurrent` — Limit simultaneous interactive sessions
- `serial.*` — Default serial port parameters

## Air-Gapped / Lab Use

Set `enable_registry = false` if needed. All tools work without internet — they wrap local PuTTY executables.
