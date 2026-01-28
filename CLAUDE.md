# PuTTY MCP Server

## What This Is
MCP server exposing the full PuTTY toolchain (30 tools) via stdio transport.
Registered in Claude Code as `putty` MCP server.

## Architecture
- `putty_mcp.py` — FastMCP server, all 30 tool definitions
- `putty_lib/config.py` — PuTTY + ssh-keygen path resolution, TOML config loading
- `putty_lib/executor.py` — subprocess wrapper (run, spawn, launch_gui)
- `putty_lib/session_manager.py` — persistent interactive session management with background readers
- `putty_lib/registry.py` — Windows Registry CRUD for PuTTY saved sessions
- `putty_lib/utils.py` — arg building, host parsing, proxy chain construction
- `putty_lib/ppk.py` — native Python PPK v3 writer (converts OpenSSH keys to .ppk without GUI)

## Key Decisions
- **Windows puttygen.exe is GUI-only.** No CLI batch key generation or conversion. All keygen tools use `ssh-keygen` (Windows OpenSSH) instead.
- **PPK conversion** is handled by `putty_lib/ppk.py`, a from-scratch PPK v3 format writer. Supports ed25519, RSA, ECDSA. Unencrypted keys only.
- **pageant --list doesn't exist on Windows.** `pageant_list` tries `ssh-add -L` first (works if Pageant bridges to OpenSSH agent), falls back to opening the GUI key list.
- `keygen_create` auto-generates `.ppk` alongside the OpenSSH key so plink/pscp/psftp can use it immediately.

## Keys
- `keys/omegasupreme_root` — OpenSSH ed25519 private key for root@192.168.1.161 (OmegaSupreme / TrueNAS)
- `keys/omegasupreme_root.pub` — corresponding public key (installed on OmegaSupreme via TrueNAS API)
- `keys/omegasupreme_root.ppk` — PuTTY PPK v3 format of same key

## Testing
All tools tested live against OmegaSupreme (192.168.1.161):
- Host key: `SHA256:42MmFr9bIW1Wk+EyStGTBgDQi8Us/X3+WGZ9TmVjW1g`
- plink_exec, test_connection, persistent sessions, pscp upload/download/list, psftp batch, registry CRUD — all passing
- Not tested: serial tools (no device), multi-hop (needs second host), plink_tunnel (needs use case)

## Running
```
# Standalone
python putty_mcp.py

# As MCP server (configured in ~/.claude.json)
# command: C:\Python313\python.exe -m putty_mcp
# env: PYTHONPATH=D:\MCP_servers\putty-mcp
```

## Known Rough Edges
- Persistent sessions return raw ANSI escape codes (remote shell formatting). Functional but noisy.
- PPK converter only handles unencrypted keys. Passphrase-protected keys need manual puttygen GUI conversion.
- `pageant_add` launches the Pageant GUI; passphrase prompts are interactive GUI dialogs.
