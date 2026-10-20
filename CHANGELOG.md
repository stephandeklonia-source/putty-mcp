# Changelog

Every change raises the version in `putty_lib/__init__.py` (`__version__`) and adds an entry here. CI checks both on pull requests.

Versions use the format **YYYY.MM.rev**: the year, the month and a three-digit revision that starts again at 001 every month. For example 2026.10.001, then 2026.10.002, then 2026.11.001.

pip writes versions without leading zeros (`2026.10.1`); the dashboard and this file show `2026.10.001`.

## 2026.10.001

- Versions switch to the YYYY.MM.rev format.
- The version number is now shown in the dashboard header and the server log, reported to MCP clients and used for `pip install`.
- CI fails a pull request that changes code without raising the version or without a changelog entry, or with a version not in the YYYY.MM.rev format.
- CI: the real-SSH tests create `/run/sshd` and wait for sshd to start (they failed on an unprivileged runner).

## 1.2.1

(Older versions used semantic versioning.)

- The dashboard link stays valid across restarts: the token is stored in the data folder. *Settings → Reset link* creates a new one.
- On Windows the dashboard port is claimed exclusively, so a second server can no longer answer on the same port ("Missing or invalid token" after a restart).
- An invalid link shows an explanation page.

## 1.2.0

- The dashboard is the operator's interface, with tabs for live activity, settings and the audit log.
- Safety policy: allowed and blocked hosts, command rules, allowed local folders, approval modes. Approvals can remember a host or folder.
- Host keys are verified by the operator, never by the AI. Trusted keys are passed with `-hostkey`; a changed key is refused and raises an alert.
- Native key management without `ssh-keygen`. Passphrases are entered in the dashboard. Encrypted PPK v3 files are supported.
- `shell_run` runs a list of commands in one shell, for Cisco IOS and other network devices.
- Ended sessions remain visible with an explanation. `session_send` waits for the prompt.
- Daily JSONL audit log, pytest suite, CI on Linux and Windows.

## 1.1.0

- Code review fixes: stdin leak, `plink_tunnel` argument order, Ed25519 PPK, registry session names, port defaults.
- Support for mcp 1.x and 2.x.
- First version of the live monitor dashboard with the kill switch.

## 1.0.0

- First release: 30 tools covering the PuTTY toolchain.
