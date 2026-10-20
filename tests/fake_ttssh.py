"""Stand-in for CCC's TrainTools SSH utility (ttssh) in tests.

Mimics the real output: banner, "Host public key SHA-1: <hex>" (derived from
the host name, so different hosts have different keys), a ">" prompt and a
few commands. Host "down" fails to connect.
"""

import hashlib
import os
import sys

host = sys.argv[1] if len(sys.argv) > 1 else ""


def out(text):
    sys.stdout.write(text)
    sys.stdout.flush()


out("TrainTools SSH Utility\nversion 16.1.4.0\nCompressor Controls LLC, 2023-2025.\n\n")
if host == "down":
    out(f"Unable to connect to {host}\n")
    sys.exit(1)
fp = hashlib.sha1(host.encode()).hexdigest()
out(f"Host public key SHA-1: {fp}\nSSH-2.0-Series 6 New Prodigy\n"
    "Connection to Prodigy is restricted to authorized personnel.\n\n"
    f"Connected to {host}\nWelcome to TTSsh\n>")

buf = b""
while True:
    ch = os.read(0, 1)
    if not ch:
        sys.exit(0)
    if ch != b"\n":
        buf += ch
        continue
    cmd = buf.decode().strip().rstrip("\r")
    buf = b""
    if cmd == "help":
        out("\n\nCommands:\n\tver\n\tls\n\treboot\n\tdate\n\n>")
    elif cmd == "debug":
        lines = [f"[{i:05d}] boot: init subsystem {i}\n" for i in range(1500)]
        lines[700:700] = ["[00700] EtherCAT: bus scan started\n",
                          "[00701] EtherCAT: slave 1 IOP-16DI found\n",
                          "[00702] EtherCAT: slave 2 IBS-8AO found\n"]
        out("\n" + "".join(lines) + ">")
    elif cmd == "ver":
        out("\nProdigy firmware 6.2.1\n>")
    elif cmd.startswith("ls"):
        out("\napp  cfg  log\n>")
    elif cmd == "reboot":
        out("\nRebooting...\n")
        sys.exit(0)
    elif cmd:
        out(f"\nUnknown command: {cmd}\n>")
    else:
        out("\n>")
