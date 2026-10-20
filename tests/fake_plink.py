"""Stand-in for plink/pscp/psftp in tests (cross-platform, no network).

Behaviour is chosen by the host name / command:
  host "shell-*"      interactive shell: echoes commands, prints "fake$ " prompts
  host "ios-*"        Cisco IOS-like shell (R1#, config modes, --More--, % errors);
                      exec with several lines fails with "invalid autocommand"
  host "unknown-key"  prints PuTTY's unknown-host-key message unless -hostkey is given
  command "sleep N"   sleeps N seconds (for kill tests); "spawn-child" also starts a child
  otherwise           prints "ran: <command>"
"""

import subprocess
import sys
import time

FP = "SHA256:K4g+sYHWnUD2AzQJKOsFCD5LAIUb7p7kdzG89AvEeic"
args = sys.argv[1:]
hostkeys = [args[i + 1] for i, a in enumerate(args) if a == "-hostkey"]

host = None
skip = {"-P", "-l", "-i", "-hostkey", "-load", "-m", "-L", "-R", "-D", "-nc", "-proxycmd", "-sercfg", "-serial"}
i = 0
while i < len(args):
    if args[i] in skip:
        i += 2
        continue
    if args[i].startswith("-"):
        i += 1
        continue
    host = args[i]
    break
command = " ".join(args[i + 1:]) if host else ""
host = (host or "").split("@")[-1].split(":")[0]

if host == "unknown-key" and hostkeys and FP not in hostkeys:
    sys.stderr.write("FATAL ERROR: Host key not in manually configured list\n")
    sys.exit(1)
if host == "unknown-key" and not hostkeys:
    sys.stderr.write(
        "The host key is not cached for this server:\n  unknown-key (port 22)\n"
        "You have no guarantee that the server is the computer you\nthink it is.\n"
        "The server's ssh-ed25519 key fingerprint is:\n"
        f"  ssh-ed25519 255 {FP}\nConnection abandoned.\nFATAL ERROR: Cannot confirm a host key in batch mode\n"
    )
    sys.exit(1)

def ios_shell():
    import os

    def out(text):
        sys.stdout.write(text)
        sys.stdout.flush()

    def readline():
        buf = b""
        while True:
            ch = os.read(0, 1)
            if not ch:
                return None
            if ch == b"\n":
                return buf.decode()
            buf += ch

    mode = ""
    out("\r\nR1#")
    while True:
        line = readline()
        if line is None or line.strip() in ("exit", "logout") and not mode:
            return
        cmd = line.strip()
        out(cmd + "\r\n")
        if cmd in ("conf t", "configure terminal"):
            out("Enter configuration commands, one per line.  End with CNTL/Z.\r\n")
            mode = "(config)"
        elif cmd.startswith("interface "):
            mode = "(config-if)"
        elif cmd in ("end", "exit") and mode:
            mode = "" if cmd == "end" or mode == "(config)" else "(config)"
        elif cmd == "show running-config":
            for page in range(3):
                out("".join(f"line {page * 3 + i}\r\n" for i in range(3)))
                if page < 2:
                    out(" --More-- ")
                    if os.read(0, 1) != b" ":
                        return
                    out("\x08" * 10 + " " * 10 + "\x08" * 10)
        elif cmd == "copy running-config startup-config":
            out("Destination filename [startup-config]? ")
            readline()
            out("\r\n[OK]\r\n")
        elif cmd == "write memory":
            out("Building configuration...\r\n[OK]\r\n")
        elif cmd and not cmd.startswith(("description", "no ", "show")):
            out("              ^\r\n% Invalid input detected at '^' marker.\r\n")
        out(f"R1{mode}#")


if host.startswith("ios-"):
    if command:
        sys.stdout.write(f'Line has invalid autocommand "{command}"\n' if "\n" in command else f"output of {command}\n")
        sys.exit(1 if "\n" in command else 0)
    ios_shell()
    sys.exit(0)

if "-N" in args:
    time.sleep(3600)

if host.startswith("shell-"):
    sys.stdout.write("Welcome\nfake$ ")
    sys.stdout.flush()
    for line in sys.stdin:
        cmd = line.strip()
        if cmd.startswith("sleep "):
            time.sleep(float(cmd.split()[1]))
        sys.stdout.write(f"{cmd}\nout: {cmd.upper()}\nfake$ ")
        sys.stdout.flush()
    sys.exit(0)

if command.startswith("spawn-child"):
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    command = "sleep 60"
if command.startswith("sleep"):
    print("sleeping", flush=True)
    time.sleep(float(command.split()[1]))
if command == "big-output":
    print("x" * 200_000)
    sys.exit(0)
if command == "color":
    print("\x1b[01;32mgreen\x1b[0m text")
    sys.exit(0)
print(f"ran: {command}")
