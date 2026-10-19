"""Stand-in for plink/pscp/psftp in tests (cross-platform, no network).

Behaviour is chosen by the host name / command:
  host "shell-*"      interactive shell: echoes commands, prints "fake$ " prompts
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
