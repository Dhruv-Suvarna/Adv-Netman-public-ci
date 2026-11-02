#!/usr/bin/env python3
"""Timer-safe restoration of one reviewed R3/R4 SSH/PAM transaction.

The opaque token selects a device-local backup directory.  No secret or file
content is accepted on argv or printed.  This script intentionally has no
Django dependency so a transient user-systemd timer can run it after the
initiating process has died.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys


TARGETS = {"R3": "clab-srlceos01-R3", "R4": "clab-srlceos01-R4"}
TOKEN_RE = re.compile(r"^[a-f0-9]{24}$")

ROLLBACK_PROGRAM = r'''
import json, os, pathlib, pwd, shutil, signal, subprocess, sys
root = pathlib.Path(sys.argv[1])
manifest_path = root / "manifest.json"
if not manifest_path.is_file():
    raise SystemExit(20)
manifest = json.loads(manifest_path.read_text())
for item in manifest["files"]:
    destination = pathlib.Path(item["path"])
    backup = root / "files" / item["path"].lstrip("/")
    if item["existed"]:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name("." + destination.name + ".nmas-restore")
        shutil.copy2(backup, temporary)
        os.replace(temporary, destination)
    else:
        try: destination.unlink()
        except FileNotFoundError: pass
for user in manifest["created_users"]:
    try: pwd.getpwnam(user)
    except KeyError: continue
    subprocess.run(["userdel", "-r", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
check = subprocess.run(["sshd", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if check.returncode:
    raise SystemExit(21)
pids = subprocess.run(["pgrep", "-o", "sshd"], capture_output=True, text=True, check=False).stdout.strip()
if not pids:
    raise SystemExit(22)
os.kill(int(pids), signal.SIGHUP)
(root / "rolled_back").write_text("1\n")
'''


def rollback(device: str, token: str) -> int:
    container = TARGETS.get(device)
    if container is None or not TOKEN_RE.fullmatch(token):
        return 2
    backup = f"/run/nmas-linux-mfa/{device.lower()}/{token}"
    completed = subprocess.run(
        ["docker", "exec", "-i", container, "python3", "-", backup],
        input=ROLLBACK_PROGRAM,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", choices=tuple(TARGETS), required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    rc = rollback(args.device, args.token)
    print(f"Linux MFA rollback for {args.device}: {'PASS' if rc == 0 else 'FAIL'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
