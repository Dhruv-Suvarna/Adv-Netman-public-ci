#!/usr/bin/env python3
"""Keep the Troubleshooter diagnostic worker's RESTRICTED credential copy in sync after a rotation (run as root).

The worker never sees the full device credential store: its unit bind-mounts a copy that holds ONLY the allowlisted secret
ids (default: r2-nmas-automation).  When nmas-credential-rotation rotates that secret in the full store, this copies exactly
those entries (current + pending), writes the copy atomically (0600, owner nmas-ts-diagnostic) and try-restarts the worker
(a bind mount pins the old inode, so a restart is what makes the new file visible).  Unchanged => no write, no restart.
Secret values are never printed or logged.  Triggered by nmas-ts-worker-credential-sync.path (store changed) and an hourly timer.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import subprocess
import sys
import tempfile

FULL = "/home/student/Scripts/clab_dualstack_lab-deploy/monitoring/runtime/device-credentials/store.json"
COPY = "/etc/nmas/troubleshooter-worker-store.r2.json"
OWNER = "nmas-ts-diagnostic"
UNIT = "nmas-troubleshooter-device-worker.service"


class SyncError(Exception):
    pass


def restricted(full: dict, allow: list[str]) -> dict:
    secrets = full.get("secrets")
    if not isinstance(secrets, dict):
        raise SyncError("full store has no secrets map")
    missing = [s for s in allow if s not in secrets]
    if missing:
        raise SyncError(f"allowlisted secret id(s) absent from the full store: {missing}")
    return {"schema_version": full.get("schema_version"),
            "secrets": {s: {"current": secrets[s].get("current"), "pending": secrets[s].get("pending")} for s in allow}}


def write_atomic(path: str, data: dict, owner: str) -> None:
    pw = pwd.getpwnam(owner)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".worker-store.")
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, pw.pw_uid, pw.pw_gid)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        tmp = ""
    finally:
        if tmp:
            os.unlink(tmp)


def sync(full_path: str, copy_path: str, allow: list[str], owner: str, restart) -> str:
    with open(full_path) as fh:
        want = restricted(json.load(fh), allow)
    try:
        with open(copy_path) as fh:
            have = json.load(fh)
    except (OSError, ValueError):
        have = None
    if have == want:
        return "UNCHANGED"
    write_atomic(copy_path, want, owner)
    restart()
    return "SYNCED"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--full", default=FULL)
    ap.add_argument("--copy", default=COPY)
    ap.add_argument("--allow", action="append", default=None, help="secret id to copy (repeatable; default r2-nmas-automation)")
    ap.add_argument("--owner", default=OWNER)
    ap.add_argument("--no-restart", action="store_true")
    args = ap.parse_args(argv)
    allow = args.allow or ["r2-nmas-automation"]
    restart = (lambda: None) if args.no_restart else (lambda: subprocess.run(["systemctl", "try-restart", UNIT], check=True))
    try:
        result = sync(args.full, args.copy, allow, args.owner, restart)
    except (SyncError, OSError, ValueError, KeyError) as exc:
        print(f"worker credential sync FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"worker credential sync {result}: {', '.join(allow)}")          # ids only, never values
    return 0


if __name__ == "__main__":
    sys.exit(main())
