#!/usr/bin/env python3
"""Own the optional /etc/netns prerequisite without adopting foreign paths."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys


SCHEMA = "nmas.resolver-root-ownership/1"
DEFAULT_ROOT = Path("/etc/netns")
DEFAULT_STATE = Path("/var/lib/nmas-stage-b-resolver-root.json")
CHANGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")


class Refused(RuntimeError):
    pass


def trusted_directory(path: Path, expected_uid: int, expected_gid: int, label: str) -> tuple[int, os.stat_result]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refused(f"{label} is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise Refused(f"{label} must be a real directory")
    if info.st_uid != expected_uid or info.st_gid != expected_gid or info.st_mode & 0o022:
        raise Refused(f"{label} must be trusted-owner and not group/world writable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path, flags)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        os.close(fd)
        raise Refused(f"{label} changed during verification")
    return fd, opened


def safe_state(parent_fd: int, name: str, expected_uid: int) -> dict:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise Refused("resolver ownership state is unavailable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o600:
            raise Refused("resolver ownership state is unsafe")
        try:
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                fd = -1
                value = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise Refused("resolver ownership state is invalid") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise Refused("resolver ownership state schema is invalid")
    return value


def entry_exists(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def target_info(parent_fd: int) -> os.stat_result | None:
    try:
        return os.stat("netns", dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def validate_target(parent_fd: int, state: dict, expected_uid: int, expected_gid: int) -> os.stat_result:
    info = target_info(parent_fd)
    if info is None or not stat.S_ISDIR(info.st_mode):
        raise Refused("owned resolver root is missing or changed type")
    if info.st_uid != expected_uid or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) != 0o755:
        raise Refused("owned resolver root ownership or mode changed")
    if (info.st_dev, info.st_ino) != (state.get("directory_dev"), state.get("directory_ino")):
        raise Refused("resolver root inode differs from the owned directory")
    return info


def write_state(parent_fd: int, name: str, value: dict, expected_uid: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, expected_uid, 0)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise


def context(args) -> tuple[int, int]:
    return ((os.geteuid(), os.getegid()) if args.test_mode else (0, 0))


def inspect(args) -> tuple[int, os.stat_result, int, os.stat_result, int, int]:
    expected_uid, expected_gid = context(args)
    parent_fd, parent = trusted_directory(args.root.parent, expected_uid, expected_gid, "resolver parent")
    try:
        state_parent_fd, state_parent = trusted_directory(
            args.state.parent, expected_uid, expected_gid, "resolver state parent"
        )
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd, parent, state_parent_fd, state_parent, expected_uid, expected_gid


def verify_owned(args) -> dict:
    parent_fd, parent, state_parent_fd, _state_parent, uid, gid = inspect(args)
    try:
        state = safe_state(state_parent_fd, args.state.name, uid)
        if state.get("change_id") != args.change_id or state.get("path") != str(args.root):
            raise Refused("resolver ownership state belongs to another change or path")
        if (parent.st_dev, parent.st_ino) != (state.get("parent_dev"), state.get("parent_ino")):
            raise Refused("resolver parent inode changed")
        validate_target(parent_fd, state, uid, gid)
        return state
    finally:
        os.close(parent_fd)
        os.close(state_parent_fd)


def plan(args) -> dict:
    parent_fd, _parent, state_parent_fd, _state_parent, _uid, _gid = inspect(args)
    try:
        target = target_info(parent_fd)
        state_exists = entry_exists(state_parent_fd, args.state.name)
    finally:
        os.close(parent_fd)
        os.close(state_parent_fd)
    if target is None and not state_exists:
        return {"schema": SCHEMA, "action": "plan", "result": "ready-to-create", "mutations": 0}
    if target is not None and state_exists:
        verify_owned(args)
        return {"schema": SCHEMA, "action": "plan", "result": "already-owned", "mutations": 0}
    raise Refused("resolver root/state pair is incomplete or foreign")


def install(args) -> dict:
    if not args.test_mode and os.geteuid() != 0:
        raise Refused("production resolver-root mutation requires root")
    parent_fd, parent, state_parent_fd, _state_parent, uid, gid = inspect(args)
    created = False
    try:
        existing = target_info(parent_fd)
        state_exists = entry_exists(state_parent_fd, args.state.name)
        if existing is not None or state_exists:
            if existing is None or not state_exists:
                raise Refused("resolver root/state pair is incomplete or foreign")
            os.close(parent_fd)
            parent_fd = -1
            os.close(state_parent_fd)
            state_parent_fd = -1
            verify_owned(args)
            return {"schema": SCHEMA, "action": "install", "result": "already-owned", "mutations": 0}
        os.mkdir("netns", mode=0o755, dir_fd=parent_fd)
        created = True
        info = target_info(parent_fd)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise Refused("created resolver root is not a directory")
        os.chmod("netns", 0o755, dir_fd=parent_fd, follow_symlinks=False)
        if os.geteuid() == 0:
            os.chown("netns", uid, gid, dir_fd=parent_fd, follow_symlinks=False)
        info = target_info(parent_fd)
        value = {"schema": SCHEMA, "change_id": args.change_id, "path": str(args.root),
                 "created_at": datetime.now(timezone.utc).isoformat(),
                 "parent_dev": parent.st_dev, "parent_ino": parent.st_ino,
                 "directory_dev": info.st_dev, "directory_ino": info.st_ino,
                 "uid": uid, "gid": gid, "mode": "0755"}
        write_state(state_parent_fd, args.state.name, value, uid)
        return {"schema": SCHEMA, "action": "install", "result": "created", "mutations": 2,
                "path": str(args.root), "state": str(args.state)}
    except BaseException:
        if created:
            try:
                os.rmdir("netns", dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        if state_parent_fd >= 0:
            os.close(state_parent_fd)


def verify(args) -> dict:
    state = verify_owned(args)
    return {"schema": SCHEMA, "action": "verify", "result": "owned", "mutations": 0,
            "path": state["path"], "change_id": state["change_id"]}


def rollback(args) -> dict:
    if not args.test_mode and os.geteuid() != 0:
        raise Refused("production resolver-root mutation requires root")
    parent_fd, parent, state_parent_fd, _state_parent, uid, gid = inspect(args)
    try:
        target = target_info(parent_fd)
        state_exists = entry_exists(state_parent_fd, args.state.name)
        if target is None and not state_exists:
            return {"schema": SCHEMA, "action": "rollback", "result": "already-absent", "mutations": 0}
        if target is None or not state_exists:
            raise Refused("resolver root/state pair is incomplete; refusing deletion")
        state = safe_state(state_parent_fd, args.state.name, uid)
        if state.get("change_id") != args.change_id or state.get("path") != str(args.root):
            raise Refused("resolver ownership state belongs to another change or path")
        if (parent.st_dev, parent.st_ino) != (state.get("parent_dev"), state.get("parent_ino")):
            raise Refused("resolver parent inode changed")
        validate_target(parent_fd, state, uid, gid)
        try:
            os.rmdir("netns", dir_fd=parent_fd)
        except OSError as exc:
            raise Refused("owned resolver root is not empty; refusing deletion") from exc
        os.unlink(args.state.name, dir_fd=state_parent_fd)
        return {"schema": SCHEMA, "action": "rollback", "result": "removed", "mutations": 2}
    finally:
        os.close(parent_fd)
        os.close(state_parent_fd)


def parse(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "install", "verify", "rollback"))
    parser.add_argument("--change-id", required=True)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--test-mode", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not CHANGE_RE.fullmatch(args.change_id):
        parser.error("--change-id is malformed")
    if args.root.name != "netns" or not args.root.is_absolute() or not args.state.is_absolute():
        parser.error("--root/--state must be absolute approved paths")
    if args.test_mode:
        prefix = "/tmp/nmas-resolver-root-test-"
        if not str(args.root).startswith(prefix) or not str(args.state).startswith(prefix):
            parser.error("test paths must be contained by an approved disposable fixture")
    elif args.root != DEFAULT_ROOT or args.state != DEFAULT_STATE:
        parser.error("production paths are fixed at /etc/netns and the approved ownership receipt")
    return args


def main(argv=None) -> int:
    args = parse(argv)
    try:
        result = {"plan": plan, "install": install, "verify": verify, "rollback": rollback}[args.action](args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
