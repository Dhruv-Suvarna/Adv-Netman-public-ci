#!/usr/bin/env python3
"""Disposable ownership and rollback tests for resolver_root.py."""

from pathlib import Path
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
TOOL = HERE / "resolver_root.py"
CHANGE = "CHG-NMAS-20261115-STAGE-B-001"


def run(action: str, root: Path, state: Path, *, ok: bool = True):
    result = subprocess.run(["/usr/bin/python3", str(TOOL), action, "--change-id", CHANGE,
                             "--root", str(root), "--state", str(state), "--test-mode"],
                            text=True, capture_output=True)
    if ok and result.returncode:
        raise AssertionError(result.stderr)
    if not ok and result.returncode == 0:
        raise AssertionError("expected refusal")
    return result


def fixture(base: Path, name: str) -> tuple[Path, Path]:
    parent = base / name / "etc"
    parent.mkdir(parents=True, mode=0o755)
    parent.parent.chmod(0o755)
    parent.chmod(0o755)
    return parent / "netns", base / name / "resolver-root.json"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="nmas-resolver-root-test-") as temporary:
        base = Path(temporary)
        root, state = fixture(base, "lifecycle")
        assert "ready-to-create" in run("plan", root, state).stdout
        assert "created" in run("install", root, state).stdout
        assert root.is_dir() and not root.is_symlink() and root.stat().st_mode & 0o777 == 0o755
        assert state.is_file() and state.stat().st_mode & 0o777 == 0o600
        assert "already-owned" in run("install", root, state).stdout
        assert "owned" in run("verify", root, state).stdout
        assert "removed" in run("rollback", root, state).stdout
        assert not root.exists() and not state.exists()
        assert "already-absent" in run("rollback", root, state).stdout

        foreign, foreign_state = fixture(base, "foreign")
        foreign.mkdir(mode=0o755)
        assert "foreign" in run("install", foreign, foreign_state, ok=False).stderr
        assert foreign.is_dir() and not foreign_state.exists()

        link, link_state = fixture(base, "symlink")
        target = link.parent / "elsewhere"
        target.mkdir()
        link.symlink_to(target, target_is_directory=True)
        assert run("install", link, link_state, ok=False).returncode == 65
        assert link.is_symlink() and target.is_dir()

        state_link_root, state_link = fixture(base, "state-symlink")
        state_target = state_link.parent / "foreign-receipt"
        state_target.write_text("preserve", encoding="utf-8")
        state_link.symlink_to(state_target)
        assert run("install", state_link_root, state_link, ok=False).returncode == 65
        assert state_link.is_symlink() and state_target.read_text(encoding="utf-8") == "preserve"

        state_parent_root, _unused_state = fixture(base, "state-parent-symlink")
        real_state_parent = base / "real-state-parent"
        real_state_parent.mkdir(mode=0o755)
        linked_state_parent = base / "linked-state-parent"
        linked_state_parent.symlink_to(real_state_parent, target_is_directory=True)
        linked_state = linked_state_parent / "receipt.json"
        assert "real directory" in run("install", state_parent_root, linked_state, ok=False).stderr
        assert not state_parent_root.exists() and not linked_state.exists()

        occupied, occupied_state = fixture(base, "occupied")
        run("install", occupied, occupied_state)
        marker = occupied / "foreign"
        marker.write_text("preserve", encoding="utf-8")
        assert "not empty" in run("rollback", occupied, occupied_state, ok=False).stderr
        assert marker.read_text(encoding="utf-8") == "preserve" and occupied_state.exists()

        replaced, replaced_state = fixture(base, "replaced")
        run("install", replaced, replaced_state)
        original = replaced.parent / "owned-original"
        replaced.rename(original)
        replaced.mkdir(mode=0o755)
        assert "inode differs" in run("verify", replaced, replaced_state, ok=False).stderr
        assert "inode differs" in run("rollback", replaced, replaced_state, ok=False).stderr
        assert replaced.is_dir() and original.is_dir() and replaced_state.exists()

        parent_link = base / "parent-link"
        real_parent = base / "real-parent"
        real_parent.mkdir(mode=0o755)
        parent_link.symlink_to(real_parent, target_is_directory=True)
        bad_root = parent_link / "netns"
        assert "real directory" in run("install", bad_root, base / "bad-state.json", ok=False).stderr

    print("PASS: resolver-root create/idempotency/ownership/foreign/symlink/nonempty/inode/rollback tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
