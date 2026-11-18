#!/usr/bin/env python3
"""Disposable focused tests for the worker runtime installer."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
INSTALLER = HERE / "worker_runtime.py"


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def record_value(data: bytes) -> str:
    value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    return "sha256=" + value


def run(*args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["/usr/bin/python3", str(INSTALLER), *args], text=True, capture_output=True, check=False)
    if ok and result.returncode:
        raise AssertionError(result.stderr)
    if not ok and result.returncode == 0:
        raise AssertionError("expected refusal")
    return result


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="nmas-worker-installer-test-") as temporary:
        root = Path(temporary)
        source = root / "source"
        write(source / "web/manage.py", b"print('worker help')\n")
        write(source / "web/var/device-locks/transient.lock", b"runtime-only\n")
        write(source / "netbox/.env", b"NETBOX_TOKEN=must-not-enter-worker-runtime\n")
        (source / "netbox/.env").chmod(0o600)
        write(source / "inventory.yml", b"network_devices: {}\n")
        source_venv = root / "source-venv"
        site = source_venv / "lib/python3.12/site-packages"
        package = b"VALUE = 1\n"
        metadata = b"Name: demo-dependency\nVersion: 1.0\n"
        write(site / "demo_dependency/__init__.py", package)
        write(site / "demo_dependency-1.0.dist-info/METADATA", metadata)
        record = site / "demo_dependency-1.0.dist-info/RECORD"
        record.parent.mkdir(parents=True, exist_ok=True)
        with record.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows([
                ("demo_dependency/__init__.py", record_value(package), str(len(package))),
                ("demo_dependency-1.0.dist-info/METADATA", record_value(metadata), str(len(metadata))),
                ("demo_dependency-1.0.dist-info/RECORD", "", ""),
            ])
        lock = root / "lock"
        lock.write_text("demo-dependency==1.0\n", encoding="utf-8")
        manifest = root / "manifest.json"
        run("build-manifest", "--source", str(source), "--output", str(manifest),
            "--release-id", "TEST-RELEASE-0001")
        built = json.loads(manifest.read_text(encoding="utf-8"))
        assert all(not row["path"].startswith("web/var/") for row in built["files"])
        assert all(Path(row["path"]).name != ".env" for row in built["files"])
        overlay = root / "overlay"
        write(overlay / "web/manage.py", b"print('overlay worker help')\n")
        overlay_manifest = root / "overlay.json"
        run("build-overlay-manifest", "--overlay-root", str(overlay), "--overlay-path", "web/manage.py",
            "--output", str(overlay_manifest), "--release-id", "TEST-OVERLAY-0001")
        runtime, state = root / "opt/nmas", root / "state"
        common = ("--source", str(source), "--source-manifest", str(manifest), "--source-venv", str(source_venv),
                  "--lock", str(lock), "--runtime", str(runtime), "--state-root", str(state), "--test-mode")
        # The fake app cannot pass the production smoke imports, so replace the smoke-only
        # lock/source with the real local production dependency source for the lifecycle test.
        # Source and ownership behavior is still entirely disposable.
        production_lock = HERE / "worker-runtime.lock"
        production_venv = Path("/home/student/Scripts/.venv")
        common = ("--source", str(source), "--source-manifest", str(manifest), "--source-venv", str(production_venv),
                  "--overlay-root", str(overlay), "--overlay-manifest", str(overlay_manifest),
                  "--lock", str(production_lock), "--runtime", str(runtime), "--state-root", str(state), "--test-mode")
        run("install", *common)
        assert (runtime / "current/web/manage.py").read_text() == "print('overlay worker help')\n"
        # Regression (2026-11-16 live activation): the staged root kept mkdtemp's 0700, so the unprivileged worker
        # account could not traverse /opt/nmas to its interpreter.  Every directory on the path must be traversable.
        assert runtime.stat().st_mode & 0o777 == 0o755, oct(runtime.stat().st_mode)
        for directory in (runtime / "current", runtime / "venv", runtime / "venv/bin"):
            assert directory.stat().st_mode & 0o005 == 0o005, (directory, oct(directory.stat().st_mode))
        first = json.loads((state / "install-state.json").read_text())
        result = run("install", *common)
        assert json.loads(result.stdout)["result"] == "already-installed"
        assert first == json.loads((state / "install-state.json").read_text())
        run("verify", *common)
        foreign = runtime / "current/foreign"
        foreign.write_text("not owned", encoding="utf-8")
        assert "drift" in run("verify", *common, ok=False).stderr
        foreign.unlink()
        run("uninstall", *common)
        run("uninstall", *common)
        assert not runtime.exists()

        # Never adopt an existing foreign runtime and never follow a source symlink.
        runtime.mkdir(parents=True)
        assert "without NMAS ownership" in run("install", *common, ok=False).stderr
        runtime.rmdir()
        (source / "bad-link").symlink_to("web/manage.py")
        refused_manifest = root / "refused.json"
        assert "regular non-symlink" in run("build-manifest", "--source", str(source), "--output", str(refused_manifest),
                                                  "--release-id", "TEST-RELEASE-0002", ok=False).stderr
    print("PASS: worker runtime install/idempotency/drift/rollback/foreign-object/symlink tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
