#!/usr/bin/env python3
"""Disposable live-systemd proof for the research unit's mount protections.

The fixture creates a temporary network namespace and transient systemd units.
It never changes host routes, addresses, firewall policy, persistent units or
the host resolver. Root is required only for the disposable namespace and
transient service-manager operations.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import uuid


SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
IP = "/usr/sbin/ip"


def run(argv: list[str], *, ok: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True, check=False)
    if ok and result.returncode:
        raise AssertionError(
            f"command failed ({result.returncode}): {argv!r}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    if not ok and result.returncode == 0:
        raise AssertionError(f"command unexpectedly passed: {argv!r}\n{result.stdout}")
    return result


def sudo(*argv: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["/usr/bin/sudo", "-n", *argv], ok=ok)


def cleanup(*argv: str) -> None:
    subprocess.run(["/usr/bin/sudo", "-n", *argv], text=True, capture_output=True, check=False)


def transient(
    unit: str,
    namespace: str,
    resolver: Path,
    protected: Path,
    unrelated: Path,
    *,
    optional: bool,
    ok: bool = True,
) -> subprocess.CompletedProcess[str]:
    inaccessible = f"-{protected}" if optional else str(protected)
    probe = r"""
set -eu
test "$(cat /etc/resolv.conf)" = "nameserver 192.0.2.53"
findmnt -n -o OPTIONS /etc/resolv.conf | tr ',' '\n' | grep -Fx ro >/dev/null
test "$(stat -Lc %i /proc/self/ns/net)" = "$(stat -Lc %i "$1")"
if cat "$2" >/dev/null 2>&1; then exit 21; fi
test "$(cat "$3")" = unrelated-readable
test ! -r /run/docker.sock
""".strip()
    return sudo(
        SYSTEMD_RUN,
        f"--unit={unit}",
        "--wait",
        "--property=Type=oneshot",
        "--property=DynamicUser=yes",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateDevices=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=CapabilityBoundingSet=",
        "--property=RestrictNamespaces=yes",
        f"--property=NetworkNamespacePath=/run/netns/{namespace}",
        f"--property=BindReadOnlyPaths={resolver}:/etc/resolv.conf",
        f"--property=InaccessiblePaths={inaccessible}",
        "--property=InaccessiblePaths=-/run/docker.sock",
        "/bin/sh",
        "-c",
        probe,
        "nmas-systemd-fixture",
        f"/run/netns/{namespace}",
        str(protected),
        str(unrelated),
        ok=ok,
    )


def main() -> int:
    token = uuid.uuid4().hex[:10]
    namespace = f"nmas-sd-{token}"
    units: list[str] = []
    temporary = Path(f"/run/nmas-systemd-mounts-{token}")
    sudo(
        "/usr/bin/install",
        "-d",
        "-o",
        str(os.getuid()),
        "-g",
        str(os.getgid()),
        "-m",
        "0755",
        str(temporary),
    )
    resolver = temporary / "resolv.conf"
    protected = temporary / "diagnostic.env"
    unrelated = temporary / "unrelated.txt"
    resolver.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
    unrelated.write_text("unrelated-readable\n", encoding="utf-8")
    resolver.chmod(0o644)
    unrelated.chmod(0o644)
    try:
        sudo(IP, "netns", "add", namespace)

        missing_unit = f"nmas-systemd-missing-{token}.service"
        units.append(missing_unit)
        transient(missing_unit, namespace, resolver, protected, unrelated, optional=True)

        protected.write_text("diagnostic-credential-fixture\n", encoding="utf-8")
        protected.chmod(0o644)
        existing_unit = f"nmas-systemd-existing-{token}.service"
        units.append(existing_unit)
        transient(existing_unit, namespace, resolver, protected, unrelated, optional=True)

        protected.unlink()
        fail_closed_unit = f"nmas-systemd-required-{token}.service"
        units.append(fail_closed_unit)
        failed = transient(
            fail_closed_unit,
            namespace,
            resolver,
            protected,
            unrelated,
            optional=False,
            ok=False,
        )
        combined = f"{failed.stdout}\n{failed.stderr}"
        if "226/NAMESPACE" not in combined and "Failed to set up mount namespacing" not in combined:
            status = sudo(
                SYSTEMCTL,
                "show",
                fail_closed_unit,
                "-p",
                "ExecMainStatus",
                "-p",
                "Result",
            ).stdout
            if "ExecMainStatus=226" not in status or "Result=exit-code" not in status:
                raise AssertionError(f"required missing path did not fail closed as 226/NAMESPACE: {combined}\n{status}")

        print("PASS: missing optional inaccessible path permits startup")
        print("PASS: existing optional inaccessible path cannot be read")
        print("PASS: NetworkNamespacePath and read-only resolver bind coexist")
        print("PASS: unrelated readable path remains readable; Docker socket stays inaccessible")
        print("PASS: mandatory missing inaccessible path fails closed with 226/NAMESPACE")
        return 0
    finally:
        for unit in units:
            cleanup(SYSTEMCTL, "stop", unit)
            cleanup(SYSTEMCTL, "reset-failed", unit)
        cleanup(IP, "netns", "delete", namespace)
        shutil.rmtree(temporary, ignore_errors=True)
        cleanup("/usr/bin/rmdir", str(temporary))


if __name__ == "__main__":
    raise SystemExit(main())
