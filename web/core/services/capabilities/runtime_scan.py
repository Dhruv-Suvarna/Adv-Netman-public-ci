"""Read-only IOS XR artifact/runtime investigation for the exhaustive ledger."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from . import assessment, features
from .offline_verify import verify_cell

IMAGE_ROOT = Path("/home/student/clab-quickstart/images")
XR_TOKENS = ("iosxr", "ios-xr", "xrv", "xrv9k", "xr7", "iosxrv")


def inspect_iosxr_runtime() -> dict:
    """Inspect the canonical image hierarchy and local Docker image names."""
    files = sorted(str(path) for path in IMAGE_ROOT.rglob("*") if path.is_file() and
                   any(token in path.name.lower() for token in XR_TOKENS)) if IMAGE_ROOT.is_dir() else []
    images = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                            capture_output=True, text=True, timeout=15, check=False)
    if images.returncode:
        raise RuntimeError("Docker image inventory was unavailable; runtime absence is not established.")
    docker = sorted(line for line in images.stdout.splitlines() if any(t in line.lower() for t in XR_TOKENS))
    stamp = hashlib.sha256("\n".join([*files, *docker, str(IMAGE_ROOT)]).encode()).hexdigest()[:16]
    return {"files": files, "docker_images": docker, "reference": f"runtime:iosxr-artifact-scan/{stamp}"}


def verify_unavailable_iosxr(*, head: str, actor: str, record: bool = True) -> list[assessment.CellAssessment]:
    scanned = inspect_iosxr_runtime()
    if scanned["files"] or scanned["docker_images"]:
        raise RuntimeError("IOS XR artifact exists; live boot investigation is required instead of absence classification.")
    cells = []
    for feature in features.catalogue():
        cell = verify_cell("cisco_iosxr", feature, head=head)
        reference = scanned["reference"]
        cell.probes["live_read"] = assessment.probe("BLOCKED", "Canonical image and Docker inventories contain no IOS XR runtime; NMAS has no IOS XR live reader.",
                                                      reason="RUNTIME_IMAGE_UNAVAILABLE", test_type="STATIC", reference=reference)
        cell.probes["live_write"] = assessment.probe("BLOCKED", "No IOS XR runtime or registered NMAS executor is available for a write attempt.",
                                                       reason="EXECUTOR_ABSENT", test_type="STATIC", reference=reference)
        cell.probes["live_post_write_validation"] = assessment.probe("BLOCKED", "No IOS XR runtime and no NMAS post-write adapter exist.",
                                                                       reason="POSTCHECK_ABSENT", test_type="STATIC", reference=reference)
        cell.probes["compensation"] = assessment.probe("BLOCKED", "No IOS XR runtime and no NMAS compensation adapter exist.",
                                                        reason="COMPENSATION_ABSENT", test_type="STATIC", reference=reference)
        cell.probes["runtime_validation"] = assessment.probe("BLOCKED", "Canonical image and Docker inventories were scanned; no IOS XR runtime artifact exists.",
                                                              reason="RUNTIME_IMAGE_UNAVAILABLE", test_type="STATIC", reference=reference)
        if not cell.complete or cell.status != "UNSUPPORTED":
            raise RuntimeError("IOS XR cell failed the fail-closed completeness contract.")
        if record:
            assessment.persist(cell, actor=actor)
        cells.append(cell)
    return cells
