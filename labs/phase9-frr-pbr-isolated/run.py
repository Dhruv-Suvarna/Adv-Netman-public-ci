"""Assess the Ubuntu/FRR policy-based-routing cells against the isolated capability lab, with an ephemeral NMAS database.

Run from the repository root with DJANGO_DEBUG=1 and the ``nmas-cap-validation`` lab running.  The FRR containers are
credential-free (``docker exec``); nothing secret is read or recorded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "web")]
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402

django.setup()

from django.conf import settings  # noqa: E402
from django.core.management import call_command  # noqa: E402

from core.services.capabilities.batch_frr_pbr import CELLS, probe_frr_pbr  # noqa: E402
from core.services.capabilities.features import by_key  # noqa: E402
from core.services.capabilities.offline_verify import verify_cell  # noqa: E402

# Bind the live proof to the implementation that renders, plans, writes, reads, imports and compensates each cell.
SOURCES = ("web/core/services/frr_pbr.py", "web/core/services/capabilities/batch_frr_pbr.py",
           "web/core/services/capabilities/offline_verify.py", "web/core/services/platform_drivers.py",
           "web/core/services/planning/configlet_factory.py", "web/core/services/execution/executors/linux.py",
           "web/core/services/execution/executors/frr_routing.py", "web/core/services/config_import/parser_frr.py",
           "web/core/services/config_import/service.py", "web/core/services/health/live.py",
           "web/core/services/health/evaluators.py", "web/core/services/health/requirements.py",
           "templates/features/ubuntu_frr/pbr_map.j2")
EVIDENCE = "docs/evidence/v2-phase9-closure/frr-pbr"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("features", nargs="*", choices=CELLS, help="cells to assess (default: all)")
    keys = parser.parse_args().features or list(CELLS)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCES}
    with tempfile.TemporaryDirectory(prefix="nmas-frr-pbr-assessment-") as temporary:
        settings.DATABASES["default"]["NAME"] = str(Path(temporary) / "assessment.sqlite3")
        call_command("migrate", interactive=False, verbosity=0)
        for key in keys:
            cell = verify_cell("ubuntu_frr", by_key()[key], head=head)
            failed = [name for name, result in cell.probes.items() if result["outcome"] in {"FAIL", "BLOCKED"}]
            if failed:
                print(json.dumps({"feature": key, "offline_failures": failed}), flush=True)
                continue
            scenarios = probe_frr_pbr(cell, key)
            record = {"schema": "nmas.v2.phase9.frr-pbr-live/1", "repository_head": head,
                      "uncommitted_source_sha256": hashes, "ephemeral_database": True,
                      "assessment": cell.as_dict(), "scenarios": scenarios}
            path = ROOT / EVIDENCE / f"{key.replace('.', '-')}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            print(json.dumps({"feature": key, "status": cell.status, "complete": cell.complete,
                              "evidence": str(path.relative_to(ROOT))}), flush=True)


if __name__ == "__main__":
    main()
