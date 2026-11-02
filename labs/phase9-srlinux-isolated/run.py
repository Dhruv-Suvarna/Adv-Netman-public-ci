"""Assess selected SR Linux Phase 9 cells on the verified disposable fixture.

Run from the repository root with DJANGO_DEBUG=1 and NMAS_CAP_SRL_PASSWORD
in the environment. Uses an ephemeral SQLite database and records no secrets.
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

from core.services.capabilities.batch_srlinux_phase9 import CELLS, probe_srlinux_phase9  # noqa: E402
from core.services.capabilities.features import by_key  # noqa: E402
from core.services.capabilities.offline_verify import verify_cell  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("features", nargs="*", choices=CELLS, default=["routing.OSPFV2"])
    keys = parser.parse_args().features
    if not os.environ.get("NMAS_CAP_SRL_PASSWORD"):
        raise SystemExit("NMAS_CAP_SRL_PASSWORD is required through the environment.")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    # Bind live proof to the implementation that renders, writes, reads, imports and compensates each cell.
    paths = ("web/core/services/capabilities/batch_srlinux_phase9.py",
             "web/core/services/capabilities/batch_srlinux.py",
             "web/core/services/capabilities/offline_verify.py",
             "web/core/services/config_import/parser_srlinux.py",
             "web/core/services/platform_drivers.py",
             "web/core/services/planning/configlet_factory.py",
             "web/core/services/srlinux_model.py",
             "web/core/services/execution/executors/srlinux.py",
             "web/core/services/execution/writers/srlinux_gnmi.py",
             "web/core/services/health/live.py",
             "web/core/services/health/routing_config.py",
             "templates/features/srlinux/acl_ipv4.j2",
             "templates/features/srlinux/acl_ipv6.j2",
             "templates/features/srlinux/routing_ospfv2.j2",
             "templates/features/srlinux/routing_ospfv3.j2")
    hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}
    with tempfile.TemporaryDirectory(prefix="nmas-srl-assessment-") as temporary:
        settings.DATABASES["default"]["NAME"] = str(Path(temporary) / "assessment.sqlite3")
        call_command("migrate", interactive=False, verbosity=0)
        for key in keys:
            cell = verify_cell("nokia_srlinux", by_key()[key], head=head)
            offline_failures = [name for name, outcome in cell.probes.items()
                                if outcome["outcome"] in {"FAIL", "BLOCKED"}]
            if offline_failures:
                print(json.dumps({"feature": key, "offline_failures": offline_failures}), flush=True)
                continue
            scenarios = probe_srlinux_phase9(cell, key)
            record = {"schema": "nmas.v2.phase9.srlinux-live/1", "repository_head": head,
                      "uncommitted_source_sha256": hashes, "ephemeral_database": True,
                      "assessment": cell.as_dict(), "scenarios": scenarios}
            path = ROOT / "docs/evidence/v2-phase9-closure/srlinux" / f"{key.replace('.', '-')}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            print(json.dumps({"feature": key, "status": cell.status, "complete": cell.complete,
                              "evidence": str(path.relative_to(ROOT))}), flush=True)


if __name__ == "__main__":
    main()
