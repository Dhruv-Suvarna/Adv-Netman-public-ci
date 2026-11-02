"""Run FRR IS-IS against the verified disposable pair, with an ephemeral NMAS database."""

from __future__ import annotations

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

from core.services.capabilities.batch_frr_isis import KEY, probe_frr_isis  # noqa: E402
from core.services.capabilities.features import by_key  # noqa: E402
from core.services.capabilities.offline_verify import verify_cell  # noqa: E402


def main() -> None:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    paths = ("web/core/services/capabilities/batch_frr_isis.py", "web/core/services/platform_drivers.py",
             "web/core/services/execution/executors/frr_routing.py", "web/core/services/execution/executors/linux.py",
             "web/core/services/config_import/parser_frr.py", "web/core/services/candidate_composition.py",
             "web/core/services/health/live.py", "web/core/services/capabilities/offline_verify.py",
             "templates/features/ubuntu_frr/routing_isis.j2")
    hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}
    with tempfile.TemporaryDirectory(prefix="nmas-frr-isis-assessment-") as temporary:
        settings.DATABASES["default"]["NAME"] = str(Path(temporary) / "assessment.sqlite3")
        call_command("migrate", interactive=False, verbosity=0)
        cell = verify_cell("ubuntu_frr", by_key()[KEY], head=head)
        failed = [name for name, result in cell.probes.items() if result["outcome"] in {"FAIL", "BLOCKED"}]
        if failed:
            raise RuntimeError(f"FRR IS-IS offline failure: {failed}")
        scenarios = probe_frr_isis(cell)
        record = {"schema": "nmas.v2.phase9.frr-isis-live/1", "repository_head": head,
                  "uncommitted_source_sha256": hashes, "ephemeral_database": True,
                  "assessment": cell.as_dict(), "scenarios": scenarios}
        path = ROOT / "docs/evidence/v2-phase9-closure/frr-isis/assessment.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"feature": KEY, "status": cell.status, "complete": cell.complete,
                          "evidence": str(path.relative_to(ROOT))}), flush=True)


if __name__ == "__main__":
    main()
