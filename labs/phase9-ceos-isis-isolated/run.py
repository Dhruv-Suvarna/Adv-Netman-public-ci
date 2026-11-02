"""Record one real cEOS IS-IS assessment with an ephemeral local Django database.

Run from the repository root with DJANGO_DEBUG=1 and NMAS_CAP_CEOS_PASSWORD
in the environment. The password is used only in memory. This script touches
only the pre-existing disposable nmas-cap-validation fixture.
"""

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

from core.services.capabilities import phase9_ledger  # noqa: E402
from core.services.capabilities.batch_ceos_isis import probe_ceos_isis  # noqa: E402
from core.services.capabilities.features import by_key  # noqa: E402
from core.services.capabilities.offline_verify import verify_cell  # noqa: E402


def main():
    if not os.environ.get("NMAS_CAP_CEOS_PASSWORD"):
        raise SystemExit("NMAS_CAP_CEOS_PASSWORD must be supplied through the environment.")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    paths = ("web/core/services/capabilities/fixture_ceos_ssh.py",
             "web/core/services/capabilities/batch_ceos_isis.py",
             "web/core/services/capabilities/batch_live.py",
             "web/core/tests/test_ceos_isis_phase9.py")
    source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths}
    with tempfile.TemporaryDirectory(prefix="nmas-isis-assessment-") as temporary:
        # An empty temporary DB protects the deployed NMAS and every worktree DB.
        settings.DATABASES["default"]["NAME"] = str(Path(temporary) / "assessment.sqlite3")
        call_command("migrate", interactive=False, verbosity=0)
        cell = verify_cell("arista_ceos", by_key()["routing.ISIS"], head=head)
        offline_failed = [name for name, result in cell.probes.items()
                          if name not in {"live_read", "live_write", "live_post_write_validation", "compensation", "runtime_validation"}
                          and result["outcome"] != "PASS"]
        if offline_failed:
            raise RuntimeError(f"IS-IS offline prerequisite failure: {offline_failed}")
        probe_ceos_isis(cell)
        if not cell.complete or cell.status != "SUPPORTED":
            raise RuntimeError("IS-IS assessment did not prove all ten stages.")
        record = {"schema": "nmas.v2.phase9.ceos-isis-live/1", "repository_head": head,
                  "uncommitted_source_sha256": source_hashes, "ephemeral_database": True,
                  "assessment": cell.as_dict()}
        path = ROOT / "docs/evidence/v2-phase9-closure/ceos-isis/assessment.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        # The authoritative 396-cell ledger is promoted only after review/commit;
        # this file is independently reviewable proof tied to exact source hashes.
        print(json.dumps({"status": cell.status, "evidence": str(path.relative_to(ROOT)),
                          "all_stages": all(phase9_ledger.stages_for(cell.probes).values())}, sort_keys=True))


if __name__ == "__main__":
    main()
