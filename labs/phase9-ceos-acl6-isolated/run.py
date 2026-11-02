"""Capture three IPv6 ACL capability cells over pinned SSH in a temporary DB."""

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
from core.services.capabilities.batch_live import CeosServiceLab, probe_cell  # noqa: E402
from core.services.capabilities.features import by_key  # noqa: E402
from core.services.capabilities.offline_verify import verify_cell  # noqa: E402

KEYS = tuple(f"service_policy.{code}" for code in ("ACL_IPV6_STANDARD", "ACL_IPV6_EXTENDED", "ACL_ATTACH_IPV6"))
SOURCE = ("web/core/services/capabilities/batch_live.py", "web/core/services/capabilities/fixture_ceos_ssh.py",
          "web/core/services/config_import/parser_ceos.py", "web/core/services/config_import/ceos_port_names.py",
          "web/core/services/platform_drivers.py", "templates/features/ceos/acl_ipv6.j2")


def main():
    if not os.environ.get("NMAS_CAP_CEOS_PASSWORD"):
        raise SystemExit("NMAS_CAP_CEOS_PASSWORD must be supplied through the environment.")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE}
    with tempfile.TemporaryDirectory(prefix="nmas-acl6-assessment-") as temporary:
        settings.DATABASES["default"]["NAME"] = str(Path(temporary) / "assessment.sqlite3")
        call_command("migrate", interactive=False, verbosity=0)
        cells = [verify_cell("arista_ceos", by_key()[key], head=head) for key in KEYS]
        for cell in cells:
            failures = [name for name, result in cell.probes.items() if name not in (
                "live_read", "live_write", "live_post_write_validation", "compensation", "runtime_validation")
                and result["outcome"] != "PASS"]
            if failures:
                raise RuntimeError(f"{cell.feature} offline gate failed: {failures}")
        lab = CeosServiceLab()
        try:
            for cell in cells:
                probe_cell(lab, cell, cell.feature)
        finally:
            restored = lab.close()
        if not restored or any(not cell.complete or cell.status != "SUPPORTED" or
                               not all(phase9_ledger.stages_for(cell.probes).values()) for cell in cells):
            raise RuntimeError("IPv6 ACL isolated evidence did not pass every stage and restore the baseline.")
        path = ROOT / "docs/evidence/v2-phase9-closure/ceos-acl6/assessment.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": "nmas.v2.phase9.ceos-acl6-live/1", "repository_head": head,
                                    "uncommitted_source_sha256": source_hashes, "ephemeral_database": True,
                                    "fixture_restored": restored, "assessments": [cell.as_dict() for cell in cells]},
                                   indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": "SUPPORTED", "cells": list(KEYS), "evidence": str(path.relative_to(ROOT))}, sort_keys=True))


if __name__ == "__main__":
    main()
