"""Scheduler-safe automatic rotation of enabled, due device accounts."""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand

from core.services.credentials.engine import rotate_due_credentials


class Command(BaseCommand):
    help = "Rotate enabled managed-device credentials whose next_due_at has passed."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="Emit bounded non-secret JSON evidence.")

    def handle(self, *args, **options):
        outcomes = rotate_due_credentials()
        rows = [
            {"credential_id": o.credential_id, "run_id": o.run_id, "status": o.status, "code": o.code}
            for o in outcomes
        ]
        if options["json"]:
            self.stdout.write(json.dumps({"selected": len(rows), "outcomes": rows}, sort_keys=True))
        else:
            self.stdout.write(f"Selected {len(rows)} due credential(s).")
            for row in rows:
                self.stdout.write(f"credential={row['credential_id']} run={row['run_id'] or '-'} {row['status']} {row['code']}")
        if any(row["status"] in {"FAILED", "UNCERTAIN", "BLOCKED"} for row in rows):
            raise SystemExit(1)
