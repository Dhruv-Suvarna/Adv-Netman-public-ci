"""Scheduler entry point of the Phase-20 probation soak: take the due evidence sample of every RUNNING soak.

    python web/manage.py probation_soak_tick [--dry-run] [--soak SOAK-000001] [--json]

Idempotent and restartable: run it as often as you like (every 5 minutes is recommended: at most half the sample interval, so no interval is
skipped by scheduler jitter).  Two overlapping invocations, a repeated tick or a crash mid-run never duplicate a sample and never fabricate
one for downtime.  It READS monitoring, the persisted execution history and the Phase-15 read-only device allowlists, and WRITES only soak
evidence, audit and notification rows.  It never configures a device, writes NetBox / Git, deploys anything, refreshes telemetry or creates a
Golden bundle (that needs the operator's explicit decision).  ``--dry-run`` reads nothing external and writes nothing.

Exit status: 0 = the tick ran (whatever each soak's verdict), 1 = a soak could not be processed (see the ERROR row; the next tick retries).
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand

from core.services import soak_service


class Command(BaseCommand):
    help = "Collect the due evidence sample of every running probation soak (read-only against the network; idempotent)."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Report which soaks are due; read nothing external and write nothing.")
        parser.add_argument("--soak", default="", help="Only this soak id (for example SOAK-000001).")
        parser.add_argument("--json", action="store_true", help="Print one JSON document.")

    def handle(self, *args, **options):
        report = soak_service.run_tick(dry_run=options["dry_run"], soak_id=options["soak"])
        document = report.to_dict()
        if options["json"]:
            self.stdout.write(json.dumps(document, indent=2, sort_keys=True))
        else:
            self.stdout.write(f"probation_soak_tick at {document['now']}{' (dry run)' if report.dry_run else ''}: {len(report.runs)} running soak(s)")
            for row in document["runs"]:
                self.stdout.write("  " + " ".join(f"{key}={value}" for key, value in sorted(row.items())))
        if any(row.action == "ERROR" for row in report.runs):
            raise SystemExit(1)
