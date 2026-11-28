"""READ-ONLY inventory-to-lifecycle-registry reconciliation report.

    python manage.py nmas_reconcile_inventory [--json] [--fail-on-gap]

Writes nothing, contacts no device/NetBox/broker, adopts nothing, grants no admission.  ``--fail-on-gap`` exits non-zero when an
any evidence gap, conflict or unavailable source remains.
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from ...services.devices import reconciliation


class Command(BaseCommand):
    help = "Report inventory vs lifecycle-registry reconciliation (read-only)."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--fail-on-gap", action="store_true")

    def handle(self, *args, **options):
        report = reconciliation.build_report()
        if options["json"]:
            self.stdout.write(json.dumps(report, indent=2, sort_keys=True, default=str))
        else:
            self.stdout.write("evidence=LOCAL; production registry and live device status unvalidated")
            for r in report["devices"]:
                gaps = ",".join(r["evidence"].get("gaps", [])) or "-"
                self.stdout.write(f"{r['name']:<10} {r['classification']:<17} {(r['lifecycle'] or {}).get('admission_state', '-'):<19} "
                                  f"conflicts={','.join(r['conflicts']) or '-'} gaps={gaps}")
            self.stdout.write(f"missing_eligible={report['missing_eligible']} excluded={report['excluded']} digest={report['digest'][:12]}")
        if options["fail_on_gap"] and report["has_gaps"]:
            raise CommandError("reconciliation gaps present")
