"""Read-only lifecycle stage report (``core.services.devices.stage_report``): no device is contacted, nothing is written.

    manage.py nmas_lifecycle_report                 # one line per device
    manage.py nmas_lifecycle_report --json          # the fleet report document
    manage.py nmas_lifecycle_report --device R7     # one device (name or DEV id)
    manage.py nmas_lifecycle_report --verify        # exit 2 when any evidence chain is broken or a legacy device claims ADMITTED
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core import models
from core.services.devices import lifecycle, stage_report


class Command(BaseCommand):
    help = "Read-only lifecycle stage / evidence report of the registered devices."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--device", default="")
        parser.add_argument("--verify", action="store_true", help="fail (exit 2) on a broken chain or an untruthful legacy admission")

    def handle(self, *args, **options):
        if options["device"]:
            device = lifecycle.get_device(options["device"]) or models.ManagedDevice.objects.filter(name=options["device"]).order_by("-id").first()
            if device is None:
                raise CommandError("unknown device")
            reports = {"devices": [stage_report.device_report(device)]}
        else:
            reports = stage_report.fleet_report()
        if options["json"]:
            self.stdout.write(json.dumps(reports if not options["device"] else reports["devices"][0], indent=2, sort_keys=True, default=str))
        else:
            for report in reports["devices"]:
                stages = " ".join(f"{s['stage'][:5]}={s['status'][:4]}" for s in report["stages"])
                self.stdout.write(f"{report['device']} {report['name']:<9} {report['admission_state']:<18} chain="
                                  f"{'ok' if report['evidence']['chain_intact'] else 'BROKEN'} ready={report['verdicts']['readiness']['ready']} {stages}")
            if "summary" in reports:
                self.stdout.write(json.dumps(reports["summary"], sort_keys=True))
        if options["verify"]:
            problems = [f"{r['device']}: evidence chain broken" for r in reports["devices"] if not r["evidence"]["chain_intact"]]
            problems += [f"{r['device']}: adopted device reports ADMITTED" for r in reports["devices"]
                         if r["origin"] == models.DeviceOrigin.LEGACY_ADOPTION and r["admission_state"] == models.ProductionAdmissionState.ADMITTED]
            if problems:
                self.stderr.write("\n".join(problems))
                raise SystemExit(2)
