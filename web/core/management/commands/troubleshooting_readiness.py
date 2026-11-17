"""Read-only troubleshooting operational-readiness report (per device and per runbook).

    manage.py troubleshooting_readiness [--json] [--device R1 ...] [--with-nmas-providers]

Uses the exact admission path a troubleshooting run uses, plus an independent evaluation of every gate so all blockers and their
corrective actions are listed at once.  Database and file reads only: no device, NetBox, gateway or credential is contacted, nothing is
adopted, verified or written.  ``--with-nmas-providers`` evaluates the documented binding (NMAS inventory + lifecycle + observed-version providers) in place of ``settings.NMAS_TS_DEPLOYMENT`` -- it changes nothing, it answers "what would admission say if bound".
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand

from core.services.troubleshooting import readiness

from core.services.troubleshooting.adapters.nmas_providers import RECOMMENDED_BINDING as NMAS_BINDING
from core.services.troubleshooting import qualification


class Command(BaseCommand):
    help = "Report why each device is (not) admitted for troubleshooting and which runbooks can run live (read-only)."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="machine-readable output")
        parser.add_argument("--device", action="append", default=None, help="limit to these devices (repeatable)")
        parser.add_argument("--matrix", action="store_true", help="emit the per-device qualification matrix (JSON; managed/excluded/host/peer, gates, collector limits)")
        parser.add_argument("--with-nmas-providers", action="store_true",
                            help="evaluate the documented NMAS inventory+lifecycle binding instead of settings (read-only)")

    def handle(self, *args, **options):
        config = dict(NMAS_BINDING) if options["with_nmas_providers"] else None
        if options["matrix"]:
            self.stdout.write(json.dumps(qualification.device_matrix(config), indent=2, sort_keys=True, default=str))
            return
        report = readiness.device_readiness(config, options["device"])
        report["binding"] = "nmas-providers (evaluated, not configured)" if config else "settings.NMAS_TS_DEPLOYMENT"
        runbooks = readiness.runbook_readiness(report)
        if options["json"]:
            self.stdout.write(json.dumps({**report, "runbooks": runbooks}, indent=2, sort_keys=True, default=str))
        else:
            self.stdout.write(f"binding: {report['binding']}")
            self.stdout.write(readiness.render_text(report, runbooks))
