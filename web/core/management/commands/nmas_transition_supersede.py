"""Assess (default) or close stale isolation / admission transition Changes as SUPERSEDED (``isolation.supersede``).

    manage.py nmas_transition_supersede --change CHG-... [--change ...] --actor NAME --reason TEXT [--apply] [--json]

Without ``--apply`` nothing is written (SQLite ``PRAGMA query_only``).  With it, each Change that ``assess`` proves stale gets
one append-only SUPERSEDED lifecycle event carrying the evidence; a refused Change is left untouched.  No device is contacted.
Exit 0: every Change closable (or closed); 3: at least one refused.
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from ...services.isolation import supersede as service
from ... import models


class Command(BaseCommand):
    help = "Assess or close stale isolation/admission transition Changes as SUPERSEDED (records only)."

    def add_arguments(self, parser):
        parser.add_argument("--change", action="append", required=True, help="Change id (repeatable)")
        parser.add_argument("--actor", default="", help="operator or service recording the closure")
        parser.add_argument("--reason", default="", help="why the Change is superseded")
        parser.add_argument("--apply", action="store_true", help="write the SUPERSEDED event (default: assess only)")
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        changes = []
        for change_id in options["change"]:
            change = models.Change.objects.filter(change_id=change_id).first()
            if change is None:
                raise CommandError(f"unknown Change {change_id}")
            changes.append(change)
        read_only = not options["apply"] and connection.vendor == "sqlite"
        try:
            if read_only:
                with connection.cursor() as cursor:
                    cursor.execute("PRAGMA query_only = ON")
            call = service.supersede if options["apply"] else service.assess
            results = [call(change, actor=options["actor"], reason=options["reason"]) for change in changes]
        finally:
            if read_only:
                with connection.cursor() as cursor:
                    cursor.execute("PRAGMA query_only = OFF")
        report = {"schema": service.SCHEMA, "mode": "apply" if options["apply"] else "assess",
                  "results": [{"change": r.change.change_id, "ok": r.ok, "state": r.change.lifecycle_state,
                               "blockers": r.blockers, "evidence": r.evidence} for r in results]}
        if options["json"]:
            self.stdout.write(json.dumps(report, indent=2, sort_keys=True, default=str))
        else:
            for row in report["results"]:
                verdict = "OK" if row["ok"] else "REFUSED"
                owner = row["evidence"].get("owner", {})
                self.stdout.write(f"{row['change']}: {verdict} state={row['state']} owner={owner.get('id', '-')}:"
                                  f"{owner.get('state', '-')} successor={owner.get('successor', {}).get('change', '-')}"
                                  f" digest={row['evidence'].get('digest', '')[:12]}")
                for item in row["blockers"]:
                    self.stdout.write(f"  - {item['code']}: {item['message']}")
        if not all(r.ok for r in results):
            raise SystemExit(3)
