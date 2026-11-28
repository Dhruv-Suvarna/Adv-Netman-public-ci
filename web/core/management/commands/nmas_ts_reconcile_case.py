"""Engineer reconciliation of an escalated route-source monitoring case against fresh live evidence.

    manage.py nmas_ts_reconcile_case TS-... [--cause-case TS-...] [--note TEXT]            # dry run: reads only, writes nothing
    manage.py nmas_ts_reconcile_case TS-... --apply [--cause-case TS-...] [--note TEXT]    # record evidence; close or escalate

Outcomes:
- CLOSE_CLEARED_EXTERNALLY: closes UNRESOLVED, cleared_externally=true, nmas_performed_repair=false.
- RETAIN: a blocker such as an open handoff, a plan in flight, a lock or maintenance; the case is untouched apart from an audited note.
- ESCALATE: the condition is still present or unreadable; the case stays open and the engineer is emailed.
- REFUSED: not an open, escalated RSRC monitoring case.

The age of a case is never a reason to close it.  See ``core.services.troubleshooting.reconcile``.
"""
import json

from django.core.management.base import BaseCommand, CommandError

from core.services.troubleshooting import reconcile


class Command(BaseCommand):
    help = "Re-verify an escalated RSRC monitoring case from fresh read-only evidence; close it only if cleared externally."

    def add_arguments(self, parser):
        parser.add_argument("case_id")
        parser.add_argument("--apply", action="store_true", help="record the evidence and close/escalate (default: dry run)")
        parser.add_argument("--cause-case", default="", help="terminal case recording the upstream cause, for correlation")
        parser.add_argument("--note", default="", help="engineer note stored with the disposition (no secrets)")

    def handle(self, *args, **opts):
        verdict = reconcile.reconcile(opts["case_id"], apply=opts["apply"], cause_case=opts["cause_case"], note=opts["note"])
        self.stdout.write(json.dumps(verdict.as_dict(), indent=2, sort_keys=True, default=str))
        if verdict.outcome == "REFUSED":
            raise CommandError(f"refused: {'; '.join(verdict.reasons)}")
