"""Admission acceptance through the PRODUCTION Troubleshooter path (no shortcut, no forged authorization).

    open   --devices R1 R2 S1 S3 S4   open one acceptance case, run the deterministic engine, open a special-case handoff and
                                      start the real dispatcher unit (nmas-troubleshooter-dispatch@<handoff>)
    report --case TS-...              per-device: worker audit request/code, persisted observations, admission resolution

The dispatcher's deterministic pre-model hook (``ai_runtime`` ADMISSION_ACCEPTANCE) runs the registered read-only HC04
collection through the isolated diagnostic worker on every delegated target before any model turn.  The worker itself
authorizes each request against the live handoff (OPEN, target delegated, target VERIFIED on the case) exactly as for an
incident.  At most ``ai.DEFAULT_BUDGET['max_devices']`` devices per case.
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core import models
from core.services.troubleshooting import ai, intake, repository as repo
from core.services.troubleshooting.ai_runtime import ADMISSION_ACCEPTANCE

ACTOR = "nmas-acceptance"


class Command(BaseCommand):
    help = "Open an admission-acceptance case through the production Troubleshooter path, or report its worker evidence."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        o = sub.add_parser("open")
        o.add_argument("--devices", nargs="+", required=True)
        o.add_argument("--no-dispatch", action="store_true")
        o.add_argument("--resume", default="", help="continue an existing acceptance case left before its handoff (e.g. lock contention)")
        r = sub.add_parser("report")
        r.add_argument("--case", required=True)

    def handle(self, *args, **opts):
        from django.db import connection

        with connection.cursor() as cursor:            # connection-local: wait for other SQLite writers instead of failing
            cursor.execute("PRAGMA busy_timeout = 120000")
        getattr(self, "_" + opts["action"])(opts)

    def _open(self, opts):
        from core import troubleshooting_views as tv
        from core.services.troubleshooting import runtime as rt

        devices = sorted(set(opts["devices"]))
        if len(devices) > ai.DEFAULT_BUDGET["max_devices"]:
            raise CommandError(f"at most {ai.DEFAULT_BUDGET['max_devices']} devices per acceptance case")
        now = timezone.now()
        actor = repo.Actor(ACTOR, "system", tenant="default", devices=frozenset(devices))
        if opts.get("resume"):
            case = models.TsCase.objects.get(case_id=opts["resume"], trigger_source="acceptance")
            if sorted((case.affected_scope or {}).get("devices") or []) != devices or case.state in models.TS_TERMINAL_CASE_STATES:
                raise CommandError("refused: resume target is not a live acceptance case for exactly these devices")
        else:
            case = None
        case = case or repo.open_case(
            actor, trigger_source="acceptance", trigger_ref=f"ADMISSION:{','.join(devices)}", severity="LOW",
            idempotency_key=f"admission-acceptance:{','.join(devices)}:{int(now.timestamp())}",
            title=f"Admission acceptance: read-only diagnostics on {', '.join(devices)}",
            symptom=("Bulk topology admission acceptance (CHG-NMAS-20261117-BULK-ADMISSION-019): prove that each admitted device answers "
                     "a registered read-only collection through its approved ManagementPath and dedicated nmas-diag identity via the "
                     "isolated diagnostic worker. No fault is asserted; nothing may be changed."),
            service_intent={"service": "admission acceptance", "source": "nmas-bulk-admission", "fault_category": ADMISSION_ACCEPTANCE},
            affected_scope={"devices": devices, "interfaces": []},
            target_states={d: "UNKNOWN" for d in devices}, runbook="RB02", first_detected_at=now, now=now)
        rt.run_case(actor, case.case_id, tv._runtime_deps())  # pylint: disable=protected-access
        case = models.TsCase.objects.get(pk=case.pk)
        handoff = ai.open_handoff(
            actor, case, agent_identity="",
            uncertainty=("Admission acceptance only: NMAS has already collected one read-only HC04 result per delegated device through the "
                         "isolated worker before this turn. Review that evidence. Do not propose any remediation; there is no fault to "
                         "fix. Submit a result that states, per device, whether genuine read-only evidence was collected."),
            special_case_reason="admission acceptance of the bulk-admitted managed topology (owner-authorized, read-only)")
        started = False if opts["no_dispatch"] else intake.start_dispatch(handoff.record_id)
        repo.audit(actor, case, "ACCEPTANCE_DISPATCH", decision=f"{handoff.record_id} started={started}", result="OK" if started else "NOT_STARTED")
        self.stdout.write(json.dumps({"case": case.case_id, "handoff": handoff.record_id, "allowed_targets": handoff.allowed_targets,
                                      "target_states": case.target_states, "dispatch_started": started}))

    def _report(self, opts):
        case = models.TsCase.objects.get(case_id=opts["case"])
        rows = {}
        for d in sorted((case.affected_scope or {}).get("devices") or []):
            obs = models.TsObservation.objects.filter(case=case, target=d, basis="OBSERVED")
            rows[d] = {"target_state": (case.target_states or {}).get(d), "observed_rows": obs.count(),
                       "sources": sorted(set(obs.values_list("source", flat=True)))[:4],
                       "sample": [(o.key, str(o.value)[:40]) for o in obs.order_by("id")[:3]]}
        tests = list(models.TsDiagnosticTest.objects.filter(case=case, basis="OBSERVED").values_list("test_id", "stage_decision"))
        self.stdout.write(json.dumps({"case": case.case_id, "state": case.state, "devices": rows, "observed_tests": tests}, indent=1,
                                     default=str))
