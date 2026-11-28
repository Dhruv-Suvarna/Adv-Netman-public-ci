"""Read-only live commissioning acceptance gates (see ``core.services.commissioning.acceptance``).

    check  --devices R6 R7 [--scope FILE] [--flow SRC:DST:PROTO:FAMILY[:THROUGH+THROUGH]]... [--freshness S] [--json] [--out FILE]
           exit 0 READY, 3 BLOCKED (a prerequisite is missing), 2 FAIL (an invariant is broken)
    plan   --devices R6 R7 [--scope FILE] [...]   the ordered governed steps, each with its rollback and the gate re-run after it,
                                                  preceded by the current prerequisites
    scope-template --devices R6 R7               an UNAPPROVED live-scope skeleton to fill in, review and have a second person approve

Nothing here writes to the database, contacts a device or performs a lifecycle step.
"""

from __future__ import annotations

import json
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone

from core.services.commissioning import acceptance as A

EXIT = {A.READY: 0, A.FAIL: 2, A.BLOCKED: 3}
STEP_ORDER = ("MANAGEMENT_PATH_APPROVE", "BOOTSTRAP_AUTHORIZE", "ISOLATION_ENFORCE", "ZTP_REBOOTSTRAP", "DHCP_RENEWAL_WINDOW",
              "COMMISSIONING_CONFIGURE", "ADMISSION")


def parse_flow(text: str) -> dict:
    parts = text.split(":")
    if len(parts) not in (4, 5) or not all(parts[:4]):
        raise CommandError(f"--flow {text!r}: expected SRC:DST:PROTOCOL:FAMILY[:THROUGH+THROUGH]")
    flow = {"source": parts[0], "destination": parts[1], "protocol": parts[2].upper(), "family": parts[3].upper()}
    if len(parts) == 5 and parts[4]:
        flow["through"] = parts[4].split("+")
    return flow


def runbook(report: dict, scope: dict | None) -> list[dict]:
    done = []
    steps = [{"step": 0, "device": "*", "action": "GATE", "run": "nmas_commissioning_acceptance check (must exit 0 READY)",
              "pass": "verdict READY, digest recorded in the change record", "rollback": "none (read-only)"}]
    for device in report["devices"]:
        wanted = A.scoped_operations(scope, device["name"])
        for op in [o for o in STEP_ORDER if o in wanted]:
            how, rollback = A.OPERATIONS[op]
            steps.append({"step": len(steps), "device": device["name"], "action": op, "run": how, "rollback": rollback,
                          "pass": "the governed workflow reports success AND the gate re-run below is not FAIL; protected flows within the "
                                  "scope's traffic_continuity"})
            done.append(f"{device['name']}:{op}")
            steps.append({"step": len(steps), "device": device["name"], "action": "GATE",
                          "run": f"nmas_commissioning_acceptance check --devices {' '.join(report['requested'])} --scope <scope> "
                                 + " ".join(f"--completed {d}" for d in done),
                          "pass": "no FAIL gate; MANAGEMENT stays PASS (management access retained)",
                          "rollback": f"on FAIL: the {op} rollback above, then re-run the gate until it matches the step-0 baseline"})
    steps.append({"step": len(steps), "device": "*", "action": "CLOSE",
                  "run": "nmas_lifecycle_report --verify; traffic runner on every scope flow; export lifecycle evidence",
                  "pass": "chains intact, every device ADMITTED / IN_SERVICE, every flow FRESH_PASS",
                  "rollback": "per-step rollbacks above, newest first"})
    return steps


class Command(BaseCommand):
    help = "Read-only live commissioning acceptance gates, runbook and live-scope template."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        for name in ("check", "plan"):
            p = sub.add_parser(name)
            p.add_argument("--devices", nargs="+", required=True, help="in the intended execution order (validated)")
            p.add_argument("--scope", default="", help="device-specific live-change scope JSON (schema nmas.lifecycle.live-scope/1)")
            p.add_argument("--flow", action="append", default=[], help="SRC:DST:PROTOCOL:FAMILY[:THROUGH+THROUGH] (overrides scope flows)")
            p.add_argument("--completed", action="append", default=[], help="DEVICE:OPERATION already executed (cumulative)")
            p.add_argument("--freshness", type=int, default=A.DEFAULT_TRAFFIC_FRESHNESS_SECONDS)
            p.add_argument("--json", action="store_true")
            p.add_argument("--out", default="")
        t = sub.add_parser("scope-template")
        t.add_argument("--devices", nargs="+", required=True)

    def handle(self, *args, **opts):
        if opts["action"] == "scope-template":
            return self._template(opts)
        guard = connection.vendor == "sqlite"
        if guard:
            with connection.cursor() as cursor:            # this command must never write (any write raises)
                cursor.execute("PRAGMA query_only = ON")
        try:
            return self._evaluate(opts)
        finally:
            if guard:                                       # the connection outlives the command (call_command, shells)
                with connection.cursor() as cursor:
                    cursor.execute("PRAGMA query_only = OFF")

    def _evaluate(self, opts):
        scope = None
        if opts["scope"]:
            try:
                with open(opts["scope"], encoding="utf-8") as fh:
                    scope = json.load(fh)
            except (OSError, ValueError) as exc:
                raise CommandError(f"--scope unreadable: {type(exc).__name__}") from exc
        flows = [parse_flow(f) for f in opts["flow"]] or None
        report = A.evaluate(opts["devices"], scope=scope, flows=flows, completed=opts["completed"], freshness_seconds=opts["freshness"])
        out = report if opts["action"] == "check" else {
            "schema": "nmas.lifecycle.acceptance-runbook/1", "gates_digest": report["digest"], "verdict": report["verdict"],
            "prerequisites": A.prerequisites(report), "steps": runbook(report, scope)}
        text = json.dumps(out, indent=2, sort_keys=True, default=str)
        if opts["out"]:
            with open(opts["out"], "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        if opts["json"]:
            self.stdout.write(text)
        else:
            self._summary(report, out if opts["action"] == "plan" else None)
        if report["verdict"] != A.READY:
            raise SystemExit(EXIT[report["verdict"]])

    def _summary(self, report, plan):
        self.stdout.write(f"verdict {report['verdict']}  digest {report['digest'][:16]}")
        for gate in report["global"]:
            self.stdout.write(f"  *     {gate['gate']:<24} {gate['status']:<15} {' '.join(gate['codes'])}")
        for device in report["devices"]:
            for gate in device["gates"]:
                self.stdout.write(f"  {device['name']:<5} {gate['gate']:<24} {gate['status']:<15} {' '.join(gate['codes'])}")
        for step in (plan or {}).get("steps", []):
            self.stdout.write(f"  step {step['step']:>2} {step['device']:<5} {step['action']:<24} {step['run']}")

    def _template(self, opts):
        now = timezone.now().replace(microsecond=0)
        template = {
            "schema": A.SCOPE_SCHEMA, "change": "CHG-<id>", "prepared_by": "<operator>", "approved_by": "",
            "window": {"start": now.isoformat(), "end": (now + timedelta(hours=2)).isoformat()},
            "devices": [{"name": n, "operations": []} for n in opts["devices"]],
            "allowed_operations": {k: v[0] for k, v in A.OPERATIONS.items()},
            "traffic_continuity": {"mode": "ZERO_LOSS", "max_outage_seconds": 0},
            "retain_management": True,
            "flows": [{"source": "<host>", "destination": "<host>", "protocol": "ICMP", "family": "IPV4", "through": []}],
        }
        self.stdout.write(json.dumps(template, indent=2))
