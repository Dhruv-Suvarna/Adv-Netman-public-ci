"""The baseline static-IPv6 to IS-IS migration from the server shell, step by step, as one NMAS Change.

    python manage.py nmas_isis_migration create   --actor <name>
    python manage.py nmas_isis_migration validate --change CHG-... --actor <name>
    python manage.py nmas_isis_migration plan     --change CHG-... --actor <name>
    python manage.py nmas_isis_migration precheck --change CHG-... --actor <name>
    python manage.py nmas_isis_migration approve  --change CHG-... --actor <name> --confirm CHG-... --ack <name> [--ack ...]
    python manage.py nmas_isis_migration execute  --change CHG-... --actor <name> --confirm CHG-...
    python manage.py nmas_isis_migration show     --change CHG-...

    python manage.py nmas_isis_migration dry-run  [--output report.json]         READ-ONLY, needs no Change, records nothing
    python manage.py nmas_isis_migration source-of-truth                         READ-ONLY, contacts no device
    python manage.py nmas_isis_migration create-revert --actor <name> --migration-run <run id of a SUCCEEDED migration>

``create``, ``create-revert``, ``validate``, ``plan``, ``approve``, ``show`` and ``source-of-truth`` contact no device.
``dry-run`` is the read-only mode: the production transport, the precheck and every read-back, with every write refused;
it prints PRODUCTION_READ_ONLY_DRY_RUN and PRODUCTION_PRECHECK.  ``precheck`` reads all six devices, runs the dedicated
probes for its duration and records the result against the Change.  ``execute`` is refused unless the transition is
READY (core/services/route_shield/readiness.py); nothing on this command line can change that.

A revert Change (``create-revert``) goes through the same ``validate``, ``plan``, ``precheck``, ``approve``, ``execute``.

There is deliberately no option that forces a step, skips the precheck, ignores probe loss or disables the automatic
reverse path: a refused step is repeated after its cause is fixed.
"""

import json
import time

from django.core.management.base import BaseCommand, CommandError

from core import models
from core.services.route_shield import lifecycle, production, readiness

WARM_UP_SECONDS = 30


class Command(BaseCommand):
    help = "Create, validate, plan, precheck, approve and execute the baseline IS-IS migration as one Change."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("create").add_argument("--actor", required=True)
        for name in ("validate", "plan", "precheck"):
            step = sub.add_parser(name)
            step.add_argument("--change", required=True)
            step.add_argument("--actor", required=True)
        approve = sub.add_parser("approve")
        approve.add_argument("--change", required=True)
        approve.add_argument("--actor", required=True)
        approve.add_argument("--confirm", required=True, help="The Change id, typed again.")
        approve.add_argument("--ack", action="append", default=[], choices=[name for name, _ in lifecycle.ACKNOWLEDGEMENTS],
                             help="One acknowledgement (repeat for each): " + "; ".join(f"{name} = {label}" for name, label in lifecycle.ACKNOWLEDGEMENTS))
        execute = sub.add_parser("execute")
        execute.add_argument("--change", required=True)
        execute.add_argument("--actor", required=True)
        execute.add_argument("--confirm", required=True, help="The Change id, typed again.")
        sub.add_parser("show").add_argument("--change", required=True)
        dry = sub.add_parser("dry-run")
        dry.add_argument("--output", default="", help="Also write the full report to this file.")
        dry.add_argument("--warm-up", type=int, default=WARM_UP_SECONDS, choices=range(10, 301), metavar="SECONDS")
        sub.add_parser("source-of-truth")
        revert = sub.add_parser("create-revert")
        revert.add_argument("--actor", required=True)
        revert.add_argument("--migration-run", required=True, help="The run id of the SUCCEEDED baseline migration to revert.")

    def _change(self, change_id):
        change = models.Change.objects.filter(change_id=change_id).first()
        if change is None or not lifecycle.is_transition(change):
            raise CommandError(f"{change_id} is not a transition Change.")
        return change

    def _print(self, value):
        self.stdout.write(json.dumps(value, indent=1, default=str))

    def handle(self, *args, **options):
        action = options["action"]
        try:
            if action == "create":
                change = lifecycle.create_change(actor=options["actor"])
                return self._print({"change": change.change_id, "lifecycle": change.lifecycle_state})
            if action == "create-revert":
                change = lifecycle.create_revert(actor=options["actor"], migration_run_id=options["migration_run"])
                return self._print({"change": change.change_id, "kind": lifecycle.kind_of(change), "lifecycle": change.lifecycle_state,
                                    "reverts": change.metadata["transition"]["reverts"]})
            if action == "dry-run":
                from core.services.route_shield import dry_run

                report = dry_run.run(warm_up_seconds=options["warm_up"])
                if options["output"]:
                    with open(options["output"], "w", encoding="utf-8") as handle:
                        json.dump(report, handle, indent=1, default=str)
                self._print({"checks": [{"check": row["check"], "status": row["status"]} for row in report["checks"]],
                             "precheck": report.get("precheck"), "write_attempts": report["write_attempts"], "host": report["snapshot"].get("host")})
                self.stdout.write(f"PRODUCTION_READ_ONLY_DRY_RUN = {report['PRODUCTION_READ_ONLY_DRY_RUN']}")
                self.stdout.write(f"PRODUCTION_PRECHECK = {report['PRODUCTION_PRECHECK']}")
                return None
            if action == "source-of-truth":
                from core.services.route_shield import source_of_truth

                return self._print({"tracked_intent": source_of_truth.tracked_state(), "required_updates": source_of_truth.required_updates()})
            change = self._change(options["change"])
            if action == "validate":
                run = lifecycle.validate_change(change, actor=options["actor"])
                return self._print({"validation": run.status, "findings": run.report["findings"], "readiness": run.report["readiness"]})
            if action == "plan":
                plan = lifecycle.build_plan(change, actor=options["actor"])
                return self._print({"plan": str(plan.plan_id), "plan_hash": plan.plan_hash, "operations": plan.configlets.count(),
                                    "permanent": plan.summary["permanent"], "temporary": plan.summary["temporary"]})
            if action == "precheck":
                env = production.environment()
                production.start_probes(env)
                try:
                    time.sleep(WARM_UP_SECONDS)
                    run = lifecycle.run_precheck(change, actor=options["actor"], env=env)
                finally:
                    env.probes.stop()
                return self._print({"precheck": run.status, "blockers": run.report["blockers"], "probes": run.report.get("probes")})
            if action == "approve":
                event = lifecycle.approve(change, actor=options["actor"], confirmation=options["confirm"], acknowledgements={name: True for name in options["ack"]})
                return self._print({"approved": True, "lifecycle": event.to_state, "approval": event.metadata["approval"]})
            if action == "execute":
                if readiness.refusal(lifecycle.READINESS_OF[lifecycle.kind_of(change)]):   # refused before a probe is started or a device is contacted
                    result = lifecycle.execute(change, actor=options["actor"], confirmation=options["confirm"], env=None)
                    return self._print({"outcome": result.outcome, "blockers": result.blockers})
                env = production.environment()
                production.start_probes(env)
                try:
                    time.sleep(WARM_UP_SECONDS)
                    result = lifecycle.execute(change, actor=options["actor"], confirmation=options["confirm"], env=env)
                finally:
                    env.probes.stop()
                report = result.run.report if result.run is not None else {}
                return self._print({"outcome": result.outcome, "blockers": result.blockers, "failure": report.get("failure"), "restored": report.get("restored"),
                                    "temporary_remaining": (report.get("temporary_state") or {}).get("remaining"),
                                    "persistence": report.get("persistence"), "probes": report.get("probes")})
            plan = lifecycle.latest_plan(change)
            runs = [{"run": str(run.run_id), "outcome": run.outcome or run.state, "started": run.started_at,
                     "persistence": ((run.report or {}).get("persistence") or {}).get("status"),
                     "temporary_remaining": ((run.report or {}).get("temporary_state") or {}).get("remaining")}
                    for run in change.execution_runs.order_by("started_at")]
            return self._print({"change": change.change_id, "kind": lifecycle.kind_of(change), "lifecycle": change.lifecycle_state,
                                "reverts": change.metadata["transition"].get("reverts"), "validation": getattr(lifecycle.latest_validation(change), "status", None),
                                "plan": str(plan.plan_id) if plan else None,
                                "precheck": getattr(lifecycle.latest_precheck(change, plan), "status", None) if plan else None,
                                "readiness": readiness.READINESS[lifecycle.READINESS_OF[lifecycle.kind_of(change)]], "runs": runs,
                                "operations": [{"cfg_id": c.cfg_id, "device": c.target_device, "description": c.description, "status": c.execution_status}
                                               for c in plan.configlets.order_by("sequence")] if plan else []})
        except lifecycle.LifecycleError as exc:
            raise CommandError("; ".join(f"{b['code']}: {b['message']}" for b in exc.blockers)) from None
