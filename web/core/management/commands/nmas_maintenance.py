"""Maintenance Mode from the server shell.

    python manage.py nmas_maintenance request   --device R1 --actor <name> --reason "<why>" --hours 4
    python manage.py nmas_maintenance readiness --id MNT-000001 [--actor <name>]   READ-ONLY: observes the network, forms the verdict and the plan
    python manage.py nmas_maintenance approve   --id MNT-000001 --actor <name> --plan-hash <the hash shown by "show">
    python manage.py nmas_maintenance enter     --id MNT-000001 --actor <name> --confirm MNT-000001
    python manage.py nmas_maintenance exit      --id MNT-000001 --actor <name> --confirm MNT-000001
    python manage.py nmas_maintenance cancel    --id MNT-000001 --actor <name>
    python manage.py nmas_maintenance show      --id MNT-000001
    python manage.py nmas_maintenance verify    --id MNT-000001               recompute the evidence chain
    python manage.py nmas_maintenance list

``request``, ``approve``, ``cancel``, ``show``, ``verify`` and ``list`` contact no device.  ``readiness`` only reads.
``enter`` drains the device and ``exit`` restores it, both synchronously in this process under the record's claim and the
shared device locks; both write to devices only through the maintenance executor, and ``enter`` is refused unless every
planned drain mechanism is READY (core/services/route_shield/readiness.py).  ``exit`` on an escalated record runs the
restore again.  The website queues the same steps for the worker (``manage.py maintenance_tick``).

There is deliberately no option that forces a step, skips a check or ignores probe loss.  The requested hours are the
operator's intended window: they never end a maintenance.  Seven days after entry the worker starts the same restore.
"""

import json
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core import models
from core.services.maintenance_mode import evidence, model, service


class Command(BaseCommand):
    help = "Request, evaluate, approve, enter, exit, cancel and inspect device maintenance."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        request = sub.add_parser("request")
        request.add_argument("--device", required=True)
        request.add_argument("--actor", required=True)
        request.add_argument("--reason", required=True)
        request.add_argument("--hours", type=float, required=True, help="The intended window.  Information only: it ends nothing.")
        readiness = sub.add_parser("readiness")
        readiness.add_argument("--id", required=True)
        readiness.add_argument("--actor", default=service.WORKER)
        for name in ("show", "verify"):
            sub.add_parser(name).add_argument("--id", required=True)
        approve = sub.add_parser("approve")
        approve.add_argument("--id", required=True)
        approve.add_argument("--actor", required=True)
        approve.add_argument("--plan-hash", required=True, help="The plan hash you reviewed (shown by 'show').")
        cancel = sub.add_parser("cancel")
        cancel.add_argument("--id", required=True)
        cancel.add_argument("--actor", required=True)
        for name in ("enter", "exit"):
            step = sub.add_parser(name)
            step.add_argument("--id", required=True)
            step.add_argument("--actor", required=True)
            step.add_argument("--confirm", required=True, help="The maintenance id, typed again.")
        sub.add_parser("list")

    def _show(self, row) -> None:
        status = service.status(row.pk, now=timezone.now())
        self.stdout.write(json.dumps(status, indent=1, default=str))

    def handle(self, *args, **options):
        action, now = options["action"], timezone.now
        try:
            if action == "list":
                for row in models.MaintenanceRecord.objects.all()[:50]:
                    self.stdout.write(f"{row.record_id}  {row.device_name:<8} {row.state:<26} requested by {row.requested_by}: {row.reason}")
                return
            if action == "verify":
                row = service._row(options["id"])
                intact, problems = evidence.verify(row)
                self.stdout.write(f"{row.record_id}: evidence chain {'INTACT' if intact else 'BROKEN'} ({len(evidence.entries(row))} entries)")
                for problem in problems:
                    self.stdout.write(f"  {problem}")
                if not intact:
                    raise CommandError("the evidence chain does not verify")
                return
            if action == "request":
                row = service.request(options["device"], options["actor"], options["reason"], timedelta(hours=options["hours"]), now=now(),
                                      runtime=service.production_runtime())
            elif action == "readiness":
                row = service.evaluate(options["id"], options["actor"], now=now(), runtime=service.production_runtime())
            elif action == "approve":
                row = service.approve(options["id"], options["actor"], now=now(), plan_hash=options["plan_hash"])
            elif action == "cancel":
                row = service.cancel(options["id"], options["actor"], now=now())
            elif action in ("enter", "exit"):
                if options["confirm"].upper() != service._row(options["id"]).record_id:
                    raise CommandError("--confirm must repeat the maintenance id")
                run = service.enter if action == "enter" else service.leave
                try:
                    row = run(options["id"], options["actor"], now=now, runtime=service.production_runtime())
                except model.MaintenanceError as refused:
                    self._show(service._row(options["id"]))
                    raise CommandError(str(refused)) from None
            else:
                row = service._row(options["id"])
        except model.MaintenanceError as refused:
            raise CommandError(str(refused)) from None
        self._show(row)
        if row.escalated and action in ("enter", "exit"):
            raise CommandError(f"{row.record_id}: {row.state}")
