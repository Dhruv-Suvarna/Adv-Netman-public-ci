"""Append-only state reconciliation from the server shell.

    python manage.py nmas_reconcile observe --device R2
    python manage.py nmas_reconcile accept  --device R2 --actor <name> --reason "<why>" --ack "ACCEPT R2 <digest12>" \
                                            --run <run id> [--run ...] --section "interface Ethernet1" [--section ...]
    python manage.py nmas_reconcile project-status --record REC-000001 --status active --actor <name> --confirm

``observe`` is read-only.  ``accept`` writes one StateReconciliation row and one audit event and never contacts a device
for writing.  ``project-status`` sets ONE NetBox device status because the named record says so; nothing is inferred from
interface state.
"""

import json

from django.core.management.base import BaseCommand, CommandError

from core import models
from core.services import reconciliation_service as service


class Command(BaseCommand):
    help = "Observe a device, accept its current state as the expected baseline, or project a reconciled status to NetBox."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        observe = sub.add_parser("observe")
        observe.add_argument("--device", required=True)
        accept = sub.add_parser("accept")
        accept.add_argument("--device", required=True)
        accept.add_argument("--actor", required=True)
        accept.add_argument("--reason", required=True)
        accept.add_argument("--ack", required=True, help='Exactly "ACCEPT <device> <first 12 digits of the observed digest>".')
        accept.add_argument("--run", action="append", default=[], help="A superseded execution run id (repeatable).")
        accept.add_argument("--section", action="append", default=[], help="An affected configuration section (repeatable).")
        project = sub.add_parser("project-status")
        project.add_argument("--record", required=True)
        project.add_argument("--status", required=True)
        project.add_argument("--actor", required=True)
        project.add_argument("--confirm", action="store_true")

    def handle(self, *args, **options):
        try:
            getattr(self, "_" + options["action"].replace("-", "_"))(options)
        except service.ReconciliationError as exc:
            raise CommandError(f"{exc.code}: {exc}") from exc

    def _observe(self, options):
        observation = service.observe(options["device"])
        self.stdout.write(json.dumps(observation, indent=2, sort_keys=True))
        if observation["state"] == "OK":
            self.stdout.write("acknowledgement: " + service.acknowledgement_phrase(options["device"], observation["digest"]))

    def _accept(self, options):
        observation = service.observe(options["device"])
        record, created = service.accept(
            device_name=options["device"], actor=options["actor"], reason=options["reason"], acknowledgement=options["ack"],
            execution_run_ids=options["run"], affected_sections=options["section"], observation=observation)
        self.stdout.write(f"{record.record_id} {'CREATED' if created else 'UNCHANGED'} {record.device_name} "
                          f"previous={record.previous_expected_digest[:12]} accepted={record.accepted_digest[:12]}")

    def _project_status(self, options):
        record = models.StateReconciliation.objects.filter(record_id=options["record"]).first()
        if record is None:
            raise CommandError(f"No reconciliation record {options['record']}.")
        from modules import netbox_ipam

        result = service.project_netbox_status(record=record, status=options["status"], actor=options["actor"],
                                               client=netbox_ipam.build_client(), confirm=options["confirm"])
        self.stdout.write(f"{record.record_id} NetBox {result['device']}: {result['previous']} -> {result['status']} ({result['action']})")
