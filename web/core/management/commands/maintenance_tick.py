"""One pass of the Maintenance Mode worker (run by ``nmas-maintenance-tick.timer``).

    python manage.py maintenance_tick            recover interrupted runs, run queued operator requests, start due deadline restores
    python manage.py maintenance_tick --dry-run  report what is due; claim nothing, contact nothing

Idempotent and safe to run concurrently: every record is claimed before anything is done with it.  With nothing due it
reads one table and exits without building the runtime (no NetBox, inventory or device access).  Exit status 1 when a
restore ended escalated (``RESTORE_FAILED_ESCALATED``), so the unit's failure is visible in ``systemctl``.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q
from django.utils import timezone

from core import models
from core.services.maintenance_mode import lifecycle, service


class Command(BaseCommand):
    help = "Run one pass of the Maintenance Mode worker."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Report what is due; claim and contact nothing.")

    def handle(self, *args, **options):
        if options["dry_run"]:
            now = timezone.now()
            stale = Q(claim_token="") | Q(heartbeat_at__lt=now - service.CLAIM_STALE_AFTER)
            due = {
                "recover": models.MaintenanceRecord.objects.filter(stale, state__in=(lifecycle.ENTERING, lifecycle.RESTORING)).count(),
                "queued": models.MaintenanceRecord.objects.filter(claim_token="").exclude(queued_action="").count(),
                "deadline": models.MaintenanceRecord.objects.filter(claim_token="", state=lifecycle.ACTIVE, deadline_at__lte=now).count(),
            }
            self.stdout.write("MAINTENANCE_TICK_DRY_RUN: " + ", ".join(f"{key}={value}" for key, value in due.items()))
            return
        results = service.tick(now=timezone.now)
        self.stdout.write(f"MAINTENANCE_TICK: {len(results)} item(s)" + "".join(
            f"\n  {row['record']} {row['item']} -> {row['state']} ({row['outcome']})" for row in results))
        if any(row.get("escalated") and row["state"] == lifecycle.RESTORE_FAILED for row in results):
            raise CommandError("a restore was not completed and is escalated (RESTORE_FAILED_ESCALATED)")
