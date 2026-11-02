"""Finalise abandoned traffic test runs (a crash or restart left them CREATED / RUNNING past their deadline) as INTERRUPTED.

Read-only against the network: it only updates the abandoned rows.  Safe to run at any time and from a scheduler; a run is never
reconciled into a pass.
"""

from django.core.management.base import BaseCommand

from core.services import traffic_service


class Command(BaseCommand):
    help = "Mark traffic test runs that were abandoned past their deadline as INTERRUPTED."

    def handle(self, *args, **options):
        reconciled = traffic_service.reconcile()
        for run in reconciled:
            self.stdout.write(f"{run.run_id} {run.family} {run.source}->{run.destination}: INTERRUPTED")
        self.stdout.write(f"reconciled {len(reconciled)} abandoned run(s)")
