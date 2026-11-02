"""Configuration Validation (GitHub Actions) from the server shell.

    python manage.py nmas_configuration_validation status       --change CHG-...     READ-ONLY apart from the GitHub status refresh
    python manage.py nmas_configuration_validation reconcile    [--change CHG-...]   read results from GitHub for every run that owes one
    python manage.py nmas_configuration_validation demo-failure --change CHG-... --actor <name>

``status`` refreshes and prints the tracked run of a Change.  The normal trigger is not here: NMAS dispatches the
workflow by itself when a Change passes validation (Save Draft / Run Change Validation).

``demo-failure`` shows a failing run without touching anything: it takes the Change's latest PASSING validation run,
adds one labelled protected-VLAN violation to a COPY of its bundle and dispatches that.  The tracking row is marked as
a demonstration; it never counts for the execution gate and never replaces the real result.  No device is contacted
and the Change itself is not modified.
"""

from django.core.management.base import BaseCommand, CommandError

from core import models
from core.services.configuration_validation import service


class Command(BaseCommand):
    help = "Show the Configuration Validation of a Change, or dispatch a deliberately failing demonstration."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("status").add_argument("--change", required=True)
        sub.add_parser("reconcile").add_argument("--change", default="")
        demo = sub.add_parser("demo-failure")
        demo.add_argument("--change", required=True)
        demo.add_argument("--actor", required=True)

    def _print(self, title, row):
        if row is None:
            self.stdout.write(f"{title}: none")
            return
        self.stdout.write(f"{title}: {service.effective_status(row) if not row.demonstration else row.status}  correlation {row.correlation_id}\n"
                          f"  candidate {row.candidate_hash[:12]}  snapshot {row.snapshot_hash[:12]}  run {row.github_run_id or '-'}  {row.run_url or ''}\n"
                          f"  triggered {row.triggered_at or '-'}  completed {row.completed_at or '-'}  repo sha {row.tested_sha[:12] or '-'}\n"
                          f"  {row.failure_summary}".rstrip())

    def handle(self, *args, **options):
        if options["action"] == "reconcile" and not options["change"]:
            owing = models.Change.objects.filter(configuration_validation_runs__status__in=[*service.PENDING, service.S.STALE],
                                                 configuration_validation_runs__completed_at__isnull=True).distinct()
            for change in owing:
                for row in service.reconcile(change):
                    self._print(change.change_id, row)
            return
        change = models.Change.objects.filter(change_id=options["change"]).first()
        if change is None:
            raise CommandError("No such Change.")
        if options["action"] == "demo-failure":
            run = change.validation_runs.filter(status__in=service.PASSING_TIER2).order_by("-created_at", "-id").first()
            if run is None or service.exempt(change):
                raise CommandError("The Change needs a passing validation run (and must not be a routing transition).")
            self._print("DEMONSTRATION (deliberately invalid)", service.dispatch(run, actor=options["actor"], demonstration=True))
            return
        service.reconcile(change)
        row, demo = service.latest(change), service.latest(change, demonstration=True)
        self._print("CONFIGURATION_VALIDATION", row)
        if demo is not None:
            self._print("DEMONSTRATION (deliberately invalid)", demo)
