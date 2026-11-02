"""Baseline configuration templates (V2 Phase 3).

    manage.py nmas_templates generate-baselines [--live] [--write-packages]
        Build the six baseline families from the source devices.  Default: the newest STORED sanitized snapshot of each
        source (no device contact).  --live performs the existing read-only capture instead.  Never mutates a device.
    manage.py nmas_templates load-baselines
        Register the tracked packages under templates/baselines/ on this instance (idempotent).
    manage.py nmas_templates list
"""

from django.core.management.base import BaseCommand, CommandError

from core.services.config_templates import baselines, service


class Command(BaseCommand):
    help = "Generate, export and load the baseline configuration templates."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=("generate-baselines", "load-baselines", "list"))
        parser.add_argument("--live", action="store_true", help="Read each source device (read-only capture) instead of its stored snapshot.")
        parser.add_argument("--write-packages", action="store_true", help="Also write the tracked packages to templates/baselines/.")
        parser.add_argument("--actor", default="nmas-templates-cli")

    def handle(self, *args, **options):
        actor = options["actor"]
        try:
            if options["action"] == "generate-baselines":
                for row in baselines.generate(actor=actor, live=options["live"]):
                    self.stdout.write(f"{row['key']}: {row['ref']} {'PUBLISHED' if row['created'] else 'unchanged'} {row['digest'][:12]}")
                if options["write_packages"]:
                    for path in baselines.write_packages(actor=actor):
                        self.stdout.write(f"wrote {path.name}")
            elif options["action"] == "load-baselines":
                for row in baselines.load_packages(actor=actor):
                    self.stdout.write(f"{row['file']}: {row['ref']} {'REGISTERED' if row['created'] else 'already present'} {row['digest'][:12]}")
            else:
                for row in service.list_templates(include_retired=True):
                    shown = row["shown"]
                    self.stdout.write(f"{row['template'].template_id} [{row['template'].family}] v{shown.version} {shown.status} {shown.digest[:12]} {row['template'].name}")
        except service.TemplateError as exc:
            raise CommandError(str(exc)) from None
