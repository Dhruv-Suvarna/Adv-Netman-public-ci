"""Regenerate the V2 Phase 9 ten-stage capability ledger (docs/evidence/v2-phase7-9/phase9/capability-{ledger.json,summary.md})."""

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from ...services.capabilities import phase9_ledger


class Command(BaseCommand):
    help = "Regenerate the Phase 9 capability closure ledger from the stored exhaustive ledger and Phase 9 live evidence."

    def add_arguments(self, parser):
        parser.add_argument("--out", default="docs/evidence/v2-phase7-9/phase9")

    def handle(self, *args, **options):
        root = Path(settings.BASE_DIR).resolve().parent
        result = phase9_ledger.write(root, root / options["out"])
        self.stdout.write(f"matrix {result['matrix_total']} supported {result['matrix_supported']} totals {result['totals']}")
        for row in result["lifecycle_linked_rows"]:
            self.stdout.write(f"{row['platform']} {row['feature']}: {row['closure_class']} missing={row['missing_stages']}")
