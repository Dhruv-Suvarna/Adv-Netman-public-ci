"""Operator recovery for an UNCERTAIN / stale IN_PROGRESS credential rotation."""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core.models import DeviceCredential
from core.services.credentials.engine import reconcile_credential


class Command(BaseCommand):
    help = "Resolve an UNCERTAIN rotation by fresh-login testing the pending then current candidate (never changes the device)."

    def add_arguments(self, parser):
        parser.add_argument("--credential-id", type=int, required=True)

    def handle(self, *args, **options):
        if not DeviceCredential.objects.filter(pk=options["credential_id"]).exists():
            raise CommandError("Unknown credential id.")
        outcome = reconcile_credential(options["credential_id"])
        self.stdout.write(json.dumps(outcome.__dict__, sort_keys=True))
        if outcome.status not in ("SUCCESS", "FAILED", "SKIPPED"):
            raise SystemExit(1)
