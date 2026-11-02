"""Render (never apply) the authoritative human 2FA candidate for one device."""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core.models import DeviceCredential, DeviceLoginMfaPolicy
from core.services.credentials.mfa import MfaConfigError, render_candidate


class Command(BaseCommand):
    help = "Render the deterministic Microsoft Authenticator/RADIUS candidate + rollback; secrets remain provider references."

    def add_arguments(self, parser):
        parser.add_argument("--device", required=True)
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--record-digest", action="store_true", help="Store the candidate digest on the policy row")

    def handle(self, *args, **options):
        try:
            policy = DeviceLoginMfaPolicy.objects.get(device_name=options["device"])
        except DeviceLoginMfaPolicy.DoesNotExist:
            raise CommandError("No two-factor policy for that device.") from None
        try:
            candidate = render_candidate(policy, list(DeviceCredential.objects.filter(device_name=policy.device_name)))
        except MfaConfigError as exc:
            raise CommandError(str(exc)) from None
        if options["record_digest"]:
            policy.candidate_digest = candidate.digest
            policy.save(update_fields=["candidate_digest", "updated_at"])
        if options["json"]:
            self.stdout.write(json.dumps(candidate.as_dict(), sort_keys=True))
            return
        self.stdout.write(f"# {policy.device_name} ({policy.platform}) digest {candidate.digest}")
        for blocker in candidate.blockers:
            self.stdout.write(f"# BLOCKER: {blocker}")
        self.stdout.write("\n".join(candidate.lines))
        self.stdout.write("# --- rollback ---")
        self.stdout.write("\n".join(candidate.rollback_lines))
