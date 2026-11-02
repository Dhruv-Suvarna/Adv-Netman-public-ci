"""Device-aware cEOS MFA rollout command.

Secrets and approval are interactive/provider-only. No password, TOTP, RADIUS
secret or approval option exists on argv.
"""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core.services.credentials import r1_pilot as rollout
from core.services.credentials.r1_pilot_runner import R1PilotRunner

OPERATIONS = (
    "precheck", "validate", "status", "checkpoint", "stage1", "verify-logins",
    "stage2", "confirm", "persist", "replace", "verify-positive", "record-verification",
)


class Command(BaseCommand):
    help = "Reviewed one-device-at-a-time cEOS MFA rollout with checkpoints and an EOS commit timer."

    def add_arguments(self, parser):
        parser.add_argument("operation", choices=OPERATIONS)
        parser.add_argument("--device", required=True)
        parser.add_argument("--name", help="Device-specific checkpoint name for checkpoint/replace")
        parser.add_argument("--phase", choices=("post-stage1", "post-stage2"), help="verify-logins contract")

    def handle(self, *args, **options):
        try:
            target = rollout.target_for(options["device"])
        except rollout.PilotError as exc:
            raise CommandError(str(exc)) from None
        operation = options["operation"]
        if operation in ("checkpoint", "replace"):
            if not options["name"]:
                raise CommandError("--name is required for checkpoint/replace.")
            if options["name"] not in target.checkpoints:
                raise CommandError(f"--name must be one of {list(target.checkpoints)} for {target.device}.")
        if operation == "verify-logins" and not options["phase"]:
            raise CommandError("--phase is required for verify-logins.")
        runner = R1PilotRunner(device=target.device, target=target)
        runner.deps.actor = "manage.py ceos_mfa_rollout"
        try:
            if operation == "precheck":
                result = runner.precheck()
            elif operation == "validate":
                result = runner.validate()
            elif operation == "status":
                result = runner.status()
            elif operation == "checkpoint":
                result = runner.checkpoint(options["name"])
            elif operation == "stage1":
                result = runner.stage1()
            elif operation == "verify-logins":
                result = runner.verify(options["phase"])
            elif operation == "stage2":
                result = runner.stage2()
            elif operation == "confirm":
                result = runner.confirm()
            elif operation == "persist":
                result = runner.persist()
            elif operation == "verify-positive":
                result = runner.verify_positive()
            elif operation == "record-verification":
                result = runner.record_verification()
            else:
                result = runner.replace(options["name"])
        except rollout.PilotError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(json.dumps(result, indent=1, sort_keys=True, default=str))
        verdict = result.get("PASS", result.get("ok"))
        if verdict is False:
            raise CommandError(f"{operation}: FAIL (see the redacted evidence above).")
