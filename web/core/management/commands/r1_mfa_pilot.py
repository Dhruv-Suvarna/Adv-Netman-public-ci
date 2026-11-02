"""Reviewed R1 Microsoft Authenticator 2FA pilot helper.

    manage.py r1_mfa_pilot validate                 # canary parser validation; sessions always aborted
    manage.py r1_mfa_pilot status                   # read-only state, timer and gates
    manage.py r1_mfa_pilot checkpoint --name pre-2fa-pilot      # LIVE
    manage.py r1_mfa_pilot stage1                               # LIVE
    manage.py r1_mfa_pilot verify-logins --phase post-stage1    # SSH login checks, no config change
    manage.py r1_mfa_pilot checkpoint --name pre-2fa-stage2     # LIVE
    manage.py r1_mfa_pilot stage2                               # LIVE, commit timer 00:10:00
    manage.py r1_mfa_pilot verify-logins --phase post-stage2    # prompts for nmas-admin factors (not echoed)
    manage.py r1_mfa_pilot confirm                              # LIVE
    manage.py r1_mfa_pilot replace --name pre-2fa-pilot|pre-2fa-stage2   # LIVE restore
    manage.py r1_mfa_pilot verify-positive                      # routine: ONE nmas-admin password+TOTP login, no negatives
    manage.py r1_mfa_pilot record-verification                  # R1 policy metadata from recorded evidence (DB only)

LIVE operations read the approval phrase from the interactive terminal only;
no secret or approval is ever accepted on argv.  Output is redacted JSON.
"""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core.services.credentials import r1_pilot as p
from core.services.credentials.r1_pilot_runner import R1PilotRunner

OPERATIONS = ("validate", "status", "checkpoint", "stage1", "verify-logins", "stage2", "confirm", "replace",
              "verify-positive", "record-verification")


class Command(BaseCommand):
    help = "Reviewed R1 2FA pilot helper: canary validation, status, checkpoints, staged apply, commit-timer confirm, restore."

    def add_arguments(self, parser):
        parser.add_argument("operation", choices=OPERATIONS)
        parser.add_argument("--device", default=p.PILOT_DEVICE, help="Only R1 is accepted; anything else is refused.")
        parser.add_argument("--name", choices=p.CHECKPOINTS, help="checkpoint/replace recovery point")
        parser.add_argument("--phase", choices=("post-stage1", "post-stage2"), help="verify-logins contract")

    def handle(self, *args, **options):
        operation = options["operation"]
        if options["device"] != p.PILOT_DEVICE:
            raise CommandError(f"This helper only targets {p.PILOT_DEVICE}; refusing {options['device']!r}.")
        if operation in ("checkpoint", "replace") and not options["name"]:
            raise CommandError("--name is required for checkpoint/replace.")
        if operation == "verify-logins" and not options["phase"]:
            raise CommandError("--phase is required for verify-logins.")
        runner = R1PilotRunner(device=options["device"])
        runner.deps.actor = "manage.py r1_mfa_pilot"
        try:
            if operation == "validate":
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
            elif operation == "verify-positive":
                result = runner.verify_positive()
            elif operation == "record-verification":
                result = runner.record_verification()
            else:
                result = runner.replace(options["name"])
        except p.PilotError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(json.dumps(result, indent=1, sort_keys=True, default=str))
        verdict = result.get("PASS", result.get("ok"))
        if verdict is False:
            raise CommandError(f"{operation}: FAIL (see the redacted evidence above).")
