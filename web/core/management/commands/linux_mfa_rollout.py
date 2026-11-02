"""Guarded R3/R4 Linux human MFA rollout command."""
from __future__ import annotations

import getpass
import json

from django.core.management.base import BaseCommand, CommandError

from core.services.credentials import linux_mfa as lm
from core.services.credentials.linux_mfa_runner import LinuxMfaRunner


OPERATIONS = ("stage-radius", "install-module", "precheck", "backup", "arm", "activate", "verify-machine-recovery",
              "verify-operational", "verify-human", "finalize", "status")


def human_factors():
    try:
        password = getpass.getpass("nmas-admin password (not echoed): ")
        otp = getpass.getpass("Current Microsoft Authenticator code (not echoed): ")
    except (EOFError, OSError):
        raise lm.LinuxMfaError("An interactive terminal is required for the human factor proof.") from None
    return password, otp


class Command(BaseCommand):
    help = "One-device-at-a-time R3/R4 PAM RADIUS/TOTP rollout with an automatic rollback timer."

    def add_arguments(self, parser):
        parser.add_argument("operation", choices=OPERATIONS)
        parser.add_argument("--device", choices=("R3", "R4"), required=True)
        parser.add_argument("--token", help="Opaque token emitted by backup; required for timer-window operations")

    def handle(self, *args, **options):
        operation = options["operation"]; token = options.get("token")
        if operation in ("arm", "activate", "verify-machine-recovery", "verify-operational", "verify-human", "finalize") and not token:
            raise CommandError("--token is required for this timer-window operation.")
        runner = LinuxMfaRunner(options["device"])
        try:
            if operation == "stage-radius": result = runner.stage_radius()
            elif operation == "install-module": result = runner.install_module()
            elif operation == "precheck": result = runner.precheck()
            elif operation == "backup": result = runner.backup()
            elif operation == "arm": result = runner.arm(token)
            elif operation == "activate": result = runner.activate(token)
            elif operation == "verify-machine-recovery": result = runner.verify_machine_recovery(token)
            elif operation == "verify-operational": result = runner.verify_operational(token)
            elif operation == "verify-human": result = runner.verify_human(token, human_factors)
            elif operation == "finalize": result = runner.finalize(token)
            else: result = runner.status()
        except lm.LinuxMfaError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(json.dumps(result, indent=1, sort_keys=True, default=str))
        if result.get("PASS") is False:
            raise CommandError(f"{operation}: FAIL; leave the automatic rollback timer armed.")
