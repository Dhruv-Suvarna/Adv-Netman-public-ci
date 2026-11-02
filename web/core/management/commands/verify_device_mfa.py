"""Legacy SSH-key + password verifier retained for Phase-23 evidence.

The authoritative Microsoft Authenticator RADIUS/TOTP design needs a human,
controlled live verification procedure and must never consume an operator's
TOTP seed through NMAS.  This command therefore refuses RADIUS_TOTP policies.
"""
from __future__ import annotations

import json

import paramiko
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from modules.device_credentials import FileSecretProvider, SecretProviderError, load_ssh_private_key

from core.models import AccountKind, DeviceCredential, DeviceLoginMfaPolicy, MfaEnforcementState, MfaMechanism
from core.services import nsot_live
from core.services.credentials.mfa import evaluate_probe, probe_two_factor_login


class Command(BaseCommand):
    help = "Legacy Phase-23 SSH-key + password probe; RADIUS/TOTP policies require the controlled human rollout verifier."

    def add_arguments(self, parser):
        parser.add_argument("--device", required=True)
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        try:
            policy = DeviceLoginMfaPolicy.objects.get(device_name=options["device"])
        except DeviceLoginMfaPolicy.DoesNotExist:
            raise CommandError("No two-factor policy for that device.") from None
        if policy.mechanism == MfaMechanism.RADIUS_TOTP:
            raise CommandError(
                "Microsoft Authenticator RADIUS/TOTP verification is intentionally unavailable before controlled live rollout."
            )
        if policy.enforcement_state not in (MfaEnforcementState.ENFORCED, MfaEnforcementState.LIVE_VERIFIED):
            raise CommandError("Policy is not ENFORCED; live verification requires an authorized activation first.")
        credential = DeviceCredential.objects.filter(
            device_name=policy.device_name, account_kind=AccountKind.SERVICE, ssh_key_ref__gt="",
        ).first()
        target = nsot_live.get_live_target_metadata(policy.device_name)
        if credential is None or target is None:
            raise CommandError("No enrolled service account or trusted target.")
        try:
            password = FileSecretProvider().current(credential.secret_ref).value
            pkey = load_ssh_private_key(credential.ssh_key_ref)
        except SecretProviderError:
            raise CommandError("Protected provider could not supply the service factors.") from None

        def transport_factory():
            transport = paramiko.Transport((target["address"], 22))
            transport.banner_timeout = settings.EXECUTION_DEVICE_TIMEOUT_SECONDS
            transport.start_client(timeout=settings.EXECUTION_DEVICE_TIMEOUT_SECONDS)
            return transport

        results = probe_two_factor_login(transport_factory, credential.username, password=password, pkey=pkey)
        ok, verdict = evaluate_probe(results)
        policy.last_verification_result = verdict
        if ok:
            policy.enforcement_state = MfaEnforcementState.LIVE_VERIFIED
            policy.last_verified_at = timezone.now()
        elif policy.enforcement_state == MfaEnforcementState.LIVE_VERIFIED:
            policy.enforcement_state = MfaEnforcementState.ENFORCED  # evidence no longer holds
        policy.save()
        payload = {"device": policy.device_name, "results": results, "verdict": verdict}
        self.stdout.write(json.dumps(payload, sort_keys=True) if options["json"] else f"{policy.device_name}: {verdict} {results}")
        if not ok:
            raise SystemExit(1)
