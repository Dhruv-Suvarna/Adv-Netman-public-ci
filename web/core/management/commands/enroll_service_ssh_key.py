"""Generate an optional NMAS machine SSH key in the protected provider.

This remains automation-specific and is not Microsoft Authenticator enrollment.
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from modules.device_credentials import FileSecretProvider, SecretProviderError

from core.models import AccountKind, DeviceAuthMethod, DeviceCredential
from core.services.credentials.mfa import generate_service_keypair


class Command(BaseCommand):
    help = ("Create an optional Ed25519 key for a SERVICE account: the private key goes only to the runtime provider; "
            "this does not enroll or satisfy the authoritative human TOTP policy and contacts no device.")

    def add_arguments(self, parser):
        parser.add_argument("--credential-id", type=int, required=True)
        parser.add_argument("--key-ref", required=True, help="runtime://device-credentials/<key> for the private key")
        parser.add_argument("--replace", action="store_true")

    def handle(self, *args, **options):
        try:
            credential = DeviceCredential.objects.get(pk=options["credential_id"])
        except DeviceCredential.DoesNotExist:
            raise CommandError("Unknown credential id.") from None
        if credential.account_kind != AccountKind.SERVICE:
            raise CommandError("Only SERVICE accounts have NMAS-held keys; humans register their own public key.")
        private, public, fingerprint = generate_service_keypair(f"{credential.username}@nmas")
        try:
            FileSecretProvider().initialize(options["key_ref"], private, replace=options["replace"])
        except SecretProviderError as exc:
            raise CommandError(str(exc)) from None
        del private
        credential.ssh_key_ref = options["key_ref"]
        credential.ssh_public_key = public
        credential.ssh_public_key_fingerprint = fingerprint
        credential.auth_method = DeviceAuthMethod.PUBLICKEY_AND_PASSWORD
        credential.save()
        self.stdout.write(f"Enrolled {credential} public key {fingerprint}")
        self.stdout.write(public)
