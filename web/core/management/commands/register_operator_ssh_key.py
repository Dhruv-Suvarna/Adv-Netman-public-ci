"""Register legacy Phase-23 human SSH-key metadata.

Retained for dependency compatibility; this is not Microsoft Authenticator
enrollment and no longer represents the authoritative human 2FA design.
"""
from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.models import AccountKind, DeviceAuthMethod, DeviceCredential
from core.services.credentials.mfa import MfaConfigError, parse_public_key, public_key_fingerprint


class Command(BaseCommand):
    help = ("DEPRECATED for human 2FA: record legacy public-key metadata only. Microsoft Authenticator TOTP "
            "enrollment occurs later in privacyIDEA. Does not contact any device.")

    def add_arguments(self, parser):
        parser.add_argument("--device", required=True)
        parser.add_argument("--platform", default="arista_ceos")
        parser.add_argument("--username", required=True)
        parser.add_argument("--public-key-file", required=True)
        parser.add_argument("--role", default="network-admin")
        parser.add_argument("--privilege", type=int, default=15)
        parser.add_argument("--break-glass", action="store_true", help="Mark as the emergency administrator account")

    def handle(self, *args, **options):
        try:
            line = Path(options["public_key_file"]).read_text(encoding="utf-8").strip()
            parse_public_key(line)
        except (OSError, MfaConfigError) as exc:
            raise CommandError(f"Public key rejected: {exc.__class__.__name__}") from None
        credential, _ = DeviceCredential.objects.update_or_create(
            device_name=options["device"], username=options["username"],
            defaults={
                "platform": options["platform"],
                "account_kind": AccountKind.BREAK_GLASS if options["break_glass"] else AccountKind.HUMAN,
                "auth_method": DeviceAuthMethod.PUBLICKEY_AND_PASSWORD,
                "account_role": options["role"], "privilege_level": options["privilege"],
                "ssh_public_key": line, "ssh_public_key_fingerprint": public_key_fingerprint(line),
                "rotation_enabled": False,
            },
        )
        self.stdout.write(self.style.WARNING("Legacy metadata only: SSH key + password is superseded for human 2FA."))
        self.stdout.write(f"Registered {credential} {credential.ssh_public_key_fingerprint}")
