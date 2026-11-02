"""Create protected, non-live metadata for exactly one R3/R4 rollout."""
from __future__ import annotations

import json
import os
import secrets
import tempfile

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from modules.device_credentials import (FileSecretProvider, SecretNotFound, SecretProviderError,
                                        load_ssh_private_key)

from core.models import (AccountKind, CentralAaaState, CredentialStatus, DeviceAuthMethod, DeviceCredential,
                         DeviceLoginMfaPolicy, MfaEnforcementState, MfaMechanism)
from core.services.credentials.linux_mfa import HUMAN_USERNAME, SERVICE_USERNAME, radius_secret_path, target_for
from core.services.credentials.mfa import generate_service_keypair, public_key_fingerprint, render_candidate


def _write_private_new(path, value: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".radius-linux-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None; handle.write(value + "\n"); handle.flush(); os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        if fd is not None: os.close(fd)
        try: os.unlink(temporary)
        except FileNotFoundError: pass


class Command(BaseCommand):
    help = "Prepare protected R3/R4 Linux MFA identities and policy metadata; never contacts or changes a device."

    def add_arguments(self, parser):
        parser.add_argument("--device", choices=("R3", "R4"), required=True)
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        target = target_for(options["device"])
        provider = FileSecretProvider()
        created = []
        try:
            try:
                key_version = provider.current(target.service_key_ref).version
                pkey = load_ssh_private_key(target.service_key_ref, path=provider.path)
                public = f"{pkey.get_name()} {pkey.get_base64()} {SERVICE_USERNAME}@{target.device.lower()}"
                fingerprint = public_key_fingerprint(public)
            except SecretNotFound:
                private, public, fingerprint = generate_service_keypair(f"{SERVICE_USERNAME}@{target.device.lower()}")
                key_version = provider.initialize(target.service_key_ref, private)
                del private
                created.append("service_key")
            try:
                breakglass_version = provider.current(target.breakglass_ref).version
            except SecretNotFound:
                breakglass_version = provider.initialize(target.breakglass_ref, secrets.token_urlsafe(36))
                created.append("breakglass_password")
            radius_path = radius_secret_path(target.device)
            if not radius_path.exists():
                _write_private_new(radius_path, secrets.token_urlsafe(48))
                created.append("radius_secret")
        except (OSError, SecretProviderError) as exc:
            raise CommandError(f"Protected metadata preparation failed ({exc.__class__.__name__}).") from None

        with transaction.atomic():
            root = DeviceCredential.objects.select_for_update().filter(
                device_name=target.device, username="root", account_kind=AccountKind.LEGACY_SHARED,
            ).first()
            if root is None:
                raise CommandError("Existing local-root recovery metadata is missing; refusing rollout preparation.")
            service, _ = DeviceCredential.objects.update_or_create(
                device_name=target.device, username=SERVICE_USERNAME,
                defaults={"platform": "ubuntu_frr", "account_kind": AccountKind.SERVICE,
                          "auth_method": DeviceAuthMethod.PUBLICKEY, "secret_ref": "",
                          "ssh_key_ref": target.service_key_ref, "ssh_public_key": public,
                          "ssh_public_key_fingerprint": fingerprint, "account_role": "machine-read",
                          "privilege_level": None, "rotation_enabled": False, "next_due_at": None,
                          "last_status": CredentialStatus.BLOCKED, "last_result_code": "PUBLICKEY_ONLY_NOT_ROTATABLE"},
            )
            breakglass, _ = DeviceCredential.objects.update_or_create(
                device_name=target.device, username=target.breakglass_username,
                defaults={"platform": "ubuntu_frr", "account_kind": AccountKind.BREAK_GLASS,
                          "auth_method": DeviceAuthMethod.PASSWORD, "secret_ref": target.breakglass_ref,
                          "account_role": "emergency-root", "privilege_level": None,
                          "rotation_enabled": False, "next_due_at": None},
            )
            human, _ = DeviceCredential.objects.update_or_create(
                device_name=target.device, username=HUMAN_USERNAME,
                defaults={"platform": "ubuntu_frr", "account_kind": AccountKind.HUMAN,
                          "auth_method": DeviceAuthMethod.PASSWORD_AND_TOTP, "secret_ref": "",
                          "account_role": "sudo-admin", "privilege_level": None,
                          "rotation_enabled": False, "next_due_at": None},
            )
            policy = DeviceLoginMfaPolicy.objects.select_for_update().get(device_name=target.device)
            policy.platform = "ubuntu_frr"; policy.mechanism = MfaMechanism.RADIUS_TOTP
            policy.enforcement_state = MfaEnforcementState.PLANNED; policy.central_aaa_state = CentralAaaState.PLANNED
            policy.radius_secret_ref = target.radius_ref; policy.radius_source_interface = "Vlan200"
            policy.automation_exempt = True; policy.blocked_reason = ""
            policy.emergency_path = f"{target.breakglass_username} from NMAS or docker exec privileged shell"
            candidate = render_candidate(policy, DeviceCredential.objects.filter(device_name=target.device))
            if candidate.blockers:
                raise CommandError("Prepared metadata did not satisfy the reviewed Linux MFA candidate contract.")
            policy.candidate_digest = candidate.digest; policy.save()
        payload = {
            "device": target.device, "device_changed": False, "created_protected_items": sorted(created),
            "service_credential_id": service.pk, "breakglass_credential_id": breakglass.pk,
            "human_credential_id": human.pk, "service_key_version": key_version,
            "breakglass_version": breakglass_version, "public_key_fingerprint": fingerprint,
            "candidate_digest": candidate.digest, "blockers": candidate.blockers,
        }
        self.stdout.write(json.dumps(payload, sort_keys=True) if options["json"] else str(payload))
