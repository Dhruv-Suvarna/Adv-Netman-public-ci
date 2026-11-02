"""Create only non-secret database metadata for one reviewed cEOS rollout.

This command never connects to a device, resolves a secret, creates a local
EOS account, or enrolls a TOTP token. It makes the later rendered candidate
complete and deterministic while leaving every live rollout gate in place.
"""
from __future__ import annotations

import json
import re

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from core.models import AccountKind, DeviceAuthMethod, DeviceCredential, DeviceLoginMfaPolicy, MfaMechanism
from core.services.credentials import r1_pilot as rollout
from core.services.credentials.mfa import render_candidate

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_RESERVED = {"admin", "nmas-automation", "nmas-telemetry"}


class Command(BaseCommand):
    help = "Prepare non-secret DeviceCredential metadata for one reviewed cEOS human-TOTP rollout; never touches a device."

    def add_arguments(self, parser):
        parser.add_argument("--human-username", required=True)
        parser.add_argument("--device", default="R1")
        parser.add_argument("--json", action="store_true")

    @staticmethod
    def _ensure_account(*, device, username, kind, secret_ref, role, privilege, auth_method):
        existing = DeviceCredential.objects.filter(device_name=device, username=username).first()
        if existing is not None and existing.account_kind != kind:
            raise CommandError(f"{device}/{username} already exists with incompatible account metadata.")
        if existing is None:
            return DeviceCredential.objects.create(
                device_name=device, username=username, platform="arista_ceos",
                account_kind=kind, auth_method=auth_method, secret_ref=secret_ref,
                account_role=role, privilege_level=privilege, rotation_enabled=False,
            )
        # Preserve any separately reviewed SSH-key enrollment/audit metadata.
        # This command owns rollout classification only; it must not silently
        # erase another credential workflow's evidence.
        existing.platform = "arista_ceos"
        existing.auth_method = auth_method
        existing.secret_ref = secret_ref
        existing.account_role = role
        existing.privilege_level = privilege
        existing.rotation_enabled = False
        existing.save(update_fields=(
            "platform", "auth_method", "secret_ref", "account_role",
            "privilege_level", "rotation_enabled", "updated_at",
        ))
        return existing

    @transaction.atomic
    def handle(self, *args, **options):
        device = options["device"]
        try:
            target = rollout.target_for(device)
        except rollout.PilotError as exc:
            raise CommandError(str(exc)) from None
        human = options["human_username"].strip()
        if not _NAME_RE.fullmatch(human) or human in (_RESERVED | {target.breakglass_account}):
            raise CommandError("Human username is invalid or reserved for a local/machine identity.")
        legacy = DeviceCredential.objects.filter(
            device_name=device, username="admin", account_kind=AccountKind.LEGACY_SHARED,
        ).first()
        if legacy is None:
            raise CommandError(f"{device} legacy admin metadata is required to render an exact rollback.")
        if DeviceCredential.objects.filter(device_name=device, account_kind=AccountKind.HUMAN).exclude(username=human).exists():
            raise CommandError(f"{device} rollout metadata already names a different human operator; reconcile it explicitly.")
        policy = DeviceLoginMfaPolicy.objects.filter(device_name=device).first()
        if policy is None or policy.platform != "arista_ceos" or policy.mechanism != MfaMechanism.RADIUS_TOTP:
            raise CommandError(f"{device} requires an existing arista_ceos RADIUS_TOTP policy row.")

        rows = [
            self._ensure_account(
                device=device,
                username="nmas-automation", kind=AccountKind.SERVICE,
                secret_ref=target.automation_ref,
                role="network-admin", privilege=15, auth_method=DeviceAuthMethod.PASSWORD,
            ),
            self._ensure_account(
                device=device,
                username=target.breakglass_account, kind=AccountKind.BREAK_GLASS,
                secret_ref=target.breakglass_ref,
                role="network-admin", privilege=15, auth_method=DeviceAuthMethod.PASSWORD,
            ),
            self._ensure_account(
                device=device,
                username=human, kind=AccountKind.HUMAN, secret_ref="",
                role="network-admin", privilege=15, auth_method=DeviceAuthMethod.PASSWORD_AND_TOTP,
            ),
        ]
        candidate = render_candidate(policy, list(DeviceCredential.objects.filter(device_name=device)))
        if candidate.blockers:
            raise CommandError("Candidate remains blocked: " + "; ".join(candidate.blockers))
        policy.candidate_digest = candidate.digest
        policy.save(update_fields=["candidate_digest", "updated_at"])
        payload = {
            "device": device,
            "accounts": [
                {"username": row.username, "account_kind": row.account_kind, "auth_method": row.auth_method,
                 "secret_ref": row.secret_ref or "operator-held"}
                for row in rows
            ],
            "live_device_changed": False,
            "totp_enrolled": False,
            "candidate_digest": candidate.digest,
            "least_privilege_exception": "EOS role enforcement defect; automation and break-glass retain network-admin/15",
        }
        self.stdout.write(json.dumps(payload, sort_keys=True) if options["json"]
                          else f"{device} rollout metadata prepared; live state unchanged.")
