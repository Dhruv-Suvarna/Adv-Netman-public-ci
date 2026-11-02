"""Managed-device registry from the shell (NMAS database only -- no device, NetBox or credential is touched).

    python manage.py nmas_devices list                                    READ-ONLY: every resolved device and discrepancy
    python manage.py nmas_devices resolve --name R1                       READ-ONLY: one device's resolution as JSON
    python manage.py nmas_devices adopt --name R1 --role router --actor <user> --confirm R1
    python manage.py nmas_devices expire-authorizations [--actor <label>] closes bootstrap authorizations whose window is over

``adopt`` needs ``--actor`` to be an active website user holding ``core.nmas_approve`` (the same permission as the page).
"""

from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from ...services.devices import authorization, lifecycle, resolver
from ...services.identity.policy import Action, permission_name


class Command(BaseCommand):
    help = "Inspect the managed-device resolver, adopt an existing device, expire bootstrap authorizations."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("list")
        resolve = sub.add_parser("resolve")
        resolve.add_argument("--name", required=True)
        adopt = sub.add_parser("adopt")
        adopt.add_argument("--name", required=True)
        adopt.add_argument("--role", required=True, choices=lifecycle.ROLES)
        adopt.add_argument("--actor", required=True)
        adopt.add_argument("--confirm", required=True, help="repeat the device name")
        expire = sub.add_parser("expire-authorizations")
        expire.add_argument("--actor", default="system:bootstrap-authorization-expiry")

    def handle(self, *args, **options):
        action = options["action"]
        if action == "list":
            resolution = resolver.resolve_all()
            for target in resolution.targets.values():
                self.stdout.write(f"{target.name:<12} {target.authority:<22} {target.scope:<20} {target.device_id or '-':<11} "
                                  f"{(target.lifecycle or {}).get('lifecycle_state', '-')}")
            for item in resolution.discrepancies:
                self.stdout.write(f"DISCREPANCY {item.code} {item.name} {item.detail}")
            return
        if action == "resolve":
            target = resolver.resolve(options["name"])
            if target is None:
                raise CommandError(f"{options['name']!r} is not a managed or registered device")
            self.stdout.write(json.dumps(target.as_dict(), indent=2, sort_keys=True))
            return
        if action == "adopt":
            if options["confirm"] != options["name"]:
                raise CommandError("--confirm must repeat the device name")
            user = get_user_model().objects.filter(username=options["actor"], is_active=True).first()
            if user is None or not user.has_perm(permission_name(Action.APPROVE)):
                raise CommandError("--actor must be an active user holding core.nmas_approve")
            result = lifecycle.adopt_existing(options["name"], role=options["role"], actor=user.get_username())
            if not result.ok:
                raise CommandError(f"refused: {', '.join(result.codes)}")
            self.stdout.write(f"{result.device.device_id} {result.device.name}: {'adopted' if result.changed else 'already adopted'}")
            return
        expired = authorization.expire_due(actor=options["actor"])
        self.stdout.write(f"expired {len(expired)}: {', '.join(expired) or '-'}")
