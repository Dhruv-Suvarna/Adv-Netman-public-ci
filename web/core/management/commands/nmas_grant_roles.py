"""Create / update an NMAS website user and assign NMAS role groups (bootstrap and admin enrollment).

    python manage.py nmas_grant_roles --username alice --all-roles --create      # prompts for a password (never echoed)
    python manage.py nmas_grant_roles --username bob --role "NMAS Viewer"

Roles are the Django groups seeded by migration 0019 (core.services.identity.policy.ROLE_PERMISSIONS).  Passwords are
only ever read interactively through getpass and stored as Django password hashes; nothing is printed or logged.
"""

import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from core.models import AuditEventType
from core.services.identity import audit, policy


class Command(BaseCommand):
    help = "Create/update an NMAS website user and assign NMAS role groups."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--role", action="append", default=[], choices=sorted(policy.ROLE_PERMISSIONS))
        parser.add_argument("--all-roles", action="store_true")
        parser.add_argument("--create", action="store_true", help="Create the user if missing (prompts for a password).")
        parser.add_argument("--staff", action="store_true", help="Also allow Django admin access (is_staff).")
        parser.add_argument("--set-password", action="store_true", help="Prompt for a new password.")

    def handle(self, *args, username, role, all_roles, create, staff, set_password, **options):
        User = get_user_model()
        user = User.objects.filter(username=username).first()
        if user is None and not create:
            raise CommandError(f"No NMAS user named {username!r} (use --create).")
        created = user is None
        if created:
            user = User(username=username, is_active=True)
        if created or set_password:
            password = self._prompt_password(user)
            user.set_password(password)
        if staff:
            user.is_staff = True
        user.save()

        roles = sorted(policy.ROLE_PERMISSIONS) if all_roles else role
        for name in roles:
            group, _ = Group.objects.get_or_create(name=name)
            codenames = [a.value for a in policy.ROLE_PERMISSIONS[name]]
            group.permissions.add(*Permission.objects.filter(content_type__app_label="core", codename__in=codenames))
            user.groups.add(group)
        audit.record(AuditEventType.WEB_ACTION, f"NMAS roles granted to {username} (console)", actor="nmas-console-admin",
                     outcome=audit.OUTCOME_SUCCESS, object_type="User", object_id=str(user.pk),
                     metadata={"category": "security_admin", "target_username": username, "roles": roles,
                               "created": created, "staff": user.is_staff, "path": "management_command"})
        self.stdout.write(f"{'Created' if created else 'Updated'} {username}; roles: {', '.join(roles) or '(unchanged)'}.")

    def _prompt_password(self, user) -> str:
        for _ in range(3):
            first = getpass.getpass("New password: ")
            second = getpass.getpass("Repeat password: ")
            if first != second:
                self.stderr.write("Passwords do not match.")
                continue
            try:
                validate_password(first, user)
            except ValidationError as exc:
                self.stderr.write("; ".join(exc.messages))
                continue
            return first
        raise CommandError("No acceptable password entered.")
