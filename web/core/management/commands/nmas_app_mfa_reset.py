"""Reset (remove) one user's NMAS WEBSITE authenticator -- the administrative recovery path for website MFA.

    python manage.py nmas_app_mfa_reset --username <user> --confirm

The user re-enrolls Microsoft Authenticator at their next sign-in.  Audited as APP_MFA_RESET.  This never touches
network-device MFA (privacyIDEA / RADIUS) or any device credential.
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from core.models import AuditEventType
from core.services.identity import audit, mfa


class Command(BaseCommand):
    help = "Reset a user's NMAS website MFA authenticator (they re-enroll at next sign-in)."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--confirm", action="store_true", help="Required: acknowledge the reset.")
        parser.add_argument("--actor", default="nmas-console-admin", help="Administrator identity recorded in the audit log.")

    def handle(self, *args, username, confirm, actor, **options):
        if not confirm:
            raise CommandError("Refusing without --confirm.")
        try:
            user = get_user_model().objects.get(username=username)
        except get_user_model().DoesNotExist as exc:
            raise CommandError(f"No NMAS user named {username!r}.") from exc
        removed = mfa.reset(user)
        audit.record(AuditEventType.APP_MFA_RESET, f"Website MFA reset for {username} (console)", actor=actor[:150],
                     outcome=audit.OUTCOME_SUCCESS, object_type="User", object_id=str(user.pk),
                     metadata={"target_username": username, "had_authenticator": removed, "path": "management_command"})
        self.stdout.write(f"Website MFA for {username}: {'reset' if removed else 'no authenticator was enrolled'}; "
                          "the user enrolls again at next sign-in.")
