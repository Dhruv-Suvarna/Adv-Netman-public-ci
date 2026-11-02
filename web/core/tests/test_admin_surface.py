"""Admin surface safety: no admin list names a secret-shaped field, and audit/lifecycle admins are view-only."""

from __future__ import annotations

from django.test import TestCase

from core import admin as core_admin
from core import models

SECRET_LOOKING_SUBSTRINGS = ("password", "secret", "token", "webhook", "credential", "private_key")


class AdminSurfaceSecretSafetyTests(TestCase):
    ADMIN_CLASSES = (
        core_admin.ChangeAdmin,
        core_admin.DeviceIntentAdmin,
        core_admin.DeviceIntentRevisionAdmin,
        core_admin.IntentFieldStateAdmin,
        core_admin.ConfigletAdmin,
        core_admin.ConfigletDependencyAdmin,
        core_admin.ChangeLifecycleEventAdmin,
        core_admin.AuditEventAdmin,
    )

    def test_no_admin_list_display_names_a_secret_field(self):
        for admin_class in self.ADMIN_CLASSES:
            list_display = getattr(admin_class, "list_display", ())
            for field_name in list_display:
                lowered = str(field_name).lower()
                for term in SECRET_LOOKING_SUBSTRINGS:
                    with self.subTest(admin=admin_class.__name__, field=field_name, term=term):
                        self.assertNotIn(term, lowered)

    def test_lifecycle_and_audit_admin_are_view_only(self):
        for model, admin_class in (
            (models.ChangeLifecycleEvent, core_admin.ChangeLifecycleEventAdmin),
            (models.AuditEvent, core_admin.AuditEventAdmin),
        ):
            instance = admin_class(model, core_admin.admin.site)
            self.assertFalse(instance.has_add_permission(None))
            self.assertFalse(instance.has_change_permission(None))
            self.assertFalse(instance.has_delete_permission(None))
