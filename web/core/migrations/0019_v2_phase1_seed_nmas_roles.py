"""Seed the NMAS website role groups (V2 Phase 1).

Frozen copy of core.services.identity.policy.ROLE_PERMISSIONS at the time of writing (a contract test keeps the two
equal).  Idempotent: an existing group keeps any extra permission an administrator added; reversing removes nothing
an operator may depend on except the seeded groups themselves.
"""

from django.db import migrations

ROLES = {
    "NMAS Viewer": ("nmas_view",),
    "NMAS Operator": ("nmas_view", "nmas_edit", "nmas_validate", "nmas_plan"),
    "NMAS Approver": ("nmas_view", "nmas_approve"),
    "NMAS Executor": ("nmas_view", "nmas_execute"),
    "NMAS Security Admin": ("nmas_view", "nmas_security_admin"),
}


def seed_roles(apps, schema_editor):
    from django.contrib.auth.management import create_permissions

    app_config = apps.get_app_config("core")
    app_config.models_module = True
    create_permissions(app_config, apps=apps, verbosity=0)
    app_config.models_module = None

    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    for name, codenames in ROLES.items():
        group, _ = Group.objects.get_or_create(name=name)
        perms = Permission.objects.filter(content_type__app_label="core", codename__in=codenames)
        group.permissions.add(*perms)


def unseed_roles(apps, schema_editor):
    apps.get_model("auth", "Group").objects.filter(name__in=ROLES).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("contenttypes", "0002_remove_content_type_name"),
        ("core", "0018_v2_phase1_identity_audit_capabilities"),
    ]

    operations = [migrations.RunPython(seed_roles, unseed_roles)]
