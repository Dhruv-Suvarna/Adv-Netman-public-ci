from django.db import migrations, models


OLD_CISCO = "cisco_ios8000v"
IOS_XR = "cisco_iosxr"


def classify_legacy_cisco_as_ios_xr(apps, schema_editor):
    """The removed identifier rendered/parsed IOS XR, so preserve its actual semantics."""
    for model_name in ("DeviceIntent", "RawConfigletRevision", "RunningConfigSnapshot", "ConfigRemoval", "CapabilityEvidence"):
        model = apps.get_model("core", model_name)
        model.objects.filter(platform=OLD_CISCO).update(platform=IOS_XR)


def reverse_legacy_cisco(apps, schema_editor):
    for model_name in ("DeviceIntent", "RawConfigletRevision", "RunningConfigSnapshot", "ConfigRemoval", "CapabilityEvidence"):
        model = apps.get_model("core", model_name)
        model.objects.filter(platform=IOS_XR).update(platform=OLD_CISCO)


PLATFORM_CHOICES = [
    ("arista_ceos", "Arista cEOS"),
    ("nokia_srlinux", "Nokia SR Linux"),
    ("ubuntu_frr", "Ubuntu / FRR"),
    ("cisco_c8000v_iosxe", "Cisco Catalyst 8000V / IOS XE"),
    ("cisco_iosxr", "Cisco IOS XR"),
    ("sonic", "SONiC"),
]


class Migration(migrations.Migration):
    dependencies = [("core", "0021_v2_phase3_configuration_templates")]

    operations = [
        migrations.AddField(
            model_name="capabilityevidence", name="evidence_type",
            field=models.CharField(default="STATIC", max_length=16),
        ),
        migrations.AddField(
            model_name="capabilityevidence", name="repository_head",
            field=models.CharField(blank=True, default="", max_length=40),
        ),
        migrations.AddField(
            model_name="capabilityevidence", name="runtime_version",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.RunPython(classify_legacy_cisco_as_ios_xr, reverse_legacy_cisco),
        migrations.AlterField(model_name="deviceintent", name="platform", field=models.CharField(choices=PLATFORM_CHOICES, max_length=32)),
        migrations.AlterField(model_name="rawconfigletrevision", name="platform", field=models.CharField(choices=PLATFORM_CHOICES, max_length=32)),
        migrations.AlterField(model_name="runningconfigsnapshot", name="platform", field=models.CharField(choices=PLATFORM_CHOICES, max_length=32)),
        migrations.AlterField(model_name="configremoval", name="platform", field=models.CharField(choices=PLATFORM_CHOICES, max_length=32)),
    ]
