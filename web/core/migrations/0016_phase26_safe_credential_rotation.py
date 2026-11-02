from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0015_phase24_r1_pilot_audit_event"),
    ]

    operations = [
        migrations.AddField(
            model_name="credentialrotationrun",
            name="phase",
            field=models.CharField(
                choices=[
                    ("CLAIMED", "Database claim recorded"),
                    ("PROVIDER_STAGED", "Pending provider version staged"),
                    ("DEVICE_TIMER_ARMED", "EOS commit timer armed"),
                    ("NEW_VERIFIED", "New credential accepted"),
                    ("OLD_REJECTED", "Previous credential rejected"),
                    ("OPERATIONAL_VALIDATED", "Operational checks passed"),
                    ("DEVICE_CONFIRMED", "EOS transaction confirmed"),
                    ("STARTUP_PERSISTED", "Startup equals running"),
                    ("PROVIDER_PROMOTED", "Pending provider version promoted"),
                    ("COMPLETE", "Database finalization complete"),
                ],
                default="CLAIMED",
                max_length=32,
            ),
        ),
        migrations.AddField(model_name="credentialrotationrun", name="session_name", field=models.CharField(blank=True, default="", max_length=64)),
        migrations.AddField(model_name="credentialrotationrun", name="checkpoint_file", field=models.CharField(blank=True, default="", max_length=128)),
        migrations.AddField(model_name="credentialrotationrun", name="checkpoint_sha256", field=models.CharField(blank=True, default="", max_length=64)),
        migrations.AddField(model_name="credentialrotationrun", name="checkpoint_md5", field=models.CharField(blank=True, default="", max_length=32)),
        migrations.AddField(model_name="credentialrotationrun", name="pre_change_digest", field=models.CharField(blank=True, default="", max_length=64)),
        migrations.AddField(model_name="credentialrotationrun", name="post_change_digest", field=models.CharField(blank=True, default="", max_length=64)),
        migrations.AddField(model_name="credentialrotationrun", name="transaction_metadata", field=models.JSONField(blank=True, default=dict)),
        migrations.AddField(model_name="credentialrotationrun", name="old_login_verification_result", field=models.CharField(blank=True, default="NOT_ATTEMPTED", max_length=32)),
        migrations.AddField(model_name="credentialrotationrun", name="operational_validation_result", field=models.CharField(blank=True, default="NOT_ATTEMPTED", max_length=32)),
        migrations.AddField(model_name="credentialrotationrun", name="transaction_confirmation_result", field=models.CharField(blank=True, default="NOT_ATTEMPTED", max_length=32)),
        migrations.AddField(model_name="credentialrotationrun", name="persistence_result", field=models.CharField(blank=True, default="NOT_ATTEMPTED", max_length=32)),
        migrations.AddField(model_name="credentialrotationrun", name="startup_verification_result", field=models.CharField(blank=True, default="NOT_ATTEMPTED", max_length=32)),
        migrations.AddField(model_name="credentialrotationrun", name="provider_promotion_result", field=models.CharField(blank=True, default="NOT_ATTEMPTED", max_length=32)),
    ]
