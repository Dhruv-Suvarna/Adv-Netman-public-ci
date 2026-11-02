from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0022_v2_phase4_binary_capability_evidence")]

    operations = [
        migrations.CreateModel(
            name="CapabilityAssessment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("platform", models.CharField(max_length=32)),
                ("feature", models.CharField(max_length=64)),
                ("probes", models.JSONField(default=dict)),
                ("evidence_ids", models.JSONField(default=list)),
                ("repository_head", models.CharField(max_length=40)),
                ("runtime_version", models.CharField(blank=True, default="", max_length=128)),
                ("recorded_by", models.CharField(blank=True, default="", max_length=150)),
                ("recorded_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["-recorded_at", "-id"], "indexes": [models.Index(fields=["platform", "feature", "-recorded_at"], name="cap_assessment_cell_time")]},
        ),
    ]
