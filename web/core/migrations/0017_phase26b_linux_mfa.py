from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("core", "0016_phase26_safe_credential_rotation")]

    operations = [
        migrations.AlterField(
            model_name="devicecredential",
            name="auth_method",
            field=models.CharField(
                choices=[
                    ("PASSWORD", "Password only (single factor)"),
                    ("PUBLICKEY", "SSH public key only (machine identity)"),
                    ("PUBLICKEY_AND_PASSWORD", "Legacy SSH key + password (automation-capable; not current human 2FA)"),
                    ("PASSWORD_AND_TOTP", "Human password + Microsoft Authenticator TOTP"),
                ],
                default="PASSWORD",
                max_length=32,
            ),
        ),
    ]
