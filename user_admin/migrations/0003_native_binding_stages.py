# Generated from Django 5.2.18; additive stages, no user/identity backfill.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("sso", "0002_minio_browser_challenge"),
        ("user_admin", "0002_usercontrol_api_version_usercontrol_auth_epoch_and_more"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="operation", name="ua_target_generation"
        ),
        migrations.AddField(
            model_name="target",
            name="creation_operation",
            field=models.ForeignKey(
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="created_targets",
                to="user_admin.operation",
            ),
        ),
        migrations.AddField(
            model_name="target",
            name="identity",
            field=models.OneToOneField(
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="managed_target",
                to="sso.serviceidentity",
            ),
        ),
        migrations.AlterField(
            model_name="operation",
            name="action",
            field=models.CharField(
                choices=[
                    ("create", "Create"),
                    ("bind", "Bind"),
                    ("enable", "Enable"),
                    ("block", "Block"),
                ],
                max_length=16,
            ),
        ),
        migrations.AddConstraint(
            model_name="operation",
            constraint=models.UniqueConstraint(
                fields=("target", "generation", "action"),
                name="ua_target_generation_action",
            ),
        ),
    ]
