# Generated from Django 5.2.18. No user/native resource backfill or IO.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("user_admin", "0003_native_binding_stages")]

    operations = [
        migrations.AddField(
            model_name="operation",
            name="observed",
            field=models.CharField(
                max_length=16, blank=True, default="", editable=False
            ),
        ),
        migrations.AddField(
            model_name="operation",
            name="authority_epoch",
            field=models.PositiveBigIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="target",
            name="authority_epoch",
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="target",
            name="block_authority_epoch",
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="target",
            name="management_paused",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="target",
            name="pause_actor_id",
            field=models.PositiveBigIntegerField(editable=False, null=True),
        ),
        migrations.CreateModel(
            name="ManagementEvent",
            fields=[
                (
                    "id",
                    models.UUIDField(editable=False, primary_key=True, serialize=False),
                ),
                ("actor_id", models.PositiveBigIntegerField()),
                ("paused", models.BooleanField()),
                ("before_epoch", models.PositiveBigIntegerField()),
                ("after_epoch", models.PositiveBigIntegerField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "target",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        to="user_admin.target",
                    ),
                ),
            ],
        ),
    ]
