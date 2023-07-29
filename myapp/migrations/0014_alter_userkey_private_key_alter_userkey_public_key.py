# Generated by Django 4.2.3 on 2023-07-21 08:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0013_rename_verified_sharedaccess_isverified'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userkey',
            name='private_key',
            field=models.CharField(max_length=2000),
        ),
        migrations.AlterField(
            model_name='userkey',
            name='public_key',
            field=models.CharField(blank=True, max_length=1000),
        ),
    ]