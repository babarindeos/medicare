# Generated by Django 4.2.2 on 2023-07-21 00:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0008_sharedaccess'),
    ]

    operations = [
        migrations.RenameField(
            model_name='sharedaccess',
            old_name='doctor',
            new_name='healthworker',
        ),
    ]