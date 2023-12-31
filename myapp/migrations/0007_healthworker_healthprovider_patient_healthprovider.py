# Generated by Django 4.2.2 on 2023-07-16 16:56

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0006_patient'),
    ]

    operations = [
        migrations.AddField(
            model_name='healthworker',
            name='healthprovider',
            field=models.ForeignKey(default='1', on_delete=django.db.models.deletion.CASCADE, related_name='hcp_worker', to='myapp.healthprovider'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='patient',
            name='healthprovider',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='hcp_patient', to='myapp.healthprovider'),
            preserve_default=False,
        ),
    ]
