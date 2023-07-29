# Generated by Django 4.2.3 on 2023-07-19 21:59

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0007_healthworker_healthprovider_patient_healthprovider'),
    ]

    operations = [
        migrations.CreateModel(
            name='SharedAccess',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('identifier', models.CharField(max_length=10)),
                ('doctor', models.CharField(max_length=10)),
                ('patient', models.CharField(max_length=10)),
                ('type', models.CharField(max_length=50)),
                ('owner', models.CharField(max_length=50)),
                ('owner_publickey', models.CharField(max_length=255)),
                ('owner_privatekey', models.CharField(max_length=255)),
                ('recipient', models.CharField(max_length=255)),
                ('recipient_publickey', models.CharField(max_length=255)),
                ('recipient_privatekey', models.CharField(max_length=255)),
                ('date', models.DateTimeField(blank=True, default=datetime.datetime.now)),
            ],
        ),
    ]
