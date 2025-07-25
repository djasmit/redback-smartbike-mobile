# Generated by Django 5.2 on 2025-05-06 13:34

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend_server', '0044_myuser_otp_myuser_otp_created_at'),
    ]

    operations = [
        migrations.CreateModel(
            name='Schedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(default='Workout', max_length=100)),
                ('description', models.TextField(blank=True, null=True)),
                ('date', models.DateField()),
                ('time', models.TimeField()),
                ('reminder_minutes', models.IntegerField(default=0)),
                ('recurrence', models.CharField(choices=[('None', 'None'), ('Daily', 'Daily'), ('Weekly', 'Weekly'), ('Monthly', 'Monthly')], default='None', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='backend_server.myuser')),
            ],
        ),
    ]
