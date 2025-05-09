# Generated by Django 5.1.6 on 2025-04-20 06:00

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0031_alter_application_application_id'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='application',
            name='author',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='applications', to=settings.AUTH_USER_MODEL, verbose_name='Автор'),
        ),
        migrations.RemoveField(
            model_name='application',
            name='authors',
        ),
        migrations.AddField(
            model_name='application',
            name='authors',
            field=models.ManyToManyField(blank=True, related_name='authored_applications', to=settings.AUTH_USER_MODEL, verbose_name='Авторы инновации'),
        ),
    ]
