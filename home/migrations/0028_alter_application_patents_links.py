# Generated by Django 5.1.6 on 2025-04-21 03:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0027_alter_application_options'),
    ]

    operations = [
        migrations.AlterField(
            model_name='application',
            name='patents_links',
            field=models.TextField(blank=True, null=True, verbose_name='Статьи, доклады, патенты, «ноу-хау» (при наличии)'),
        ),
    ]
