# Generated by Django 4.2 on 2023-05-03 10:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mainapp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='usermodel',
            name='email',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='name',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]