# Generated by Django 3.0.5 on 2020-04-20 18:44

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=500)),
                ('is_active', models.BooleanField(default=True)),
                ('timestamp', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='token_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('token', 'user')},
            },
        ),
    ]
