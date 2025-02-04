# Generated by Django 5.1.5 on 2025-02-04 10:58

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(error_messages={'unique': 'Un utilisateur avec cette adresse email existe déjà.'}, max_length=254, unique=True, verbose_name='adresse email')),
                ('first_name', models.CharField(max_length=150, verbose_name='prénom')),
                ('last_name', models.CharField(max_length=150, verbose_name='nom')),
                ('phone', models.CharField(blank=True, max_length=15, validators=[django.core.validators.RegexValidator(message="Le numéro de téléphone doit être au format: '+999999999'. 15 chiffres maximum.", regex='^\\+?1?\\d{9,15}$')], verbose_name='téléphone')),
                ('date_of_birth', models.DateField(blank=True, null=True, verbose_name='date de naissance')),
                ('is_verified', models.BooleanField(default=False, verbose_name='vérifié')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_login_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('failed_login_attempts', models.IntegerField(default=0)),
                ('is_locked', models.BooleanField(default=False)),
                ('lock_timestamp', models.DateTimeField(blank=True, null=True)),
                ('password_changed_at', models.DateTimeField(blank=True, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('avatar', models.ImageField(blank=True, null=True, upload_to='avatars/%Y/%m/')),
                ('bio', models.TextField(blank=True, max_length=500)),
                ('location', models.CharField(blank=True, max_length=100)),
                ('preferences', models.JSONField(default=dict, help_text='Préférences utilisateur en format JSON')),
                ('gender', models.CharField(blank=True, choices=[('M', 'Masculin'), ('F', 'Féminin'), ('O', 'Autre')], max_length=1)),
                ('website', models.URLField(blank=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'profil utilisateur',
                'verbose_name_plural': 'profils utilisateurs',
            },
        ),
        migrations.CreateModel(
            name='LoginHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_datetime', models.DateTimeField(auto_now_add=True)),
                ('ip_address', models.GenericIPAddressField()),
                ('user_agent', models.CharField(max_length=255)),
                ('status', models.CharField(choices=[('success', 'Succès'), ('failed', 'Échec'), ('locked', 'Compte verrouillé')], default='failed', max_length=20)),
                ('location_city', models.CharField(blank=True, max_length=100)),
                ('location_country', models.CharField(blank=True, max_length=100)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='login_history', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'historique de connexion',
                'verbose_name_plural': 'historiques de connexion',
                'ordering': ['-login_datetime'],
                'indexes': [models.Index(fields=['user', '-login_datetime'], name='users_login_user_id_2cf214_idx')],
            },
        ),
    ]
