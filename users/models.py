from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
import uuid
from users.managers import CustomUserManager

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None
    email = models.EmailField(
        _('adresse email'), 
        unique=True,
        error_messages={
            'unique': _("Un utilisateur avec cette adresse email existe déjà."),
        }
    )
    first_name = models.CharField(_('prénom'), max_length=150)
    last_name = models.CharField(_('nom'), max_length=150)
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message=_("Le numéro de téléphone doit être au format: '+999999999'. 15 chiffres maximum.")
    )
    phone = models.CharField(
        _('téléphone'), 
        validators=[phone_regex], 
        max_length=15, 
        blank=True
    )
    date_of_birth = models.DateField(_('date de naissance'), null=True, blank=True)
    is_verified = models.BooleanField(_('vérifié'), default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    is_locked = models.BooleanField(default=False)
    lock_timestamp = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(null=True, blank=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = CustomUserManager()

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ['-created_at']

    def __str__(self):
        return self.email

    def lock_account(self):
        from django.utils import timezone
        self.is_locked = True
        self.lock_timestamp = timezone.now()
        self.save()

    def reset_login_attempts(self):
        self.failed_login_attempts = 0
        self.is_locked = False
        self.lock_timestamp = None
        self.save()

class UserProfile(models.Model):
    GENDER_CHOICES = [
        ('M', _('Masculin')),
        ('F', _('Féminin')),
        ('O', _('Autre')),
    ]

    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='profile'
    )
    avatar = models.ImageField(
        upload_to='avatars/%Y/%m/', 
        null=True, 
        blank=True
    )
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=100, blank=True)
    preferences = models.JSONField(
        default=dict,
        help_text=_("Préférences utilisateur en format JSON")
    )
    gender = models.CharField(
        max_length=1,
        choices=GENDER_CHOICES,
        blank=True
    )
    website = models.URLField(blank=True)
    
    class Meta:
        verbose_name = _('profil utilisateur')
        verbose_name_plural = _('profils utilisateurs')

    def __str__(self):
        return f"Profil de {self.user.email}"

class LoginHistory(models.Model):
    LOGIN_STATUS_CHOICES = [
        ('success', _('Succès')),
        ('failed', _('Échec')),
        ('locked', _('Compte verrouillé')),
    ]

    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='login_history'
    )
    login_datetime = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=255)
    status = models.CharField(
        max_length=20,
        choices=LOGIN_STATUS_CHOICES,
        default='failed'
    )
    location_city = models.CharField(max_length=100, blank=True)
    location_country = models.CharField(max_length=100, blank=True)
    
    class Meta:
        verbose_name = _('historique de connexion')
        verbose_name_plural = _('historiques de connexion')
        ordering = ['-login_datetime']
        indexes = [
            models.Index(fields=['user', '-login_datetime']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.login_datetime} - {self.status}"