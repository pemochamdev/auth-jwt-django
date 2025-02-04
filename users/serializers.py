from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from users.models import UserProfile, LoginHistory
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.utils import timezone
import re

User = get_user_model()

class UserProfileSerializer(serializers.ModelSerializer):
    avatar_url = serializers.SerializerMethodField()
    
    class Meta:
        model = UserProfile
        fields = ('avatar', 'avatar_url', 'bio', 'location', 'preferences', 'gender', 'website')
        extra_kwargs = {
            'avatar': {'write_only': True}
        }
    
    def get_avatar_url(self, obj):
        if obj.avatar:
            return self.context['request'].build_absolute_uri(obj.avatar.url)
        return None
    
    def validate_website(self, value):
        if value and not value.startswith(('http://', 'https://')):
            value = 'https://' + value
        return value

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'password_confirm', 'first_name', 
                 'last_name', 'phone', 'date_of_birth', 'profile', 'full_name',
                 'created_at', 'is_verified')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
            'created_at': {'read_only': True},
            'is_verified': {'read_only': True}
        }

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(_("Un utilisateur avec cette adresse email existe déjà."))
        return value.lower()

    def validate_phone(self, value):
        if value:
            pattern = r'^\+?1?\d{9,15}$'
            if not re.match(pattern, value):
                raise serializers.ValidationError(
                    _("Format de téléphone invalide. Utilisez le format: '+999999999'")
                )
        return value

    def validate_password(self, value):
        try:
            password_validation.validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs.pop('password_confirm'):
            raise serializers.ValidationError({"password": _("Les mots de passe ne correspondent pas")})
        
        if attrs.get('date_of_birth'):
            if attrs['date_of_birth'] > timezone.now().date():
                raise serializers.ValidationError(
                    {"date_of_birth": _("La date de naissance ne peut pas être dans le futur")}
                )
        return attrs

    def create(self, validated_data):
        profile_data = validated_data.pop('profile', None)
        password = validated_data.pop('password')
        
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.password_changed_at = timezone.now()
        user.save()
        
        if profile_data:
            UserProfile.objects.create(user=user, **profile_data)
        return user

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', None)
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        if password:
            instance.set_password(password)
            instance.password_changed_at = timezone.now()
            
        instance.save()
        
        if profile_data and hasattr(instance, 'profile'):
            for attr, value in profile_data.items():
                setattr(instance.profile, attr, value)
            instance.profile.save()
        elif profile_data:
            UserProfile.objects.create(user=instance, **profile_data)
            
        return instance

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        try:
            data = super().validate(attrs)
        except Exception as e:
            user = User.objects.filter(email=attrs.get('email')).first()
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:  # Configurable
                    user.lock_account()
                user.save()
            raise

        user = self.user
        if user.is_locked:
            raise serializers.ValidationError({
                "error": _("Compte verrouillé. Veuillez contacter le support."),
                "locked_since": user.lock_timestamp
            })

        data.update({
            'user': {
                'id': str(user.id),
                'email': user.email,
                'full_name': f"{user.first_name} {user.last_name}",
                'is_verified': user.is_verified,
                'profile': UserProfileSerializer(
                    user.profile,
                    context=self.context
                ).data if hasattr(user, 'profile') else None
            }
        })

        user.reset_login_attempts()
        return data

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password_confirm = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Ancien mot de passe incorrect"))
        return value

    def validate_new_password(self, value):
        try:
            password_validation.validate_password(value, self.context['request'].user)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                "new_password": _("Les nouveaux mots de passe ne correspondent pas")
            })
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError({
                "new_password": _("Le nouveau mot de passe doit être différent de l'ancien")
            })
        return attrs

class LoginHistorySerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = LoginHistory
        fields = ('id', 'user_email', 'login_datetime', 'ip_address', 
                 'user_agent', 'status', 'location_city', 'location_country')
        read_only_fields = ('id', 'login_datetime')