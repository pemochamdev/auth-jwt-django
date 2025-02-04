from rest_framework import status, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
from django.utils import timezone
from users.serializers import (
    UserSerializer, 
    CustomTokenObtainPairSerializer,
    ChangePasswordSerializer,
    LoginHistorySerializer
)
from .models import LoginHistory
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class RegisterView(APIView):
    permission_classes = (AllowAny,)
    throttle_scope = 'registration'  # Protection contre les attaques par force brute

    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                user = serializer.save()
                
                # Créer les tokens JWT
                refresh = RefreshToken.for_user(user)
                
                # Enregistrer l'historique
                LoginHistory.objects.create(
                    user=user,
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    status='success'
                )
                
                return Response({
                    'user': UserSerializer(user, context={'request': request}).data,
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in registration: {str(e)}", exc_info=True)
            return Response(
                {'error': _("Une erreur est survenue lors de l'inscription")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')



class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    throttle_scope = 'login'

    def post(self, request, *args, **kwargs):
        try:
            # Vérifier le nombre de tentatives par IP
            ip = self._get_client_ip(request)
            attempts_key = f"login_attempts_{ip}"
            attempts = cache.get(attempts_key, 0)
            
            if attempts >= 5:
                return Response(
                    {'error': _("Trop de tentatives. Réessayez plus tard.")},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

            serializer = self.get_serializer(data=request.data)
            
            try:
                serializer.is_valid(raise_exception=True)
            except ValidationError as e:
                # Incrémenter le compteur de tentatives
                cache.set(attempts_key, attempts + 1, timeout=300)
                return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)

            user = serializer.user
            cache.delete(attempts_key)  # Réinitialiser les tentatives en cas de succès
            
            # Enregistrer l'historique de connexion
            LoginHistory.objects.create(
                user=user,
                ip_address=ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status='success',
                location_city=self._get_location_city(ip),
                location_country=self._get_location_country(ip)
            )
            
            # Mettre à jour les informations de connexion
            user.last_login_ip = ip
            user.last_login = timezone.now()
            user.save(update_fields=['last_login_ip', 'last_login'])
            
            return Response(serializer.validated_data)
            
        except Exception as e:
            logger.error(f"Error in login: {str(e)}", exc_info=True)
            return Response(
                {'error': _("Une erreur est survenue lors de la connexion")},
                status=status.HTTP_400_BAD_REQUEST
            )
            
            
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

    def _get_location_city(self, ip):
        # Implémenter la géolocalisation IP ici
        return ""

    def _get_location_country(self, ip):
        # Implémenter la géolocalisation IP ici
        return ""

class ChangePasswordView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer
    throttle_scope = 'password_change'

    def update(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = request.user
                
                # Changer le mot de passe
                user.set_password(serializer.validated_data['new_password'])
                user.password_changed_at = timezone.now()
                user.save()
                
                # Blacklister tous les tokens existants
                RefreshToken.for_user(user)
                
                # Créer de nouveaux tokens
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'message': _("Mot de passe modifié avec succès"),
                    'refresh': str(refresh),
                    'access': str(refresh.access_token)
                }, status=status.HTTP_200_OK)
                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f"Error in password change: {str(e)}", exc_info=True)
            return Response(
                {'error': _("Une erreur est survenue lors du changement de mot de passe")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(
                instance, 
                data=request.data, 
                partial=partial,
                context={'request': request}
            )
            
            if serializer.is_valid():
                self.perform_update(serializer)
                return Response(serializer.data)
                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Error updating profile: {str(e)}", exc_info=True)
            return Response(
                {'error': _("Une erreur est survenue lors de la mise à jour du profil")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LoginHistoryView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LoginHistorySerializer
    pagination_class = None  # Ou définir une pagination personnalisée

    def get_queryset(self):
        return (LoginHistory.objects
                .filter(user=self.request.user)
                .select_related('user')
                .order_by('-login_datetime'))

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response(
                    {'error': _("Le token de rafraîchissement est requis")},
                    status=status.HTTP_400_BAD_REQUEST
                )

            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Enregistrer la déconnexion
            LoginHistory.objects.create(
                user=request.user,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status='logout'
            )
            
            return Response(status=status.HTTP_204_NO_CONTENT)
            
        except TokenError:
            return Response(
                {'error': _("Token invalide ou expiré")},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error in logout: {str(e)}", exc_info=True)
            return Response(
                {'error': _("Une erreur est survenue lors de la déconnexion")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')