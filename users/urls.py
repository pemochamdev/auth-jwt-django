
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from users.views import (
    RegisterView,
    CustomTokenObtainPairView,
    ChangePasswordView,
    UserProfileView,
    LoginHistoryView,
    LogoutView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('login-history/', LoginHistoryView.as_view(), name='login_history'),
    path('logout/', LogoutView.as_view(), name='logout'),
]


