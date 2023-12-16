# your_app/urls.py
from django.urls import path
from .views import RegistrationAPIView, LoginAPIView, LogoutAPIView, ChangePasswordAPIView

urlpatterns = [
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),
]
