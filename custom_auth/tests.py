from django.test import TestCase

# Create your tests here.


from django.contrib.auth import authenticate, login, logout
from drf_secure_token.models import Token
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from custom_auth.serializers import UserRegisterationSerializer, UserSerializer
from utils.permissions import IsAPIKEYAuthenticated


class RegistrationView(APIView):
    permission_classes = (permissions.AllowAny)

    def post(self, request):
        serialiser = UserRegisterationSerializer(data=request.data)
        if serialiser.is_valid():
            serialiser.save()
            return Response(serialiser.data,status=status.HTTP_201_CREATED)
        return Response(serialiser.errors,status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = (permissions.IsAuthenticated, IsAPIKEYAuthenticated)

    def post(self,request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request,email=email,password=password)

        if user is not None:
            login(request,user)
            token,create = Token.objects.get_or_create(user=user)
            serialiser = UserSerializer(user)
            serialiser_data= serialiser.data
            serialiser_data['token'] = token.key

            return Response(serialiser_data)
        else:
            return Response({'error':'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated, IsAPIKEYAuthenticated)

    def delete(self, request):
        request.auth.delete()
        logout(request)
        return Response({'message':'Logout successfull'}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes = (permissions.IsAuthenticated, IsAPIKEYAuthenticated)

    def put(self, request):
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        if not user.check_password(current_password):
            return Response({'error':'Current Password is incorect'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({'message':'Password Chnage Successfully'}, status=status.HTTP_200_OK)


