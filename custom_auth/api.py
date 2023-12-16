from django.contrib.auth import authenticate, login, logout
from rest_framework import permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView

from custom_auth.serializers import UserRegisterationSerializer, UserSerializer
from utils.permissions import IsAPIKEYAuthenticated


class RegistartionView(APIView):
    permission_classes = (permissions.AllowAny, IsAPIKEYAuthenticated)

    def post(self, request):
        serialiser = UserRegisterationSerializer(data=request.data)
        if serialiser.is_valid():
            serialiser.save()
            return Response(serialiser.data,status = status.HTTP_201_CREATED)
        return Response(serialiser.errors,status = status.HTTP_400_BAD_REQUEST)


class LoginApiView(APIView):
    permission_classes = (permissions.AllowAny, IsAPIKEYAuthenticated)

    def post(self, request):
        email = self.request.get('email')
        password = self.request.get('password')
        user = authenticate(request,username=email,password=password)

        if user is not None:
            login(request,user)
            token, create = Token.objects.get_or_create(user=user)
            serialiser = UserSerializer(user)

            serialsier_data = serialiser.data
            serialsier_data['token'] = token.key
            return Response(serialiser.data)
        else:
            return Response({'error':"Invalid Credetional"}, status= status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated, IsAPIKEYAuthenticated)

    def delete(self, request):
        request.auth.delete()
        logout(request)
        return Response({'message':"Logout Successfull"}, status= status.HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes = (permissions.IsAuthenticated, IsAPIKEYAuthenticated)

    def put(self, request):
        user = request.user
        current_password = self.request.get('current_password')
        new_password = self.request.get('new_passord')

        if not user.check_password(current_password):
            return Response({'error':'Current passord is incorrct.'} , status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()

        return Response({'message':"Password Successfully change"}, status = status.HTTP_200_OK)