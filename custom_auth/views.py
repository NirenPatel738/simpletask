from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from drf_secure_token.models import Token
from django.contrib.auth import authenticate, login, logout

from utils.permissions import IsAPIKEYAuthenticated
from .serializers import UserSerializer, UserRegisterationSerializer


class RegistrationAPIView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = UserRegisterationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = (permissions.AllowAny, IsAPIKEYAuthenticated)

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            serializer = UserSerializer(user)

            # Manually add the token to the serialized data
            serialized_data = serializer.data
            serialized_data['token'] = token.key

            return Response(serialized_data)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated,IsAPIKEYAuthenticated)

    def delete(self, request):
        # Delete the authentication token or session information
        request.auth.delete()

        # Logout the user
        logout(request)

        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)


class ChangePasswordAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated,IsAPIKEYAuthenticated)

    def put(self, request):
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        if not user.check_password(current_password):
            return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
