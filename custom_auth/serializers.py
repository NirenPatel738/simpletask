# your_app/serializers.py
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import Application_User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Application_User
        fields = ("id","name","email", "username","phone","gender","address" )


class UserRegisterationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Application_User
        fields = ("id","name","email","password", "username","phone","gender","address" )
        extra_kwargs = {
            'password': {'write_only': True, 'validators': [validate_password]},
            'email': {'required': True},
            'name': {'required': True},
            'gender': {'required': True},
        }

    def create(self, validated_data):
        return Application_User.objects.create_user(**validated_data)