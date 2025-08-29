from typing import Any, Dict
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User


class UserRegistrationSerializer(serializers.ModelSerializer[User]):
    password: serializers.CharField = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    password_confirm: serializers.CharField = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ('email', 'full_name', 'password', 'password_confirm')

    def validate_email(self, value: str) -> str:
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_password(self, value: str) -> str:
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs

    def create(self, validated_data: Dict[str, Any]) -> User:
        validated_data.pop('password_confirm')
        user = User.objects.create_user(
            email=validated_data['email'],
            full_name=validated_data['full_name'],
            password=validated_data['password']
        )
        return user


class UserLoginSerializer(serializers.Serializer):
    email: serializers.EmailField = serializers.EmailField()
    password: serializers.CharField = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password
            )

            if not user:
                raise serializers.ValidationError(
                    'Unable to log in with provided credentials.',
                    code='authorization'
                )

            if not user.is_active:
                raise serializers.ValidationError(
                    'User account is disabled.',
                    code='authorization'
                )

            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError(
                'Must include "email" and "password".',
                code='authorization'
            )


class UserSerializer(serializers.ModelSerializer[User]):
    class Meta:
        model = User
        fields = ('id', 'email', 'full_name', 'is_verified', 'created_at', 'updated_at')
        read_only_fields = ('id', 'email', 'is_verified', 'created_at', 'updated_at')


class PasswordResetRequestSerializer(serializers.Serializer):
    email: serializers.EmailField = serializers.EmailField()

    def validate_email(self, value: str) -> str:
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    token: serializers.CharField = serializers.CharField()
    new_password: serializers.CharField = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm: serializers.CharField = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate_new_password(self, value: str) -> str:
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    token: serializers.CharField = serializers.CharField()


class ResendVerificationSerializer(serializers.Serializer):
    email: serializers.EmailField = serializers.EmailField()

    def validate_email(self, value: str) -> str:
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value
