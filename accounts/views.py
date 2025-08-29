from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenVerifyView as BaseTokenVerifyView
from django.contrib.auth import get_user_model
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer,
    ResendVerificationSerializer
)
from .services import (
    AuthenticationService,
    EmailVerificationService,
    PasswordResetService,
    UserService
)

User = get_user_model()


@method_decorator(ratelimit(key='ip', rate='5/m', method='POST'), name='post')
class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user",
        security=[],
        responses={
            201: openapi.Response(
                description="User created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                        'tokens': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: "Bad Request"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user, tokens = AuthenticationService.register_user(
                email=serializer.validated_data['email'],
                full_name=serializer.validated_data['full_name'],
                password=serializer.validated_data['password'],
                request=request
            )
            user_data = UserSerializer(user).data

            return Response({
                'message': 'User registered successfully. Please check your email to verify your account.',
                'user': user_data,
                'tokens': tokens
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='10/m', method='POST'), name='post')
@method_decorator(never_cache, name='post')
class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Login user and get JWT tokens. Email must be verified to login.",
        security=[],
        responses={
            200: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                        'tokens': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: "Invalid credentials",
            403: "Email not verified",
            423: "Account locked"
        }
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({
                'message': 'Email and password are required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        user, status_code, data = AuthenticationService.authenticate_user(email, password, request)

        if status_code == 'SUCCESS':
            user_data = UserSerializer(user).data
            return Response({
                'message': 'Login successful',
                'user': user_data,
                'tokens': data
            }, status=status.HTTP_200_OK)

        elif status_code == 'ACCOUNT_LOCKED':
            return Response({
                'message': 'Account is temporarily locked due to multiple failed login attempts. Please try again later or reset your password.'
            }, status=status.HTTP_423_LOCKED)

        elif status_code == 'ACCOUNT_LOCKED_NOW':
            return Response({
                'message': 'Account locked due to multiple failed login attempts. Please reset your password or try again later.'
            }, status=status.HTTP_423_LOCKED)

        elif status_code == 'EMAIL_NOT_VERIFIED':
            return Response({
                'message': 'Please verify your email address before logging in. Check your email for verification instructions.',
                'email_verified': False,
                'email': data
            }, status=status.HTTP_403_FORBIDDEN)

        elif status_code == 'INVALID_CREDENTIALS':
            return Response({
                'message': f'Invalid credentials. {data} attempts remaining before account lock.',
                'attempts_remaining': data
            }, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response({
                'message': 'Invalid credentials.'
            }, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    @swagger_auto_schema(
        operation_description="Get user profile",
        security=[{'Bearer': []}],
        responses={200: UserSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Update user profile",
        security=[{'Bearer': []}],
        responses={200: UserSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


@method_decorator(ratelimit(key='ip', rate='3/m', method='POST'), name='post')
class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Request password reset",
        security=[],
        responses={
            200: openapi.Response(
                description="Password reset email sent",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: "Bad Request"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            user, status_code = PasswordResetService.request_password_reset(email, request)

            if status_code == 'SUCCESS':
                return Response({
                    'message': 'Password reset email sent successfully'
                }, status=status.HTTP_200_OK)

            elif status_code == 'EMAIL_FAILED':
                return Response({
                    'message': 'Failed to send email. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            elif status_code == 'TOKEN_FAILED':
                return Response({
                    'message': 'Failed to process request. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            else:
                return Response({
                    'message': 'Password reset email sent successfully'
                }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='5/m', method='POST'), name='post')
class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Confirm password reset with token",
        security=[],
        responses={
            200: openapi.Response(
                description="Password reset successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: "Bad Request"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            user, status_code = PasswordResetService.confirm_password_reset(token, new_password)

            if status_code == 'SUCCESS':
                return Response({
                    'message': 'Password reset successful. Account unlocked.'
                }, status=status.HTTP_200_OK)

            elif status_code == 'INVALID_TOKEN':
                return Response({
                    'message': 'Invalid or expired token'
                }, status=status.HTTP_400_BAD_REQUEST)

            else:
                return Response({
                    'message': 'User not found'
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationView(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Verify email address with token",
        security=[],
        responses={
            200: openapi.Response(
                description="Email verified successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: "Invalid or expired token"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']

            user, status_code = EmailVerificationService.verify_email(token)

            if status_code == 'SUCCESS':
                return Response({
                    'message': 'Email verified successfully! Welcome email sent.'
                }, status=status.HTTP_200_OK)

            elif status_code == 'ALREADY_VERIFIED':
                return Response({
                    'message': 'Email is already verified'
                }, status=status.HTTP_200_OK)

            elif status_code == 'INVALID_TOKEN':
                return Response({
                    'message': 'Invalid or expired verification token'
                }, status=status.HTTP_400_BAD_REQUEST)

            else:
                return Response({
                    'message': 'User not found'
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationView(generics.GenericAPIView):
    serializer_class = ResendVerificationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Resend email verification",
        security=[],
        responses={
            200: openapi.Response(
                description="Verification email sent",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: "Bad Request"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            user, status_code = EmailVerificationService.resend_verification(email, request)

            if status_code == 'SUCCESS':
                return Response({
                    'message': 'Verification email sent successfully'
                }, status=status.HTTP_200_OK)

            elif status_code == 'ALREADY_VERIFIED':
                return Response({
                    'message': 'Email is already verified'
                }, status=status.HTTP_200_OK)

            else:
                return Response({
                    'message': 'If an account with this email exists, a verification email has been sent.'
                }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckVerificationStatusView(generics.GenericAPIView):
    serializer_class = ResendVerificationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Check email verification status",
        security=[],
        responses={
            200: openapi.Response(
                description="Verification status",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                        'is_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: "Bad Request"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)
                return Response({
                    'email': user.email,
                    'is_verified': user.is_verified,
                    'message': 'Email is verified' if user.is_verified else 'Email is not verified'
                }, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({
                    'message': 'User not found'
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TokenVerifyView(BaseTokenVerifyView):
    @swagger_auto_schema(
        operation_description="Verify JWT token validity",
        security=[],
        responses={
            200: openapi.Response(
                description="Token is valid",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'valid': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                    }
                )
            ),
            401: "Token is invalid or expired"
        }
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            return Response({
                'message': 'Token is valid',
                'valid': True
            }, status=status.HTTP_200_OK)
        return response
