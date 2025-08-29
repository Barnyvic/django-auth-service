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
from .utils import (
    generate_reset_token,
    store_reset_token,
    verify_reset_token,
    invalidate_reset_token,
    generate_verification_token,
    store_verification_token,
    verify_verification_token,
    invalidate_verification_token,
    is_account_locked,
    lock_account,
    reset_login_attempts,
    get_client_ip
)
from .email_service import send_verification_email, send_welcome_email, send_password_reset_email

User = get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


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
            user = serializer.save()
            tokens = get_tokens_for_user(user)
            user_data = UserSerializer(user).data

            verification_token = generate_verification_token()
            store_verification_token(user.email, verification_token)
            send_verification_email(user, verification_token, request)

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
        operation_description="Login user and get JWT tokens",
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
            400: "Bad Request",
            401: "Unauthorized"
        }
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        if email:
            try:
                user = User.objects.get(email=email)
                if is_account_locked(user):
                    return Response({
                        'message': 'Account is temporarily locked due to multiple failed login attempts. Please try again later or reset your password.'
                    }, status=status.HTTP_423_LOCKED)
            except User.DoesNotExist:
                pass

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']

            reset_login_attempts(user)

            tokens = get_tokens_for_user(user)
            user_data = UserSerializer(user).data

            return Response({
                'message': 'Login successful',
                'user': user_data,
                'tokens': tokens
            }, status=status.HTTP_200_OK)
        else:
            if email:
                try:
                    user = User.objects.get(email=email)
                    lock_account(user)

                    if user.failed_login_attempts >= 3:
                        return Response({
                            'message': 'Account locked due to multiple failed login attempts. Please reset your password or try again later.'
                        }, status=status.HTTP_423_LOCKED)
                    else:
                        remaining_attempts = 3 - user.failed_login_attempts
                        return Response({
                            'message': f'Invalid credentials. {remaining_attempts} attempts remaining before account lock.',
                            'attempts_remaining': remaining_attempts
                        }, status=status.HTTP_400_BAD_REQUEST)
                except User.DoesNotExist:
                    pass

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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

            try:
                user = User.objects.get(email=email)
                token = generate_reset_token()

                if store_reset_token(email, token):
                    if send_password_reset_email(user, token, request):
                        return Response({
                            'message': 'Password reset email sent successfully'
                        }, status=status.HTTP_200_OK)
                    else:
                        return Response({
                            'message': 'Failed to send email. Please try again.'
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    return Response({
                        'message': 'Failed to process request. Please try again.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            except User.DoesNotExist:
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

            email = verify_reset_token(token)
            if not email:
                return Response({
                    'message': 'Invalid or expired token'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(email=email)
                user.set_password(new_password)
                reset_login_attempts(user)
                user.save()

                invalidate_reset_token(token)

                return Response({
                    'message': 'Password reset successful. Account unlocked.'
                }, status=status.HTTP_200_OK)

            except User.DoesNotExist:
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

            email = verify_verification_token(token)
            if not email:
                return Response({
                    'message': 'Invalid or expired verification token'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(email=email)
                if user.is_verified:
                    return Response({
                        'message': 'Email is already verified'
                    }, status=status.HTTP_200_OK)

                user.is_verified = True
                user.save()

                invalidate_verification_token(token)
                send_welcome_email(user)

                return Response({
                    'message': 'Email verified successfully! Welcome email sent.'
                }, status=status.HTTP_200_OK)

            except User.DoesNotExist:
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

            try:
                user = User.objects.get(email=email)
                if user.is_verified:
                    return Response({
                        'message': 'Email is already verified'
                    }, status=status.HTTP_200_OK)

                verification_token = generate_verification_token()
                store_verification_token(user.email, verification_token)
                send_verification_email(user, verification_token, request)

                return Response({
                    'message': 'Verification email sent successfully'
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
