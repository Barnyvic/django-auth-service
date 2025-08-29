from typing import Any, Dict, Optional, Tuple, Union, TYPE_CHECKING
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import (
    generate_reset_token, store_reset_token, verify_reset_token, invalidate_reset_token,
    generate_verification_token, store_verification_token, verify_verification_token, invalidate_verification_token,
    is_account_locked, lock_account, reset_login_attempts
)
from .email_service import send_verification_email, send_welcome_email, send_password_reset_email

if TYPE_CHECKING:
    from django.http import HttpRequest
    from .models import User as UserType

User = get_user_model()


class AuthenticationService:
    @staticmethod
    def generate_tokens(user: 'UserType') -> Dict[str, str]:
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    @staticmethod
    def register_user(
        email: str,
        full_name: str,
        password: str,
        request: Optional['HttpRequest'] = None
    ) -> Tuple['UserType', Dict[str, str]]:
        user = User.objects.create_user(
            email=email,
            full_name=full_name,
            password=password
        )

        verification_token = generate_verification_token()
        store_verification_token(user.email, verification_token)
        send_verification_email(user, verification_token, request)

        tokens = AuthenticationService.generate_tokens(user)
        return user, tokens

    @staticmethod
    def authenticate_user(
        email: str,
        password: str,
        request: Optional['HttpRequest'] = None
    ) -> Tuple[Optional['UserType'], str, Union[None, Dict[str, str], int, str]]:
        try:
            user = User.objects.get(email=email)

            if is_account_locked(user):
                return None, 'ACCOUNT_LOCKED', None

            auth_user = authenticate(request=request, username=email, password=password)

            if not auth_user:
                lock_account(user)
                remaining_attempts = 3 - user.failed_login_attempts

                if user.failed_login_attempts >= 3:
                    return None, 'ACCOUNT_LOCKED_NOW', None
                else:
                    return None, 'INVALID_CREDENTIALS', remaining_attempts

            if not auth_user.is_verified:
                return None, 'EMAIL_NOT_VERIFIED', auth_user.email

            reset_login_attempts(user)
            tokens = AuthenticationService.generate_tokens(auth_user)
            return auth_user, 'SUCCESS', tokens

        except User.DoesNotExist:
            return None, 'USER_NOT_FOUND', None


class EmailVerificationService:
    @staticmethod
    def verify_email(token: str) -> Tuple[Optional['UserType'], str]:
        email = verify_verification_token(token)
        if not email:
            return None, 'INVALID_TOKEN'

        try:
            user = User.objects.get(email=email)
            if user.is_verified:
                return user, 'ALREADY_VERIFIED'

            user.is_verified = True
            user.save()

            invalidate_verification_token(token)
            send_welcome_email(user)

            return user, 'SUCCESS'

        except User.DoesNotExist:
            return None, 'USER_NOT_FOUND'

    @staticmethod
    def resend_verification(
        email: str,
        request: Optional['HttpRequest'] = None
    ) -> Tuple[Optional['UserType'], str]:
        try:
            user = User.objects.get(email=email)
            if user.is_verified:
                return user, 'ALREADY_VERIFIED'

            verification_token = generate_verification_token()
            store_verification_token(user.email, verification_token)
            send_verification_email(user, verification_token, request)

            return user, 'SUCCESS'

        except User.DoesNotExist:
            return None, 'USER_NOT_FOUND'

    @staticmethod
    def check_verification_status(email: str) -> Tuple[Optional['UserType'], str]:
        try:
            user = User.objects.get(email=email)
            return user, 'SUCCESS'
        except User.DoesNotExist:
            return None, 'USER_NOT_FOUND'


class PasswordResetService:
    @staticmethod
    def request_password_reset(
        email: str,
        request: Optional['HttpRequest'] = None
    ) -> Tuple[Optional['UserType'], str]:
        try:
            user = User.objects.get(email=email)
            token = generate_reset_token()

            if store_reset_token(email, token):
                if send_password_reset_email(user, token, request):
                    return user, 'SUCCESS'
                else:
                    return user, 'EMAIL_FAILED'
            else:
                return user, 'TOKEN_FAILED'

        except User.DoesNotExist:
            return None, 'USER_NOT_FOUND'

    @staticmethod
    def confirm_password_reset(
        token: str,
        new_password: str
    ) -> Tuple[Optional['UserType'], str]:
        email = verify_reset_token(token)
        if not email:
            return None, 'INVALID_TOKEN'

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            reset_login_attempts(user)
            user.save()

            invalidate_reset_token(token)

            return user, 'SUCCESS'

        except User.DoesNotExist:
            return None, 'USER_NOT_FOUND'


class UserService:
    @staticmethod
    def get_user_profile(user: 'UserType') -> 'UserType':
        return user

    @staticmethod
    def update_user_profile(user: 'UserType', **kwargs: Any) -> 'UserType':
        for field, value in kwargs.items():
            if hasattr(user, field) and field in ['full_name']:
                setattr(user, field, value)
        user.save()
        return user
