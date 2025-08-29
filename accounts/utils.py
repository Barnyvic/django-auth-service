import secrets
import string
from django.core.cache import cache
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from datetime import timedelta


def generate_reset_token():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))


def store_reset_token(email, token):
    cache_key = f"password_reset:{token}"
    cache.set(cache_key, email, timeout=settings.PASSWORD_RESET_TIMEOUT)
    return True


def verify_reset_token(token):
    cache_key = f"password_reset:{token}"
    email = cache.get(cache_key)
    return email


def invalidate_reset_token(token):
    cache_key = f"password_reset:{token}"
    cache.delete(cache_key)
    return True





def generate_verification_token():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))


def store_verification_token(email, token):
    cache_key = f"email_verification:{token}"
    cache.set(cache_key, email, timeout=86400)  # 24 hours
    return True


def verify_verification_token(token):
    cache_key = f"email_verification:{token}"
    email = cache.get(cache_key)
    return email


def invalidate_verification_token(token):
    cache_key = f"email_verification:{token}"
    cache.delete(cache_key)
    return True


def is_account_locked(user):
    if user.account_locked_until:
        if timezone.now() < user.account_locked_until:
            return True
        else:
            user.account_locked_until = None
            user.failed_login_attempts = 0
            user.save()
            return False
    return False


def lock_account(user):
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= 3:
        user.account_locked_until = timezone.now() + timedelta(minutes=15)  # Lock for 15 minutes
    user.save()


def reset_login_attempts(user):
    user.failed_login_attempts = 0
    user.account_locked_until = None
    user.save()


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
