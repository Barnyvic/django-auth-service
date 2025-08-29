import secrets
import string
from django.core.cache import cache
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags


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





def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
