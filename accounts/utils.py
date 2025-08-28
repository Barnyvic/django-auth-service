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


def send_password_reset_email(user, token, request=None):
    subject = 'Password Reset Request - Auth Service'

    if request:
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
        reset_url = f"{protocol}://{domain}/reset-password?token={token}"
    else:
        reset_url = f"http://localhost:8000/reset-password?token={token}"

    message = f"""
    Hello {user.full_name},

    You have requested to reset your password for your Auth Service account.

    Please click the link below to reset your password:
    {reset_url}

    This link will expire in 10 minutes.

    If you did not request this password reset, please ignore this email.

    Best regards,
    Auth Service Team
    """

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.EMAIL_HOST_USER or 'noreply@authservice.com',
            recipient_list=[user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
