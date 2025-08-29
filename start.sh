#!/bin/bash

set -e

echo "Starting production deployment..."

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Creating superuser if environment variables are set..."
if [ ! -z "$ADMIN_EMAIL" ] && [ ! -z "$ADMIN_PASSWORD" ]; then
    python -c "
import os
import django
from django.contrib.auth import get_user_model

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_service.settings')
django.setup()

User = get_user_model()

admin_email = os.environ.get('ADMIN_EMAIL')
admin_password = os.environ.get('ADMIN_PASSWORD')

if not User.objects.filter(email=admin_email).exists():
    User.objects.create_superuser(
        email=admin_email,
        full_name='Admin User',
        password=admin_password
    )
    print(f'Superuser created: {admin_email}')
else:
    print(f'Superuser already exists: {admin_email}')
"
fi

echo "Starting Gunicorn server..."
exec gunicorn --bind 0.0.0.0:8000 auth_service.wsgi:application
