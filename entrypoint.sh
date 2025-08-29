#!/bin/bash

set -e

echo "Starting Django application..."

echo "Waiting for database to be ready..."
python -c "
import os
import time
import psycopg2
from urllib.parse import urlparse

def wait_for_db():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url or 'sqlite' in db_url:
        print('Using SQLite or no DATABASE_URL, skipping database wait')
        return
    
    parsed = urlparse(db_url)
    max_retries = 30
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            conn = psycopg2.connect(
                host=parsed.hostname,
                port=parsed.port or 5432,
                user=parsed.username,
                password=parsed.password,
                database=parsed.path[1:]  # Remove leading slash
            )
            conn.close()
            print('Database is ready!')
            return
        except psycopg2.OperationalError:
            retry_count += 1
            print(f'Database not ready, retrying... ({retry_count}/{max_retries})')
            time.sleep(2)
    
    raise Exception('Database connection failed after maximum retries')

wait_for_db()
"

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Creating superuser if needed..."
python -c "
import os
import django
from django.contrib.auth import get_user_model

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_service.settings')
django.setup()

User = get_user_model()

admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')

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

echo "Starting application server..."
exec "$@"
