#!/bin/bash


set -e  # Exit on any error

echo "🚀 Starting Django Auth Service deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "manage.py" ]; then
    print_error "manage.py not found. Please run this script from the Django project root."
    exit 1
fi

print_status "Checking environment variables..."
required_vars=("SECRET_KEY" "DATABASE_URL" "REDIS_URL" "BREVO_API_KEY" "FROM_EMAIL")
missing_vars=()

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        missing_vars+=("$var")
    fi
done

if [ ${#missing_vars[@]} -ne 0 ]; then
    print_error "Missing required environment variables: ${missing_vars[*]}"
    print_error "Please set these variables before running deployment."
    exit 1
fi

print_success "All required environment variables are set"

print_status "Installing Python dependencies..."
pip install -r requirements.txt
print_success "Dependencies installed"

print_status "Testing database connection..."
python manage.py check --database default
print_success "Database connection successful"

print_status "Running database migrations..."
python manage.py makemigrations
python manage.py migrate
print_success "Database migrations completed"

print_status "Collecting static files..."
python manage.py collectstatic --noinput
print_success "Static files collected"

if [ "${CREATE_SUPERUSER:-false}" = "true" ]; then
    print_status "Creating superuser..."
    python -c "
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_service.settings')
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')

if not User.objects.filter(email=admin_email).exists():
    user = User.objects.create_superuser(
        email=admin_email,
        full_name='Admin User',
        password=admin_password
    )
    user.is_verified = True
    user.save()
    print(f'Superuser created: {admin_email}')
else:
    print('Superuser already exists')
"
    print_success "Superuser setup completed"
fi

if [ "${RUN_TESTS:-false}" = "true" ]; then
    print_status "Running tests..."
    python manage.py test --verbosity=1
    print_success "All tests passed"
fi

print_success "Deployment completed successfully!"
print_status "Your Django Auth Service is ready for production!"

# Display useful information
echo ""
echo " Deployment Summary:"
echo " Dependencies installed"
echo " Database migrations applied"
echo " Static files collected"
if [ "${CREATE_SUPERUSER:-false}" = "true" ]; then
    echo " Superuser created"
fi
if [ "${RUN_TESTS:-false}" = "true" ]; then
    echo " Tests passed"
fi

echo ""
echo "Next steps:"
echo "  • Start your web server: gunicorn auth_service.wsgi:application"
echo "  • Access admin panel: /admin/"
echo "  • API documentation: /swagger/"
