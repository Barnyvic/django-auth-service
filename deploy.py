#!/usr/bin/env python
"""
Production deployment script for Django Auth Service
Handles database migrations, static files, and other deployment tasks
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_command(command, description):
    logger.info(f"Running: {description}")
    logger.info(f"Command: {command}")
    
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            capture_output=True, 
            text=True
        )
        logger.info(f"✅ {description} completed successfully")
        if result.stdout:
            logger.info(f"Output: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ {description} failed")
        logger.error(f"Error: {e.stderr}")
        return False

def check_environment():
    logger.info("🔍 Checking environment variables...")
    
    required_vars = [
        'SECRET_KEY',
        'DATABASE_URL',
        'REDIS_URL',
        'BREVO_API_KEY',
        'FROM_EMAIL'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"Missing environment variables: {', '.join(missing_vars)}")
        return False
    
    logger.info("All required environment variables are set")
    return True

def run_migrations():
    """Run database migrations"""
    logger.info("🗄️ Running database migrations...")
    
    commands = [
        ("python manage.py makemigrations", "Generate migrations"),
        ("python manage.py migrate", "Apply migrations"),
    ]
    
    for command, description in commands:
        if not run_command(command, description):
            return False
    
    return True

def collect_static_files():
    """Collect static files for production"""
    logger.info("📁 Collecting static files...")
    return run_command(
        "python manage.py collectstatic --noinput", 
        "Collect static files"
    )

def create_superuser():
    """Create superuser if it doesn't exist"""
    logger.info("👤 Creating superuser...")
    
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
    
    create_superuser_script = f"""
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_service.settings')
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

if not User.objects.filter(email='{admin_email}').exists():
    User.objects.create_superuser(
        email='{admin_email}',
        full_name='Admin User',
        password='{admin_password}'
    )
    print('Superuser created successfully')
else:
    print('Superuser already exists')
"""
    
    with open('create_superuser.py', 'w') as f:
        f.write(create_superuser_script)
    
    result = run_command("python create_superuser.py", "Create superuser")
    
    # Clean up temporary file
    if os.path.exists('create_superuser.py'):
        os.remove('create_superuser.py')
    
    return result

def check_database_connection():
    """Test database connection"""
    logger.info("🔗 Testing database connection...")
    return run_command(
        "python manage.py check --database default", 
        "Check database connection"
    )

def run_tests():
    """Run tests to ensure everything works"""
    logger.info("🧪 Running tests...")
    return run_command(
        "python manage.py test --verbosity=1", 
        "Run tests"
    )

def main():
    """Main deployment function"""
    logger.info("🚀 Starting production deployment...")
    
    # Change to project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    deployment_steps = [
        ("Environment Check", check_environment),
        ("Database Connection", check_database_connection),
        ("Database Migrations", run_migrations),
        ("Static Files", collect_static_files),
        ("Superuser Creation", create_superuser),
    ]
    
    # Add tests only if not in production
    if os.getenv('RUN_TESTS', 'false').lower() == 'true':
        deployment_steps.append(("Tests", run_tests))
    
    failed_steps = []
    
    for step_name, step_function in deployment_steps:
        logger.info(f"\n{'='*50}")
        logger.info(f"📋 Step: {step_name}")
        logger.info(f"{'='*50}")
        
        if not step_function():
            failed_steps.append(step_name)
            logger.error(f"❌ Step '{step_name}' failed")
            
            # Continue with other steps unless it's a critical failure
            if step_name in ["Environment Check", "Database Connection"]:
                logger.error("💥 Critical step failed. Stopping deployment.")
                sys.exit(1)
        else:
            logger.info(f"✅ Step '{step_name}' completed successfully")
    
    logger.info(f"\n{'='*50}")
    logger.info("🎯 DEPLOYMENT SUMMARY")
    logger.info(f"{'='*50}")
    
    if failed_steps:
        logger.warning(f"⚠️ Some steps failed: {', '.join(failed_steps)}")
        logger.warning("Please review the logs and fix any issues.")
        sys.exit(1)
    else:
        logger.info("🎉 All deployment steps completed successfully!")
        logger.info("🚀 Your Django Auth Service is ready for production!")

if __name__ == "__main__":
    main()
