from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.conf import settings
import os

User = get_user_model()


class Command(BaseCommand):
    help = 'Setup production environment with migrations and superuser'

    def add_arguments(self, parser):
        parser.add_argument(
            '--create-superuser',
            action='store_true',
            help='Create superuser if it does not exist',
        )
        parser.add_argument(
            '--admin-email',
            type=str,
            default='admin@example.com',
            help='Admin email for superuser',
        )
        parser.add_argument(
            '--admin-password',
            type=str,
            default='admin123',
            help='Admin password for superuser',
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🚀 Setting up production environment...')
        )

        # Run migrations
        self.stdout.write('📋 Running migrations...')
        from django.core.management import call_command
        
        try:
            call_command('migrate', verbosity=1)
            self.stdout.write(
                self.style.SUCCESS('✅ Migrations completed successfully')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Migration failed: {e}')
            )
            return

        # Collect static files
        self.stdout.write('📁 Collecting static files...')
        try:
            call_command('collectstatic', interactive=False, verbosity=1)
            self.stdout.write(
                self.style.SUCCESS('✅ Static files collected successfully')
            )
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'⚠️ Static files collection failed: {e}')
            )

        # Create superuser if requested
        if options['create_superuser']:
            self.stdout.write('👤 Creating superuser...')
            
            admin_email = options['admin_email']
            admin_password = options['admin_password']
            
            if User.objects.filter(email=admin_email).exists():
                self.stdout.write(
                    self.style.WARNING(f'⚠️ Superuser with email {admin_email} already exists')
                )
            else:
                try:
                    user = User.objects.create_superuser(
                        email=admin_email,
                        full_name='Admin User',
                        password=admin_password
                    )
                    user.is_verified = True
                    user.save()
                    
                    self.stdout.write(
                        self.style.SUCCESS(f'✅ Superuser created: {admin_email}')
                    )
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'❌ Superuser creation failed: {e}')
                    )

        self.stdout.write(
            self.style.SUCCESS('🎉 Production setup completed!')
        )
