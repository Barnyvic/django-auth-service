from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch
import json

from .utils import (
    generate_reset_token,
    store_reset_token,
    verify_reset_token,
    invalidate_reset_token
)

User = get_user_model()


class UserModelTest(TestCase):
    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }

    def test_create_user(self):
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data['email'])
        self.assertEqual(user.full_name, self.user_data['full_name'])
        self.assertTrue(user.check_password(self.user_data['password']))
        self.assertFalse(user.is_verified)
        self.assertTrue(user.is_active)

    def test_create_superuser(self):
        user = User.objects.create_superuser(**self.user_data)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_user_string_representation(self):
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(str(user), self.user_data['email'])

    def test_get_full_name(self):
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.get_full_name, self.user_data['full_name'])

    def test_get_short_name(self):
        user = User.objects.create_user(**self.user_data)
        expected_short_name = self.user_data['full_name'].split(' ')[0]
        self.assertEqual(user.get_short_name, expected_short_name)


class UserRegistrationTest(APITestCase):
    """Test cases for user registration"""

    def setUp(self):
        self.register_url = reverse('accounts:register')
        self.valid_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123',
            'password_confirm': 'testpassword123'
        }

    def test_user_registration_success(self):
        """Test successful user registration"""
        response = self.client.post(self.register_url, self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
        self.assertTrue(User.objects.filter(email=self.valid_data['email']).exists())

    def test_user_registration_duplicate_email(self):
        """Test registration with duplicate email"""
        User.objects.create_user(
            email=self.valid_data['email'],
            full_name='Existing User',
            password='password123'
        )
        response = self.client.post(self.register_url, self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_registration_password_mismatch(self):
        """Test registration with password mismatch"""
        data = self.valid_data.copy()
        data['password_confirm'] = 'differentpassword'
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_registration_weak_password(self):
        """Test registration with weak password"""
        data = self.valid_data.copy()
        data['password'] = '123'
        data['password_confirm'] = '123'
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_registration_invalid_email(self):
        """Test registration with invalid email"""
        data = self.valid_data.copy()
        data['email'] = 'invalid-email'
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserLoginTest(APITestCase):
    """Test cases for user login"""

    def setUp(self):
        self.login_url = reverse('accounts:login')
        self.user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.user.is_verified = True
        self.user.save()

    def test_user_login_success(self):
        """Test successful user login"""
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
        self.assertIn('access', response.data['tokens'])
        self.assertIn('refresh', response.data['tokens'])

    def test_user_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            'email': self.user_data['email'],
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_login_nonexistent_user(self):
        """Test login with nonexistent user"""
        login_data = {
            'email': 'nonexistent@example.com',
            'password': 'password123'
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_login_inactive_user(self):
        """Test login with inactive user"""
        self.user.is_active = False
        self.user.save()
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserProfileTest(APITestCase):
    """Test cases for user profile"""

    def setUp(self):
        self.profile_url = reverse('accounts:profile')
        self.user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)

    def test_get_user_profile_authenticated(self):
        """Test getting user profile when authenticated"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user_data['email'])
        self.assertEqual(response.data['full_name'], self.user_data['full_name'])

    def test_get_user_profile_unauthenticated(self):
        """Test getting user profile when unauthenticated"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)




class PasswordResetTest(APITestCase):
    """Test cases for password reset functionality"""

    def setUp(self):
        self.reset_request_url = reverse('accounts:password_reset_request')
        self.reset_confirm_url = reverse('accounts:password_reset_confirm')
        self.user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }
        self.user = User.objects.create_user(**self.user_data)
        cache.clear()  # Clear cache before each test

    @patch('accounts.email_service.send_password_reset_email')
    def test_password_reset_request_success(self, mock_send_email):
        from django.conf import settings

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        mock_send_email.return_value = True
        data = {'email': self.user_data['email']}
        response = self.client.post(self.reset_request_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        mock_send_email.assert_called_once()

    def test_password_reset_request_nonexistent_email(self):
        """Test password reset request with nonexistent email"""
        from django.conf import settings

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.reset_request_url, data)
        # Should return success for security reasons
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_reset_request_invalid_email(self):
        """Test password reset request with invalid email format"""
        data = {'email': 'invalid-email'}
        response = self.client.post(self.reset_request_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_confirm_success(self):
        """Test successful password reset confirmation"""
        from django.conf import settings

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        token = generate_reset_token()
        store_reset_token(self.user_data['email'], token)

        data = {
            'token': token,
            'new_password': 'newpassword123',
            'new_password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))

    def test_password_reset_confirm_invalid_token(self):
        """Test password reset confirmation with invalid token"""
        data = {
            'token': 'invalid-token',
            'new_password': 'newpassword123',
            'new_password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_confirm_password_mismatch(self):
        """Test password reset confirmation with password mismatch"""
        token = generate_reset_token()
        store_reset_token(self.user_data['email'], token)

        data = {
            'token': token,
            'new_password': 'newpassword123',
            'new_password_confirm': 'differentpassword'
        }
        response = self.client.post(self.reset_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_confirm_weak_password(self):
        """Test password reset confirmation with weak password"""
        token = generate_reset_token()
        store_reset_token(self.user_data['email'], token)

        data = {
            'token': token,
            'new_password': '123',
            'new_password_confirm': '123'
        }
        response = self.client.post(self.reset_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UtilityFunctionsTest(TestCase):
    """Test cases for utility functions"""

    def setUp(self):
        cache.clear()

    def test_generate_reset_token(self):
        """Test reset token generation"""
        token = generate_reset_token()
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 32)

        token2 = generate_reset_token()
        self.assertNotEqual(token, token2)

    def test_store_and_verify_reset_token(self):
        """Test storing and verifying reset token"""
        from django.conf import settings

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        email = 'test@example.com'
        token = generate_reset_token()

        result = store_reset_token(email, token)
        self.assertTrue(result)

        retrieved_email = verify_reset_token(token)
        self.assertEqual(retrieved_email, email)

    def test_verify_invalid_reset_token(self):
        """Test verifying invalid reset token"""
        result = verify_reset_token('invalid-token')
        self.assertIsNone(result)

    def test_invalidate_reset_token(self):
        """Test invalidating reset token"""
        from django.conf import settings

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        email = 'test@example.com'
        token = generate_reset_token()

        store_reset_token(email, token)
        self.assertEqual(verify_reset_token(token), email)

        result = invalidate_reset_token(token)
        self.assertTrue(result)

        self.assertIsNone(verify_reset_token(token))


class JWTTokenTest(APITestCase):
    """Test cases for JWT token functionality"""

    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.token_refresh_url = reverse('accounts:token_refresh')


    def test_token_refresh(self):
        """Test JWT token refresh"""
        refresh = RefreshToken.for_user(self.user)
        data = {'refresh': str(refresh)}
        response = self.client.post(self.token_refresh_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_token_refresh_invalid(self):
        """Test JWT token refresh with invalid token"""
        data = {'refresh': 'invalid-token'}
        response = self.client.post(self.token_refresh_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)




class RateLimitingTest(APITestCase):
    """Test cases for rate limiting"""

    def setUp(self):
        self.login_url = reverse('accounts:login')
        self.register_url = reverse('accounts:register')
        self.reset_request_url = reverse('accounts:password_reset_request')

    def test_login_rate_limiting(self):
        """Test rate limiting on login endpoint"""
        from django.conf import settings

        if (getattr(settings, 'RATELIMIT_ENABLE', True) is False or
            'dummy' in settings.CACHES['default']['BACKEND'].lower()):
            self.skipTest("Skipping rate limiting test when rate limiting is disabled or using dummy cache")

        login_data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }

        for i in range(12):
            response = self.client.post(self.login_url, login_data)
            if i < 10:
                self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST])
            else:
                self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def tearDown(self):
        cache.clear()


class EmailVerificationTest(APITestCase):
    def setUp(self):
        self.verify_url = reverse('accounts:verify_email')
        self.resend_url = reverse('accounts:resend_verification')
        self.user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }
        self.user = User.objects.create_user(**self.user_data)
        cache.clear()

    def test_email_verification_success(self):
        from django.conf import settings
        from accounts.utils import generate_verification_token, store_verification_token

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        token = generate_verification_token()
        store_verification_token(self.user.email, token)

        data = {'token': token}
        response = self.client.post(self.verify_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('verified successfully', response.data['message'])

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)

    def test_email_verification_invalid_token(self):
        data = {'token': 'invalid-token'}
        response = self.client.post(self.verify_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_email_verification_already_verified(self):
        from django.conf import settings
        from accounts.utils import generate_verification_token, store_verification_token

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        self.user.is_verified = True
        self.user.save()

        token = generate_verification_token()
        store_verification_token(self.user.email, token)

        data = {'token': token}
        response = self.client.post(self.verify_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('already verified', response.data['message'])

    def test_resend_verification_success(self):
        data = {'email': self.user.email}
        response = self.client.post(self.resend_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('sent successfully', response.data['message'])

    def test_resend_verification_already_verified(self):
        self.user.is_verified = True
        self.user.save()

        data = {'email': self.user.email}
        response = self.client.post(self.resend_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('already verified', response.data['message'])




class AccountLockoutTest(APITestCase):
    def setUp(self):
        self.login_url = reverse('accounts:login')
        self.user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.user.is_verified = True
        self.user.save()

    def test_login_blocked_for_unverified_user(self):
        self.user.is_verified = False
        self.user.save()

        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('verify your email', response.data['message'])
        self.assertFalse(response.data['email_verified'])

    def test_failed_login_attempts_tracking(self):
        login_data = {
            'email': self.user_data['email'],
            'password': 'wrongpassword'
        }

        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('attempts remaining', response.data['message'])
        self.assertEqual(response.data['attempts_remaining'], 2)

        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)

    def test_account_lockout_after_three_attempts(self):
        login_data = {
            'email': self.user_data['email'],
            'password': 'wrongpassword'
        }

        for i in range(3):
            response = self.client.post(self.login_url, login_data)

        self.assertEqual(response.status_code, status.HTTP_423_LOCKED)
        self.assertIn('Account locked', response.data['message'])

        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 3)
        self.assertIsNotNone(self.user.account_locked_until)

    def test_successful_login_resets_attempts(self):
        self.user.failed_login_attempts = 2
        self.user.save()

        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_unverified_correct_credentials_no_failed_attempt(self):
        self.user.is_verified = False
        self.user.save()

        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)


class VerificationUtilityTest(TestCase):
    def setUp(self):
        cache.clear()

    def test_generate_verification_token(self):
        from accounts.utils import generate_verification_token
        token = generate_verification_token()
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 32)

        token2 = generate_verification_token()
        self.assertNotEqual(token, token2)

    def test_store_and_verify_verification_token(self):
        from django.conf import settings
        from accounts.utils import generate_verification_token, store_verification_token, verify_verification_token

        if 'dummy' in settings.CACHES['default']['BACKEND'].lower():
            self.skipTest("Skipping cache-dependent test with dummy cache")

        email = 'test@example.com'
        token = generate_verification_token()

        result = store_verification_token(email, token)
        self.assertTrue(result)

        retrieved_email = verify_verification_token(token)
        self.assertEqual(retrieved_email, email)

    def test_account_locking_utilities(self):
        from accounts.utils import is_account_locked, lock_account, reset_login_attempts
        user_data = {
            'email': 'test@example.com',
            'full_name': 'Test User',
            'password': 'testpassword123'
        }
        user = User.objects.create_user(**user_data)

        self.assertFalse(is_account_locked(user))

        lock_account(user)
        self.assertEqual(user.failed_login_attempts, 1)

        for i in range(2):
            lock_account(user)

        self.assertEqual(user.failed_login_attempts, 3)
        self.assertTrue(is_account_locked(user))

        reset_login_attempts(user)
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertFalse(is_account_locked(user))


class HealthCheckTest(TestCase):
    def setUp(self):
        self.health_url = '/health/'

    def test_health_check_endpoint(self):
        """Test health check endpoint returns proper response"""
        response = self.client.get(self.health_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = response.json()
        self.assertIn('status', data)
        self.assertIn('timestamp', data)
        self.assertIn('version', data)
        self.assertIn('services', data)

        # Check that services are included
        self.assertIn('database', data['services'])
        self.assertIn('redis', data['services'])

        # Version should be v1
        self.assertEqual(data['version'], 'v1')
