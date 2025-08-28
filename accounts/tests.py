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

    def test_update_user_profile(self):
        """Test updating user profile"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        update_data = {'full_name': 'Updated Name'}
        response = self.client.patch(self.profile_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.full_name, 'Updated Name')


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

    @patch('accounts.utils.send_password_reset_email')
    def test_password_reset_request_success(self, mock_send_email):
        """Test successful password reset request"""
        mock_send_email.return_value = True
        data = {'email': self.user_data['email']}
        response = self.client.post(self.reset_request_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        mock_send_email.assert_called_once()

    def test_password_reset_request_nonexistent_email(self):
        """Test password reset request with nonexistent email"""
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
        # Generate and store token
        token = generate_reset_token()
        store_reset_token(self.user_data['email'], token)

        data = {
            'token': token,
            'new_password': 'newpassword123',
            'new_password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify password was changed
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

        # Test uniqueness
        token2 = generate_reset_token()
        self.assertNotEqual(token, token2)

    def test_store_and_verify_reset_token(self):
        """Test storing and verifying reset token"""
        email = 'test@example.com'
        token = generate_reset_token()

        # Store token
        result = store_reset_token(email, token)
        self.assertTrue(result)

        # Verify token
        retrieved_email = verify_reset_token(token)
        self.assertEqual(retrieved_email, email)

    def test_verify_invalid_reset_token(self):
        """Test verifying invalid reset token"""
        result = verify_reset_token('invalid-token')
        self.assertIsNone(result)

    def test_invalidate_reset_token(self):
        """Test invalidating reset token"""
        email = 'test@example.com'
        token = generate_reset_token()

        # Store and verify token exists
        store_reset_token(email, token)
        self.assertEqual(verify_reset_token(token), email)

        # Invalidate token
        result = invalidate_reset_token(token)
        self.assertTrue(result)

        # Verify token is invalidated
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
        self.token_verify_url = reverse('accounts:token_verify')

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

    def test_token_verify_valid(self):
        """Test JWT token verification with valid token"""
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        data = {'token': access_token}
        response = self.client.post(self.token_verify_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_token_verify_invalid(self):
        """Test JWT token verification with invalid token"""
        data = {'token': 'invalid-token'}
        response = self.client.post(self.token_verify_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class RateLimitingTest(APITestCase):
    """Test cases for rate limiting"""

    def setUp(self):
        self.login_url = reverse('accounts:login')
        self.register_url = reverse('accounts:register')
        self.reset_request_url = reverse('accounts:password_reset_request')

    def test_login_rate_limiting(self):
        """Test rate limiting on login endpoint"""
        login_data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }

        # Make multiple requests to trigger rate limiting
        for i in range(12):  # Exceeds 10/m limit
            response = self.client.post(self.login_url, login_data)
            if i < 10:
                self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST])
            else:
                # Should be rate limited after 10 requests
                self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def tearDown(self):
        # Clear rate limiting cache
        cache.clear()
