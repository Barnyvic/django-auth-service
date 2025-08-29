from typing import Optional, TYPE_CHECKING
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from django.conf import settings
from decouple import config

if TYPE_CHECKING:
    from django.http import HttpRequest
    from .models import User


class BrevoEmailService:
    def __init__(self) -> None:
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = config('BREVO_API_KEY')
        self.api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
        self.from_email: str = config('FROM_EMAIL', default='noreply@authservice.com')
        self.from_name: str = config('FROM_NAME', default='Auth Service')

    def send_verification_email(
        self,
        user: 'User',
        token: str,
        request: Optional['HttpRequest'] = None
    ) -> bool:
        try:
            if request:
                domain = request.get_host()
                protocol = 'https' if request.is_secure() else 'http'
                verify_url = f"{protocol}://{domain}/verify-email?token={token}"
            else:
                verify_url = f"http://localhost:8000/verify-email?token={token}"

            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": user.email, "name": user.full_name}],
                sender={"name": self.from_name, "email": self.from_email},
                subject="Verify Your Email - Auth Service",
                html_content=f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #28a745;">Verify Your Email Address 📧</h2>

                        <p>Hello <strong>{user.full_name}</strong>,</p>

                        <p>Thank you for registering with Auth Service! To complete your registration and activate your account, please verify your email address.</p>

                        <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #bee5eb;">
                            <p style="margin: 0;"><strong>⏰ Important:</strong> This verification link will expire in <strong>24 hours</strong>.</p>
                        </div>

                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{verify_url}"
                               style="background-color: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                                Verify My Email
                            </a>
                        </div>

                        <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
                        <p style="background-color: #f8f9fa; padding: 10px; border-radius: 3px; word-break: break-all; font-family: monospace; font-size: 12px;">
                            {verify_url}
                        </p>

                        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                            <p style="margin: 0;"><strong>🔒 Security Note:</strong> If you didn't create this account, please ignore this email.</p>
                        </div>

                        <p>Best regards,<br>
                        <strong>The Auth Service Team</strong></p>

                        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                        <p style="font-size: 12px; color: #6c757d;">
                            This email was sent to {user.email}. This is an automated message, please do not reply.
                        </p>
                    </div>
                </body>
                </html>
                """
            )

            api_response = self.api_instance.send_transac_email(send_smtp_email)
            return True

        except ApiException as e:
            print(f"Exception when calling TransactionalEmailsApi->send_transac_email: {e}")
            return False
        except Exception as e:
            print(f"Failed to send verification email: {e}")
            return False

    def send_welcome_email(self, user):
        try:
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": user.email, "name": user.full_name}],
                sender={"name": self.from_name, "email": self.from_email},
                subject="Welcome to Auth Service! 🎉",
                html_content=f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #2c3e50;">Welcome to Auth Service! 🎉</h2>
                        
                        <p>Hello <strong>{user.full_name}</strong>,</p>
                        
                        <p>Thank you for registering with Auth Service! Your account has been successfully created.</p>
                        
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                            <h3 style="margin-top: 0; color: #495057;">Account Details:</h3>
                            <p><strong>Email:</strong> {user.email}</p>
                            <p><strong>Full Name:</strong> {user.full_name}</p>
                            <p><strong>Registration Date:</strong> {user.created_at.strftime('%B %d, %Y')}</p>
                        </div>
                        
                        <p>You can now use your account to:</p>
                        <ul>
                            <li>Access protected API endpoints</li>
                            <li>Manage your profile</li>
                            <li>Reset your password if needed</li>
                        </ul>
                        
                        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                        
                        <p>Best regards,<br>
                        <strong>The Auth Service Team</strong></p>
                        
                        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                        <p style="font-size: 12px; color: #6c757d;">
                            This email was sent to {user.email}. If you didn't create this account, please ignore this email.
                        </p>
                    </div>
                </body>
                </html>
                """
            )
            
            api_response = self.api_instance.send_transac_email(send_smtp_email)
            return True
            
        except ApiException as e:
            print(f"Exception when calling TransactionalEmailsApi->send_transac_email: {e}")
            return False
        except Exception as e:
            print(f"Failed to send welcome email: {e}")
            return False

    def send_password_reset_email(self, user, token, request=None):
        try:
            if request:
                domain = request.get_host()
                protocol = 'https' if request.is_secure() else 'http'
                reset_url = f"{protocol}://{domain}/reset-password?token={token}"
            else:
                reset_url = f"http://localhost:8000/reset-password?token={token}"

            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": user.email, "name": user.full_name}],
                sender={"name": self.from_name, "email": self.from_email},
                subject="Password Reset Request - Auth Service",
                html_content=f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #e74c3c;">Password Reset Request 🔐</h2>
                        
                        <p>Hello <strong>{user.full_name}</strong>,</p>
                        
                        <p>We received a request to reset your password for your Auth Service account.</p>
                        
                        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                            <p style="margin: 0;"><strong>⚠️ Important:</strong> This link will expire in <strong>10 minutes</strong> for security reasons.</p>
                        </div>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_url}" 
                               style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                                Reset My Password
                            </a>
                        </div>
                        
                        <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
                        <p style="background-color: #f8f9fa; padding: 10px; border-radius: 3px; word-break: break-all; font-family: monospace; font-size: 12px;">
                            {reset_url}
                        </p>
                        
                        <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #bee5eb;">
                            <p style="margin: 0;"><strong>🛡️ Security Note:</strong> If you didn't request this password reset, please ignore this email. Your account remains secure.</p>
                        </div>
                        
                        <p>Best regards,<br>
                        <strong>The Auth Service Team</strong></p>
                        
                        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                        <p style="font-size: 12px; color: #6c757d;">
                            This email was sent to {user.email}. This is an automated message, please do not reply.
                        </p>
                    </div>
                </body>
                </html>
                """
            )
            
            api_response = self.api_instance.send_transac_email(send_smtp_email)
            return True
            
        except ApiException as e:
            print(f"Exception when calling TransactionalEmailsApi->send_transac_email: {e}")
            return False
        except Exception as e:
            print(f"Failed to send password reset email: {e}")
            return False


def send_verification_email(user, token, request=None):
    email_service = BrevoEmailService()
    return email_service.send_verification_email(user, token, request)


def send_welcome_email(user):
    email_service = BrevoEmailService()
    return email_service.send_welcome_email(user)


def send_password_reset_email(user, token, request=None):
    email_service = BrevoEmailService()
    return email_service.send_password_reset_email(user, token, request)
