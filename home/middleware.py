from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from django.urls import reverse
from django_otp.plugins.otp_email.models import EmailDevice
from django.shortcuts import redirect  
import hashlib  # Добавьте этот импорт
import json  # Для обработки User-Agent
import hashlib
from django.urls import reverse
from django_otp.plugins.otp_email.models import EmailDevice
from django.shortcuts import redirect
import logging

logger = logging.getLogger("auth")

class PasswordChangeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Сброс сессии пароля при любом другом запросе
        if 'password_change' in request.session and not request.path == reverse('change_password'):
            del request.session['password_change']
        return self.get_response(request)
class EmailConfirmationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and not request.user.email_confirmed:
            # Перенаправляем на страницу подтверждения, если email не подтвержден
            return redirect('email_verification_required')
        return self.get_response(request)
from django_otp.middleware import OTPMiddleware

class RememberDeviceMiddleware(OTPMiddleware):
    def process_request(self, request):
        if request.user.is_authenticated and request.session.get('remember_device'):
            request.user.otp_device = None
        return super().process_request(request)

class TwoFactorAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        exempt_paths = [
            reverse('two-factor-authenticate'),
            reverse('logout'),
            reverse('account_login'),
            '/static/',
            '/media/',
            '/accounts/',
        ]
        
        current_path = request.path_info
        device_hash = self.get_device_hash(request)
        
        logger.debug(f"""
            Session Check:
            - Path: {current_path}
            - Remember Device: {request.session.get('remember_device')}
            - Device Verified: {request.session.get(f'2fa_verified_{device_hash}')}
            - Session Expiry: {request.session.get_expiry_date()}
        """)

        if any(current_path.startswith(path) for path in exempt_paths):
            return self.get_response(request)
            
        if request.user.is_authenticated:
            if EmailDevice.objects.filter(user=request.user).exists():
                remember_device = request.session.get('remember_device', False)
                verified = request.session.get(f'2fa_verified_{device_hash}', False)
                
                if remember_device and verified:
                    logger.debug("Device is remembered and verified")
                    return self.get_response(request)
                    
                if not verified:
                    logger.debug("Redirecting to 2FA - not verified")
                    return redirect('two-factor-authenticate')
        
        return self.get_response(request)

    @staticmethod
    def get_device_hash(request):
        stable_attributes = [
            request.META.get('HTTP_USER_AGENT', '')[:256],
            request.META.get('REMOTE_ADDR', '')[:64],
            request.META.get('HTTP_ACCEPT_LANGUAGE', '')[:10]
        ]
        return hashlib.sha256(
            "|".join(stable_attributes).encode()
        ).hexdigest()[:64]