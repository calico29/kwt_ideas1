from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User

class EmailConfirmationBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username, password, **kwargs)
        if user and not user.email_confirmed:
            return None  # Блокируем вход без подтверждения
        return user