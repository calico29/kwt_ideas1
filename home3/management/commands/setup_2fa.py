from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_email.models import EmailDevice

class Command(BaseCommand):
    help = 'Setup 2FA for users'

    def handle(self, *args, **options):
        User = get_user_model()
        for user in User.objects.all():
            device, created = EmailDevice.objects.get_or_create(
                user=user,
                name='Email',
                confirmed=True
            )
            if created:
                self.stdout.write(f'Created 2FA device for {user.email}')