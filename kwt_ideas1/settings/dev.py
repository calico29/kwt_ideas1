from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-qvc#@luoy3sms-kk%9%2m*ma9f1qkmany72m51cr+o7zfkv3mf"

# SECURITY WARNING: define the correct hosts in production!
ALLOWED_HOSTS = ["*"]




try:
    from .local import *
except ImportError:
    pass
