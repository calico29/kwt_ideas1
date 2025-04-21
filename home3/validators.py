# home/validators.py
from django.core.exceptions import ValidationError

def validate_file_size(value):
    filesize = value.size
    if filesize > 128 * 1024 * 1024:  # 128 MB
        raise ValidationError("Максимальный размер файла 128 МБ.")