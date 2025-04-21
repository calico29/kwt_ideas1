from django import template
from ..models import Application

register = template.Library()

@register.simple_tag
def get_unread_count(application, user, chat_type):
    return application.get_unread_count_for_chat(user, chat_type)