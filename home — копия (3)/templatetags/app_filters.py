from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    # Добавляем проверку на None
    if dictionary is None:
        return []
    return dictionary.get(key, [])