from .models import ChatMessage

def unread_messages(request):
    if request.user.is_authenticated:
        unread_count = ChatMessage.objects.filter(
            application__author=request.user,
            read=False
        ).exclude(
            sender=request.user
        ).count()
        return {'unread_messages_count': unread_count}
    return {}