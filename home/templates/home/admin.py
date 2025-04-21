from django.contrib import admin
from .models import Application
from django.contrib import admin
from django.apps import apps

EmailAddress = apps.get_model('account', 'EmailAddress')
admin.site.register(EmailAddress)

class ApplicationAdmin(admin.ModelAdmin):
    """Скрываем заявки, если пользователь не модератор"""
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)

        if request.user.groups.filter(name="Авторы").exists():
            return qs.filter(author=request.user)  # Авторы видят только свои заявки

        if request.user.groups.filter(name="Эксперты").exists():
            return qs.filter(expert=request.user)  # Эксперты – только назначенные им заявки

        return qs  # Все остальные видят всё

admin.site.register(Application, ApplicationAdmin)

@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'file', 'uploaded_at', 'is_empty')
    readonly_fields = ('is_empty',)
    actions = ['delete_empty_files']
    
    def is_empty(self, obj):
        return obj.is_empty()
    is_empty.boolean = True
    
    def delete_empty_files(self, request, queryset):
        for obj in queryset.filter(file__size=0):
            obj.delete()
        self.message_user(request, "Пустые файлы удалены")