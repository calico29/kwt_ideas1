from wagtail import hooks
from django.contrib.auth.models import Group, Permission
from wagtail.admin.viewsets.model import ModelViewSet
from wagtail.admin.ui.tables import TitleColumn, UpdatedAtColumn
from django.utils.translation import gettext_lazy as _
from .models import ApplicationPage
from django.db.utils import IntegrityError

class ApplicationAdminViewSet(ModelViewSet):
    model = ApplicationPage
    menu_label = _("Заявки")  # Название в меню
    menu_icon = "doc-full-inverse"  # Иконка
    add_to_admin_menu = True  # Добавить в админку

    # Указываем, какие поля можно редактировать в форме
    form_fields = ["title", "description"]

    # Колонки, отображаемые в списке заявок
    list_display = [TitleColumn("title"), UpdatedAtColumn()]

@hooks.register("register_admin_viewset")
def register_application_admin_viewset():
    return ApplicationAdminViewSet()
@hooks.register("after_create_user")
def assign_user_group(request, user):
    """По умолчанию назначаем пользователя в группу 'Авторы'."""
    group, created = Group.objects.get_or_create(name="Авторы")
    user.groups.add(group)