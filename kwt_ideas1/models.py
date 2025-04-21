from django.db import models
from wagtail.fields import RichTextField
from wagtail.models import Page
from wagtail.admin.panels import FieldPanel
from django.contrib.auth.models import User
from allauth.account.models import EmailAddress



class HomePage(Page):
    intro = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel('intro'),
    ]
    template = "home/home_page.html"
class ApplicationPage(Page):
    subpage_types = []  # Запрещаем вложенные страницы
    description = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel('description'),
    ]
    template = "home/application_page.html"
class ModerationPage(Page):
    subpage_types = []
    instructions = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel('instructions'),
    ]
    template = "home/moderation.html"


class DashboardPage(Page):
    subpage_types = []  # Запрещаем вложенные страницы
    intro = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel('intro'),
    ]
    template = "home/dashboard.html"

class ExpertDashboardPage(Page):
    subpage_types = []  # Запрещаем вложенные страницы
    intro = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel('intro'),
    ]
    template = "home/expert_dashboard.html"