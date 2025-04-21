from django.db import models
from wagtail.fields import RichTextField
from wagtail.models import Page
from django.db import models
from wagtail.models import Page
from wagtail.admin.panels import FieldPanel
from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.signing import Signer
from django.conf import settings
import uuid
from django.utils import timezone
from django.template import Library
from django.urls import reverse
register = Library()
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from wagtail.models import Page
from wagtail.fields import RichTextField
from wagtail.admin.panels import FieldPanel

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    phone = models.CharField("Номер телефона", max_length=20, blank=True, null=True)
    middle_name = models.CharField("Отчество", max_length=150, blank=True, null=True)

    def __str__(self):
        return f"Профиль пользователя {self.user.username}"

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    else:
        # Если профиль отсутствует (для старых пользователей) — создаём его
        if not hasattr(instance, 'profile'):
            Profile.objects.create(user=instance)
        else:
            instance.profile.save()
    
class Attachment(models.Model):
    id = models.BigAutoField(primary_key=True)  # Добавляем явное поле ID
    file = models.FileField(upload_to="attachments/")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    def is_empty(self):
        return self.file.size == 0 if self.file else True
    
    def get_protected_url(self):
        if self.is_empty():
            return None
        return reverse('protected_file', kwargs={'file_path': f"attachments/{self.file.name.split('/')[-1]}"})
    
    def clean(self):
        if self.is_empty():
            raise ValidationError("Нельзя сохранять пустой файл")

    def __str__(self):
        return self.file.name


def validate_file_size(value):
    if value.size == 0:
        raise ValidationError("Файл не должен быть пустым")
    if value.size > 20 * 1024 * 1024:  # 20MB
        raise ValidationError("Максимальный размер файла - 20 МБ")

class EmailConfirmation(models.Model):
    id = models.BigAutoField(primary_key=True)  # Добавляем явное поле ID
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    email = models.EmailField()
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.token:
            signer = Signer()
            self.token = signer.sign(self.email)
        super().save(*args, **kwargs)

    def confirm(self):
        self.confirmed_at = timezone.now()
        self.save()
from django.db import models
from django.contrib.auth.models import User

from django.db import models
from django.contrib.auth.models import User
class ApplicationManager(models.Manager):
    def search(self, query):
        qs = self.get_queryset()
        for word in query.lower().split():
            qs = qs.filter(title__icontains=word)
        return qs
class Application(models.Model):
    objects = ApplicationManager()
    id = models.BigAutoField(primary_key=True) 
    INNOVATION_TYPE_CHOICES = [
        ('educational', 'Образовательная'),
        ('scientific', 'Научно-техническая'),
        ('process', 'Процессная'),
        ('proposal', 'Инновационное предложение'),
    ]
    STATUS_CHOICES = [
        ('draft', 'Черновик'),
        ('submitted', 'Отправлена'),
        ('under_review', 'На рассмотрении'),
        ('approved', 'Одобрена'),
        ('rejected', 'Отклонена'),
    ]
    
    # Убедитесь, что поле status использует STATUS_CHOICES
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='submitted'
    )
    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('view_application', kwargs={'application_id': self.id})
    # Общие поля для всех типов инноваций
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    expert = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_expert")
    title = models.CharField(max_length=255, verbose_name="Название инновации")
    phone = models.CharField(max_length=20, verbose_name="Контактный телефон", blank=True, null=True)
    description = models.TextField(verbose_name="Описание")
    innovation_type = models.CharField(max_length=50, choices=INNOVATION_TYPE_CHOICES, verbose_name="Тип заявки")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Образовательная инновация
    authors = models.TextField(blank=True, null=True, verbose_name="Авторы инновации")
    product_type = models.CharField(max_length=255, blank=True, null=True, verbose_name="Тип продукта", choices=[
        ('МООК', 'Массовый открытый онлайн-курс (МООК)'),
        ('ЭУМК', 'Электронный учебно-методический комплекс (ЭУМК)'),
        ('ЭУМК_иностранный', 'ЭУМК на иностранном языке'),
        ('СПОК', 'Электронный персонифицированный онлайн-курс (СПОК)'),
        ('ЭОР', 'Электронный образовательный ресурс'),
    ])
    usage_type = models.CharField(max_length=255, blank=True, null=True, verbose_name="Инновация разработана для")
    resource_link = models.URLField(blank=True, null=True, verbose_name="Ссылка на ресурс")
    educational_files = models.ManyToManyField(Attachment, blank=True, verbose_name="Материалы ЭУМК")

    # Научно-техническая инновация
    scientific_product_type = models.CharField(max_length=255, blank=True, null=True, verbose_name="Тип продукта", choices=[
        ('product_1', 'Продукт 1: инновации в результатах ОКР'),
        ('product_2', 'Продукт 2: инновация в оказании технологических услуг'),
        ('product_3', 'Продукт 3: инновация в оказании инжиниринговых услуг'),
    ])
    patents_links = models.TextField(blank=True, null=True, verbose_name="Ссылки на патенты и статьи")
    readiness_level = models.CharField(max_length=255, blank=True, null=True, verbose_name="Уровень готовности")
    department = models.CharField(max_length=255, blank=True, null=True, verbose_name="Кафедра/лаборатория")
    scientific_files = models.ManyToManyField(
        Attachment, 
        blank=True,
        related_name='scientific_attachments',
        verbose_name="Научные материалы"
    )

    # Процессная инновация
    process_innovation_type = models.CharField(max_length=255, blank=True, null=True, verbose_name="Тип инновации", choices=[
        ('организационная', 'Организационная инновация'),
        ('технологическая', 'Технологическая инновация'),
        ('управленческая', 'Управленческая инновация'),
        ('другой', 'Другой тип инновации'),
    ])
    implementation_steps = models.TextField(blank=True, null=True, verbose_name="Описание процесса внедрения")
    process_files = models.FileField(upload_to='process_files/', blank=True, null=True, verbose_name="Заключение о внедрении")
    # Инновационное предложение
    problem_description = models.TextField(blank=True, null=True, verbose_name="Описание проблемы")
    solution = models.TextField(blank=True, null=True, verbose_name="Предлагаемое решение")
    expected_effects = models.TextField(blank=True, null=True, verbose_name="Ожидаемые эффекты")
    proposal_files = models.ManyToManyField(
        Attachment, 
        blank=True,
        related_name='proposal_attachments',
        verbose_name="Дополнительный документы"
    )

    additional_questions = models.TextField(blank=True, null=True, verbose_name="Дополнительные вопросы к автору")
    relevance = models.IntegerField(blank=True, null=True, verbose_name="Актуальность для СФ МЭИ")
    cost_effectiveness = models.IntegerField(blank=True, null=True, verbose_name="Отношение полезного эффекта к затратам")
    solution_quality = models.IntegerField(blank=True, null=True, verbose_name="Уровень проработки описания решения")
    novelty_level = models.IntegerField(blank=True, null=True, verbose_name="Уровень новизны")
    scalability = models.IntegerField(blank=True, null=True, verbose_name="Масштабы возможного внедрения")
    implementation_scale = models.IntegerField(blank=True, null=True, verbose_name="Масштаб фактического внедрения")
    effect_on_indicators = models.IntegerField(blank=True, null=True, verbose_name="Оценка эффекта на показатели ПКР")
    financial_effect = models.IntegerField(blank=True, null=True, verbose_name="Оценка финансового эффекта")
    comparison_with_analogues = models.IntegerField(blank=True, null=True, verbose_name="Сравнение с аналогами")
    comments = models.TextField(blank=True, null=True, verbose_name="Обоснование оценки")
    decision = models.CharField(max_length=20, choices=[
        ('approved', 'Принять'),
        ('rejected', 'Отклонить')
    ], blank=True, null=True, verbose_name="Решение")
    total_score = models.IntegerField(blank=True, null=True, verbose_name="Итоговая оценка")
    def get_innovation_type_display(self):
        return dict(self.INNOVATION_TYPE_CHOICES).get(self.innovation_type, self.innovation_type)
    
    def get_status_display(self):
        return dict(self.STATUS_CHOICES).get(self.status, self.status)
    
    def get_product_type_display(self):
        return dict([
            ('МООК', 'Массовый открытый онлайн-курс (МООК)'),
            ('ЭУМК', 'Электронный учебно-методический комплекс (ЭУМК)'),
            ('ЭУМК_иностранный', 'ЭУМК на иностранном языке'),
            ('СПОК', 'Электронный персонифицированный онлайн-курс (СПОК)'),
            ('ЭОР', 'Электронный образовательный ресурс'),
        ]).get(self.product_type, self.product_type)
    
    def get_scientific_product_type_display(self):
        return dict([
            ('product_1', 'Продукт 1: инновации в результатах ОКР'),
            ('product_2', 'Продукт 2: инновация в оказании технологических услуг'),
            ('product_3', 'Продукт 3: инновация в оказании инжиниринговых услуг'),
        ]).get(self.scientific_product_type, self.scientific_product_type)
    
    def get_process_innovation_type_display(self):
        return dict([
            ('организационная', 'Организационная инновация'),
            ('технологическая', 'Технологическая инновация'),
            ('управленческая', 'Управленческая инновация'),
            ('другой', 'Другой тип инновации'),
        ]).get(self.process_innovation_type, self.process_innovation_type)
    def get_unread_count(self, user):
        return self.chat_messages.filter(
            read=False
        ).exclude(
            sender=user
        ).count()
    def get_unread_count_for_chat(self, user, chat_type):
        return self.chat_messages.filter(
            chat_type=chat_type,
            read=False
        ).exclude(
            sender=user
        ).count()
    @register.filter
    def get_item(dictionary, key):
        return dictionary.get(key, 0)

    def get_chat_messages_by_type(self, chat_type):
        """Возвращает сообщения чата определенного типа, отсортированные по времени"""
        return self.chat_messages.filter(chat_type=chat_type).order_by('timestamp')
    def get_unread_count_for_chat(self, user, chat_type):
        return self.chat_messages.filter(
            chat_type=chat_type,
            read=False
        ).exclude(
            sender=user  # Исключаем сообщения, которые отправил сам пользователь
        ).count()
    @property
    def unread_counts(self):
        return {
            'author_expert': self.get_unread_count_for_chat(self.author, 'author_expert'),
            'author_responsible': self.get_unread_count_for_chat(self.author, 'author_responsible'),
            'expert_responsible': self.get_unread_count_for_chat(self.expert, 'expert_responsible')
        }
    def get_decision_display(self):
        return dict([
            ('approved', 'Принять'),
            ('rejected', 'Отклонить')
        ]).get(self.decision, self.decision)

    @property
    def short_description(self):
        return self.description[:100] + '...' if len(self.description) > 100 else self.description
    class Meta:
        ordering = ['-created_at']  # Сортировка по умолчанию
    @property
    def status_icon(self):
        icons = {
            'draft': 'fa-edit',
            'submitted': 'fa-paper-plane',
            'under_review': 'fa-search',
            'approved': 'fa-check-circle',
            'rejected': 'fa-times-circle'
        }
        return icons.get(self.status, 'fa-file-alt')
    
    @property
    def status_color(self):
        colors = {
            'draft': 'secondary',
            'submitted': 'primary',
            'under_review': 'info',
            'approved': 'success',
            'rejected': 'danger'
        }
        return colors.get(self.status, 'secondary')
        
    def __str__(self):
        return self.title

class ChatMessage(models.Model):
    id = models.BigAutoField(primary_key=True)  # Добавляем явное поле ID
    APPLICATION_CHAT_TYPES = [
        ('author_expert', 'Чат автора с экспертом'),
        ('author_responsible', 'Чат автора с ответственным'),
        ('expert_responsible', 'Чат эксперта с ответственным'),
    ]
    def is_unread(self, user):
        """Проверяет, является ли сообщение непрочитанным для указанного пользователя"""
        return not self.read and self.sender != user
    application = models.ForeignKey('Application', on_delete=models.CASCADE, related_name='chat_messages')
    chat_type = models.CharField(max_length=20, choices=APPLICATION_CHAT_TYPES)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    message = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    read = models.BooleanField(default=False)
    attachments = models.ManyToManyField('Attachment', blank=True)
    
    def save(self, *args, **kwargs):
        # Автоматическое преобразование ссылок в HTML
        if self.message:
            self.message = linkify_text(self.message)
        super().save(*args, **kwargs)

def linkify_text(text):
    import re
    url_pattern = re.compile(r'(https?://\S+)')
    return url_pattern.sub(r'<a href="\1" target="_blank">\1</a>', text)
    class Meta:
        ordering = ['timestamp']
        verbose_name = 'Сообщение чата'
        verbose_name_plural = 'Сообщения чатов'

    def __str__(self):
        return f"{self.get_chat_type_display()} - {self.sender}: {self.message[:50]}"

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