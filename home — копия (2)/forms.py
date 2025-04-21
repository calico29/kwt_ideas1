
from django import forms
from .models import Application, Attachment, ChatMessage
from django.contrib.auth.models import User
from django.contrib.auth.models import Group
from .models import ChatMessage
from allauth.account.forms import SignupForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView  # Добавьте эту строку
from django.contrib.auth.models import User
from .models import Profile
from django.contrib.auth.forms import PasswordChangeForm
class PasswordChangeWithCodeForm(PasswordChangeForm):
    confirmation_code = forms.CharField(label="Код подтверждения", required=True)
class UsernameChangeForm(forms.Form):
    new_username = forms.CharField(label="Новый юзернейм", max_length=150, required=True)
    confirmation_code = forms.CharField(label="Код подтверждения", required=True)

class EmailChangeForm(forms.Form):
    new_email = forms.EmailField(label="Новый Email", required=True)
    confirmation_code = forms.CharField(label="Код подтверждения", required=True)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)


class ProfileEditForm(forms.Form):
    first_name = forms.CharField(label="Имя", max_length=150, required=True)
    last_name = forms.CharField(label="Фамилия", max_length=150, required=True)
    middle_name = forms.CharField(label="Отчество", max_length=150, required=False)
    phone = forms.RegexField(
        label="Номер телефона",
        regex=r'^(?:\+7|8)\d{10}$',
        error_messages={'invalid': "Введите корректный российский номер телефона (например, +7XXXXXXXXXX или 8XXXXXXXXXX)"},
        required=True
    )
    username = forms.CharField(label="Юзернейм", max_length=150, required=True)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)
        # Заполняем поля данными из модели User
        self.fields['first_name'].initial = self.user.first_name
        self.fields['last_name'].initial = self.user.last_name
        self.fields['username'].initial = self.user.username
        # Из профиля
        if hasattr(self.user, 'profile'):
            self.fields['middle_name'].initial = self.user.profile.middle_name
            self.fields['phone'].initial = self.user.profile.phone

    def save(self):
        # Сохраняем данные в User
        self.user.first_name = self.cleaned_data['first_name']
        self.user.last_name = self.cleaned_data['last_name']
        self.user.username = self.cleaned_data['username']
        self.user.save()
        # Сохраняем данные в Profile
        profile = self.user.profile
        profile.middle_name = self.cleaned_data['middle_name']
        profile.phone = self.cleaned_data['phone']
        profile.save()

class ProfileForm(forms.ModelForm):
    first_name = forms.CharField(label="Имя", required=True)
    last_name = forms.CharField(label="Фамилия", required=True)
    middle_name = forms.CharField(label="Отчество", required=False)
    phone = forms.CharField(label="Номер телефона", required=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name']

    def __init__(self, *args, **kwargs):
        # Передаём объект пользователя, чтобы получить данные профиля
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)
        # Если у пользователя уже есть профиль, подставляем начальные данные
        if hasattr(self.user, 'profile'):
            self.fields['middle_name'].initial = self.user.profile.middle_name
            self.fields['phone'].initial = self.user.profile.phone

class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True  # Разрешаем выбор нескольких файлов
from allauth.account.forms import LoginForm
from allauth.account.models import EmailAddress
from django import forms
from .models import Application

class ApplicationForm(forms.ModelForm):
    educational_files = forms.FileField(
        widget=MultipleFileInput(attrs={'class': 'file-input'}),
        required=False,
        label="Материалы ЭУМК",
        help_text="Выберите файлы (Ctrl + клик для множественного выбора)"
    )
    scientific_files = forms.FileField(
        widget=MultipleFileInput(attrs={'class': 'file-input'}),
        required=False,
        label="Научные материалы",
        help_text="PDF, DOCX, изображения (макс. 20 МБ)"
    )

    proposal_files = forms.FileField(
        widget=MultipleFileInput(attrs={'class': 'file-input'}),
        required=False,
        label="Документы предложения",
        help_text="Поддерживаемые форматы: ZIP, XLSX, PPT"
    )
    class Meta:
        model = Application
        fields = [
            "title", "phone", "description", "innovation_type",
            "authors", "product_type", "usage_type", "resource_link",
            "scientific_product_type", "patents_links", "readiness_level", "department", 
            "process_innovation_type", "implementation_steps", "process_files",
            "problem_description", "solution", "expected_effects", 
        ]
        
        widgets = {
            # Общие поля
            'title': forms.TextInput(attrs={'placeholder': 'Введите краткое название инновации.'}),
            'phone': forms.TextInput(attrs={'placeholder': 'Введите контактный телефон.'}),
            'description': forms.Textarea(attrs={'placeholder': 'Опишите инновацию.'}),
            'innovation_type': forms.Select(choices=[
                ('educational', 'Образовательная инновация'),
                ('scientific', 'Научно-техническая инновация'),
                ('process', 'Процессная инновация'),
                ('proposal', 'Инновационное предложение'),
            ]),

            # Поля для образовательной инновации
            'product_type': forms.Select(choices=[
                ('МООК', 'Массовый открытый онлайн-курс (МООК)'),
                ('ЭУМК', 'Электронный учебно-методический комплекс (ЭУМК)'),
                ('ЭУМК_иностранный', 'ЭУМК на иностранном языке'),
                ('СПОК', 'Электронный персонифицированный онлайн-курс (СПОК)'),
                ('ЭОР', 'Электронный образовательный ресурс'),
            ]),
            'usage_type': forms.Select(choices=[
                ('основная', 'Основная образовательная программа'),
                ('дополнительная', 'Программа дополнительного профессионального образования'),
            ]),
            'resource_link': forms.URLInput(attrs={'placeholder': 'Введите ссылку на ресурс (обязательно для ЭОР).'}),
             'educational_files': MultipleFileInput(),


            # Поля для научно-технической инновации
            'scientific_product_type': forms.Select(choices=[
                ('product_1', 'Продукт 1: инновации в результатах ОКР'),
                ('product_2', 'Продукт 2: инновация в оказании технологических услуг'),
                ('product_3', 'Продукт 3: инновация в оказании инжиниринговых услуг'),
            ]),
            'patents_links': forms.Textarea(attrs={'placeholder': 'Укажите ссылки на патенты, статьи или доклады.'}),
            'readiness_level': forms.Select(choices=[
                ('1', '1'),
                ('2', '2'),
                ('3', '3'),
                ('4', '4'),
                ('5', '5'),
                ('6', '6'),
                ('7', '7'),
                ('8', '8'),
                ('9', '9'),
            ]),
            'department': forms.TextInput(attrs={'placeholder': 'Укажите кафедру/лабораторию.'}),
            'scientific_files': MultipleFileInput(),


            # Поля для процессной инновации
            'process_innovation_type': forms.Select(choices=[
                ('организационная', 'Организационная инновация'),
                ('технологическая', 'Технологическая инновация'),
                ('управленческая', 'Управленческая инновация'),
                ('другой', 'Другой тип инновации'),
            ]),
            'implementation_steps': forms.Textarea(attrs={'placeholder': 'Опишите порядок внедрения – последовательность действий, основные задачи и этапы разработки и внедрения.'}),
            'process_files': forms.FileInput(attrs={'placeholder': 'Прикрепите заключение о внедрении инновации.'}),

            # Поля для инновационного предложения
            'problem_description': forms.Textarea(attrs={'placeholder': 'Опишите проблему и текущее состояние.'}),
            'solution': forms.Textarea(attrs={'placeholder': 'Опишите предлагаемое решение.'}),
            'expected_effects': forms.Textarea(attrs={'placeholder': 'Опишите ожидаемые эффекты.'}),
            'proposal_files': MultipleFileInput(),

        }
        help_texts = {
            # Общие подсказки
            "title": "Введите краткое название инновации.",
            "phone": "Обязательно укажите контактный телефон.",
            "description": "Опишите инновацию.",
            "innovation_type": "Выберите тип инновации.",

            # Подсказки для образовательной инновации
            "authors": "Перечислите всех авторов (ФИО, должность).",
            "product_type": "Выберите тип продукта.",
            "usage_type": "Выберите, для чего разработана инновация.",
            "resource_link": "Ссылка на ресурс обязательна для ЭОР, размещенных в Лекториуме СФМЭИ.",
            "educational_files": "Вложения обязательны для ЭУМК (во вложения прикладываются все материалы ЭУМК).",

            # Подсказки для научно-технической инновации
            "scientific_product_type": "Выберите тип продукта.",
            "patents_links": "Укажите ссылки на патенты, статьи или доклады.",
            "readiness_level": "Уровень готовности должен быть не менее 4 по ГОСТ Р 58048-2017.",
            "department": "Укажите кафедру/лабораторию.",
            "scientific_files": "Прикрепите акты выполненных работ или лицензионные договоры.",

            # Подсказки для процессной инновации
            "process_innovation_type": "Выберите тип инновации.",
            "implementation_steps": "Опишите порядок внедрения – последовательность действий, основные задачи и этапы разработки и внедрения.",
            "process_files": "Прикрепите заключение о внедрении инновации.",

            # Подсказки для инновационного предложения
            "problem_description": "Опишите проблему и текущее состояние.",
            "solution": "Опишите предлагаемое решение.",
            "expected_effects": "Опишите ожидаемые эффекты.",
            "proposal_files": "Прикрепите дополнительные документы, если необходимо.",
        }

class CustomAuthForm(AuthenticationForm):
    username = forms.EmailField(label="Email")  # Используйте email вместо username

class CustomLoginForm(LoginForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['login'].label = "Логин или Email"
        self.fields['password'].label = "Пароль"

class CustomLoginView(LoginView):
    form_class = CustomAuthForm  # Укажите кастомную форму
    template_name = 'login.html'   


class ProposalReviewForm(forms.Form):
    additional_questions = forms.CharField(widget=forms.Textarea, label="Дополнительные вопросы к автору", required=False)
    relevance = forms.ChoiceField(choices=[(i, str(i)) for i in range(6)], label="Актуальность для СФ МЭИ")
    cost_effectiveness = forms.ChoiceField(choices=[(i, str(i)) for i in range(6)], label="Отношение полезного эффекта к затратам")
    solution_quality = forms.ChoiceField(choices=[(i, str(i)) for i in range(6)], label="Уровень проработки описания решения")
    comments = forms.CharField(widget=forms.Textarea, label="Обоснование оценки", required=False)
    decision = forms.ChoiceField(choices=[('approved', 'Принять'), ('rejected', 'Отклонить')], label="Решение")

    def calculate_total(self):
        fields = ['relevance', 'cost_effectiveness', 'solution_quality']
        total = sum(int(self.cleaned_data[field]) for field in fields)
        return total

class ChatMessageForm(forms.ModelForm):
    class Meta:
        model = ChatMessage
        fields = ['chat_type', 'message']
        widgets = {
            'chat_type': forms.HiddenInput(),
            'message': forms.Textarea(attrs={
                'rows': 3,
                'placeholder': 'Введите ваше сообщение...',
                'class': 'form-control'
            })
        }   
class ProcessInnovationReviewForm(forms.Form):
    additional_questions = forms.CharField(widget=forms.Textarea, label="Дополнительные вопросы к автору", required=False)
    novelty_level = forms.ChoiceField(choices=[(0, '0'), (1, '1'), (2, '2')], label="Уровень новизны")
    scalability = forms.ChoiceField(choices=[(1, '1'), (2, '2'), (3, '3')], label="Масштабы возможного внедрения")
    implementation_scale = forms.ChoiceField(choices=[(0, '0'), (1, '1'), (2, '2'), (3, '3')], label="Масштаб фактического внедрения")
    effect_on_indicators = forms.ChoiceField(choices=[(0, '0'), (1, '1'), (2, '2')], label="Оценка эффекта на показатели ПКР")
    comments = forms.CharField(widget=forms.Textarea, label="Обоснование оценки", required=False)

    def calculate_total(self):
        fields = ['novelty_level', 'scalability', 'implementation_scale', 'effect_on_indicators']
        total = sum(int(self.cleaned_data[field]) for field in fields)
        return total
class ScientificInnovationReviewForm(forms.Form):
    additional_questions = forms.CharField(widget=forms.Textarea, label="Дополнительные вопросы к автору", required=False)
    scalability = forms.ChoiceField(choices=[(0, '0'), (1, '1'), (2, '2'), (3, '3')], label="Масштабы возможного внедрения")
    financial_effect = forms.ChoiceField(choices=[(0, '0'), (1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5')], label="Оценка финансового эффекта")
    comparison_with_analogues = forms.ChoiceField(choices=[(0, '0'), (1, '1'), (2, '2')], label="Сравнение с аналогами")
    comments = forms.CharField(widget=forms.Textarea, label="Обоснование оценки", required=False)

    def calculate_total(self):
        fields = ['scalability', 'financial_effect', 'comparison_with_analogues']
        total = sum(int(self.cleaned_data[field]) for field in fields)
        return total       
class AttachmentForm(forms.ModelForm):
    class Meta:
        model = Attachment
        fields = ["file"]

class RegisterForm(SignupForm):
    username = forms.CharField(max_length=30, required=True, label="Логин")
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].label = "Email"
        self.fields['password1'].label = "Пароль"
        self.fields['password2'].label = "Подтверждение пароля"

    def save(self, request):
        user = super().save(request)
        user.is_active = False  # User remains inactive until email confirmation
        user.save()
        
        # Create email address record
        EmailAddress.objects.add_email(
            request,
            user,
            user.email,
            signup=True,
            confirm=True
        )
        
        # Add to group
        group = Group.objects.get(name='Авторы')
        user.groups.add(group)
        
        return user

    def signup(self, request, user):
        pass  # Логика уже в save


