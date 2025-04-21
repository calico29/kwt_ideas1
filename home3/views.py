from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from allauth.account.models import EmailAddress
from django.contrib.auth import login as auth_login
from django.contrib.auth import login as auth_login  # Используйте псевдони
from django.shortcuts import redirect
from django.contrib.auth.models import User
from .models import Application
from django.shortcuts import render, redirect
from .forms import ApplicationForm
from .models import Application
import logging
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView
from django.contrib.auth import login
from pathlib import Path
from django.http import Http404, FileResponse, HttpResponse
from django.core.exceptions import PermissionDenied
from django.shortcuts import render, redirect
from .forms import ApplicationForm
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.contrib.auth import login
from django.shortcuts import render, redirect
from .forms import RegisterForm
from django.contrib.auth.models import Group
from django.contrib.auth.views import LogoutView
from django.urls import reverse_lazy
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.shortcuts import render, redirect
from .models import Application, Attachment
from .forms import ApplicationForm
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, redirect
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, get_object_or_404, redirect
from django.shortcuts import render, redirect
from django.http import Http404, FileResponse
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from .forms import ProcessInnovationReviewForm, ScientificInnovationReviewForm
import logging
logger = logging.getLogger("auth")

from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import os
from django.shortcuts import redirect, render
from django.conf import settings
from google.oauth2.credentials import Credentials
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import redirect
from .forms import (  # <-- Добавьте этот импорт
    ApplicationForm,
    ProposalReviewForm,
    ProcessInnovationReviewForm,
    ScientificInnovationReviewForm
)
import random
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Application, ChatMessage
from .forms import ChatMessageForm
from django.contrib.auth import login as auth_login
from django.shortcuts import redirect
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.middleware import OTPMiddleware
from django_otp import user_has_device
from django_otp.decorators import otp_required
from django_otp.plugins.otp_email.models import EmailDevice
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django_otp.plugins.otp_email.models import EmailDevice
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .middleware import TwoFactorAuthMiddleware  # Добавьте эту строку
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_email.models import EmailDevice
from django.template.loader import render_to_string 
from django.core.mail import EmailMessage
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
User = get_user_model()
from .forms import ProfileForm
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from .forms import ProfileEditForm
from .forms import EmailChangeForm
from .forms import PasswordChangeWithCodeForm
from django.contrib.auth import update_session_auth_hash


@login_required
def change_username(request):
    if request.method == "POST" and "send_code" in request.POST:
        new_username = request.POST.get("new_username")
        code = str(random.randint(100000, 999999))
        request.session["username_change_code"] = code
        request.session["pending_new_username"] = new_username
        send_mail(
            "Код подтверждения смены юзернейма",
            f"Ваш код подтверждения: {code}",
            settings.DEFAULT_FROM_EMAIL,
            [request.user.email],
        )
        return redirect("change_username")
    else:
        form = UsernameChangeForm(request.POST or None)
        if request.method == "POST" and "confirm_change" in request.POST:
            if form.is_valid():
                code = form.cleaned_data["confirmation_code"]
                if code == request.session.get("username_change_code"):
                    new_username = request.session.get("pending_new_username")
                    request.user.username = new_username
                    request.user.save()
                    request.session.pop("username_change_code", None)
                    request.session.pop("pending_new_username", None)
                    return redirect("profile")
                else:
                    form.add_error("confirmation_code", "Неверный код подтверждения")
        else:
            form = UsernameChangeForm(initial={"new_username": request.user.username})
    return render(request, "home/change_username.html", {"form": form})


@login_required
def change_password(request):
    if request.method == "POST":
        if 'send_code' in request.POST:
            # Генерация и отправка кода
            code = str(random.randint(100000, 999999))
            request.session['password_change_code'] = code
            send_mail(
                "Код подтверждения смены пароля",
                f"Ваш код: {code}",
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],
            )
            messages.success(request, "Код отправлен на вашу почту")
            return redirect('change_password')
        
        # Проверка кода и смена пароля
        form = PasswordChangeWithCodeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            del request.session['password_change_code']
            messages.success(request, "Пароль успешно изменен")
            return redirect('profile')
    else:
        form = PasswordChangeWithCodeForm(user=request.user)
    
    return render(request, 'home/change_password.html', {'form': form})
@login_required
def change_email(request):
    if request.method == "POST":
        if 'send_code' in request.POST:
            new_email = request.POST.get('new_email')
            code = str(random.randint(100000, 999999))
            request.session['email_change_code'] = code
            request.session['pending_email'] = new_email
            send_mail(
                "Код подтверждения смены email",
                f"Ваш код: {code}",
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],
            )
            messages.success(request, "Код отправлен на текущую почту")
            return redirect('change_email')
        
        # Проверка кода и смена email
        form = EmailChangeForm(request.POST)
        if form.is_valid():
            request.user.email = request.session['pending_email']
            request.user.save()
            del request.session['email_change_code']
            del request.session['pending_email']
            messages.success(request, "Email успешно изменен")
            return redirect('profile')
    else:
        form = EmailChangeForm()
    
    return render(request, 'home/change_email.html', {'form': form})
from django.utils import timezone
from datetime import timedelta




@login_required
def edit_profile(request):
    if request.method == "POST":
        form = ProfileEditForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            return redirect("profile")
    else:
        form = ProfileEditForm(user=request.user)
    return render(request, "home/edit_profile.html", {"form": form})

@login_required
def profile_view(request):
    return render(request, "home/profile.html", {"user": request.user})
@login_required
def request_email_change(request):
    if request.method == "POST":
        if 'send_code' in request.POST:
            new_email = request.POST.get('new_email')
            
            # Генерация кода
            code = str(random.randint(100000, 999999))
            request.session['email_change'] = {
                'code': code,
                'new_email': new_email,
                'expires': str(timezone.now() + timedelta(minutes=15))
            }
            
            # Отправка письма
            send_mail(
                "Код подтверждения смены email",
                f"Ваш код: {code}",
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],  # Отправляем на текущий email
                fail_silently=False,
            )
            messages.success(request, "Код отправлен на вашу текущую почту")
            return redirect('change_email')

        elif 'confirm' in request.POST:
            session_data = request.session.get('email_change')
            if not session_data:
                messages.error(request, "Сессия истекла, начните заново")
                return redirect('change_email')
            
            if request.POST.get('code') == session_data['code']:
                # Обновляем email
                user = request.user
                user.email = session_data['new_email']
                user.save()
                del request.session['email_change']
                messages.success(request, "Email успешно изменен!")
                return redirect('profile')
            else:
                messages.error(request, "Неверный код подтверждения")
                return redirect('change_email')
    
    return render(request, 'home/change_email.html')

    
@login_required
def confirm_email_change(request, token):
    pending_email = request.session.get("pending_email")
    if not pending_email:
        return redirect("edit_profile")
    if default_token_generator.check_token(request.user, token):
        request.user.email = pending_email
        request.user.save()
        # Очистка сессии
        del request.session["pending_email"]
        del request.session["email_change_token"]
        return redirect("dashboard")
    else:
        return HttpResponse("Ошибка подтверждения", status=400)

@login_required
def edit_profile(request):
    if request.method == "POST":
        form = ProfileForm(request.POST, user=request.user, instance=request.user)
        if form.is_valid():
            # Обновляем данные пользователя (имя, фамилия)
            user = form.save()
            # Обновляем дополнительные поля профиля
            profile = user.profile
            profile.middle_name = form.cleaned_data.get("middle_name")
            profile.phone = form.cleaned_data.get("phone")
            profile.save()
            # Можно добавить уведомление о том, что изменения требуют подтверждения по email
            # и вызвать функцию отправки письма для подтверждения изменений
            return redirect("dashboard")
    else:
        form = ProfileForm(user=request.user, instance=request.user)
    return render(request, "home/edit_profile.html", {"form": form})


def send_otp_email(user, token):
    email = EmailMessage(
        subject="Ваш код подтверждения KWT Ideas",
        body=f"""Здравствуйте, {user.username}!

Ваш код подтверждения: {token}

Код действителен 10 минут. Никому не сообщайте этот код.

С уважением,
Команда KWT Ideas""",
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email],
    )
    email.send()
@login_required
def resend_2fa_code(request):
    device = EmailDevice.objects.get(user=request.user)
    device.generate_challenge()
    messages.info(request, "Новый код подтверждения отправлен на ваш email")
    return redirect('two-factor-authenticate')
def home_page(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home/home_page.html')
def two_factor_authenticate(request):
    device_hash = TwoFactorAuthMiddleware.get_device_hash(request)
    
    if request.method == 'POST':
        token = request.POST.get('token', '')
        try:
            device = EmailDevice.objects.get(user=request.user)
            if device.verify_token(token):
                # Сохраняем верификацию с привязкой к хэшу устройства
                request.session[f'2fa_verified_{device_hash}'] = True
                request.session.modified = True
                logger.debug("2FA successfully verified")
                return redirect('dashboard')
        except EmailDevice.DoesNotExist:
            pass

    # Генерация нового токена
    try:
        device = EmailDevice.objects.get(user=request.user)
        device.generate_challenge()
        logger.debug(f"New 2FA code sent to {request.user.email}")
    except Exception as e:
        logger.error(f"Error generating 2FA code: {str(e)}")
    
    return render(request, 'home/two_factor_authenticate.html')

from django.contrib.auth import login
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django_otp import user_has_device

def login_view(request):
    logger.debug(f"я в логин вью")
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()

            # Обработка remember_me
            remember_me = request.POST.get('remember_me') == 'on'

            logger.debug(f"remember_me получено: {request.POST.get('remember_me')} -> {remember_me}")
            request.session['remember_device'] = remember_me
            # Отладочный вывод: проверяем, что переменная установилась
            logger.debug(f"remember_device установлено: {request.session.get('remember_device')}")
            
            # Устанавливаем время жизни сессии: 30 дней, если выбрано "Запомнить устройство"
            request.session.set_expiry(60 * 60 * 24 * 30 if remember_me else 0)
            request.session.save()

            # Входим пользователя
            login(request, user)

            # Если у пользователя настроена 2FA, перенаправляем на проверку
            if user_has_device(user):
                return redirect('two-factor-authenticate')
            else:
                return redirect('dashboard')
    else:
        form = AuthenticationForm(request)
    return render(request, 'login.html', {'form': form})


class RememberDeviceMiddleware(OTPMiddleware):
    def process_request(self, request):
        if request.user.is_authenticated:
            # Проверяем, подтверждено ли устройство
            if not request.session.get('device_verified'):
                # Если нет, перенаправляем на 2FA
                return redirect('two-factor-authenticate')
        return super().process_request(request)
        
def setup_email_2fa(user):
    device, created = EmailDevice.objects.get_or_create(
        user=user,
        name='Email',
        confirmed=True
    )
    return device
def redirect_email_confirmation(request, key):
    try:
        confirmation = EmailConfirmation.objects.get(key=key)
    except EmailConfirmation.DoesNotExist:
        confirmation = EmailConfirmationHMAC.from_key(key)
    
    if confirmation:
        uid = confirmation.email_address.user.pk
        token = confirmation.key  # Используем ключ подтверждения как токен (или генерируем свой)
        return redirect(f'/activate/{uid}/{token}/')

    return redirect('/')  # Если не найдено, редирект на главную
class CustomLoginView(LoginView):
    logger.debug(f"CustomLoginView")
    template_name = 'home/login.html'
    redirect_authenticated_user = True
    def dispatch(self, request, *args, **kwargs):
        logger.debug("CustomLoginView: dispatch called")
        return super().dispatch(request, *args, **kwargs)
    def form_invalid(self, form):
        logger.debug(f"CustomLoginView: form is invalid, errors={form.errors}")
        return super().form_invalid(form)

    def form_valid(self, form):
        
        remember_me = self.request.POST.get('remember_me') == 'on'
        self.request.session['remember_device'] = remember_me
        self.request.session.set_expiry(60 * 60 * 24 * 30 if remember_me else 0)
        self.request.session.save()
        logger.debug(f"CustomLoginView: remember_me={remember_me}, session remember_device={self.request.session.get('remember_device')}")
        logger.debug(f"Session Data Before Redirect: {self.request.session.items()}")
        return super().form_valid(form)

def google_login(request):
    flow = Flow.from_client_config(
        {
            "installed": {
                "client_id": settings.GOOGLE_OAUTH2_CLIENT_ID,
                "client_secret": settings.GOOGLE_OAUTH2_CLIENT_SECRET,
                "redirect_uris": [settings.GOOGLE_OAUTH2_REDIRECT_URI],
            }
        },
        scopes=["https://www.googleapis.com/auth/gmail.send"],
    )
    
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    
    request.session['state'] = state
    return redirect(authorization_url)

# URL для получения и сохранения токенов
def oauth2callback(request):
    state = request.session['state']
    flow = Flow.from_client_config(
        {
            "installed": {
                "client_id": settings.GOOGLE_OAUTH2_CLIENT_ID,
                "client_secret": settings.GOOGLE_OAUTH2_CLIENT_SECRET,
                "redirect_uris": [settings.GOOGLE_OAUTH2_REDIRECT_URI],
            }
        },
        scopes=["https://www.googleapis.com/auth/gmail.send"],
    )
    
    flow.fetch_token(authorization_response=request.build_absolute_uri(), state=state)
    
    credentials = flow.credentials
    request.session['credentials'] = credentials_to_dict(credentials)
    
    return redirect('send_email')  # После успешной аутентификации отправляем пользователя на страницу отправки email

# Функция для сохранения токенов
def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes,
    }
User = get_user_model()





def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist) as e:
        logger.error(f"Activation error: {e}")
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        # Активируем пользователя
        user.is_active = True
        user.save()
        
        # Подтверждаем email
        email_address = EmailAddress.objects.get_for_user(user, user.email)
        if email_address:
            email_address.verified = True
            email_address.primary = True
            email_address.save()
        
        # Автоматически входим
        auth_login(request, user, backend='allauth.account.auth_backends.AuthenticationBackend')
        
        return redirect('dashboard')
    else:
        logger.error(f"Invalid activation link for uidb64: {uidb64}")
        return render(request, 'account/email_confirm.html', {'error': 'Неверная ссылка активации'})

def confirm_email(request, token):
    try:
        signer = Signer()
        email = signer.unsign(token)
        confirmation = EmailConfirmation.objects.get(email=email, confirmed_at=None)
        confirmation.confirm()
        user = confirmation.user
        user.is_active = True
        user.save()
        return redirect('email_confirmed')
    except BadSignature:
        return redirect('email_confirmation_failed')
    except EmailConfirmation.DoesNotExist:
        return redirect('email_confirmation_failed')        
def send_confirmation_email(request, user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    current_site = get_current_site(request)
    activate_url = f"http://{current_site.domain}/activate/{uid}/{token}/"

    # Отправка письма
    subject = "Подтверждение регистрации"
    message = f"Здравствуйте, {user.username}!\n\nДля подтверждения вашей почты перейдите по ссылке: {activate_url}\n\nЕсли вы не регистрировались, просто проигнорируйте это письмо."
    send_mail(subject, message, "kwt.ideas@gmail.com", [user.email])


def review_application(request, application_id):
    application = get_object_or_404(Application, id=application_id)
    
    FormClass = {
        'proposal': ProposalReviewForm,
        'process': ProcessInnovationReviewForm,
        'scientific': ScientificInnovationReviewForm
    }.get(application.innovation_type)

    if not FormClass:
        return redirect('expert_dashboard')

    if request.method == "POST":
        form = FormClass(request.POST)
        if form.is_valid():
            # Общие поля
            application.additional_questions = form.cleaned_data.get('additional_questions')
            application.comments = form.cleaned_data.get('comments')
            application.decision = form.cleaned_data.get('decision')

            # Поля оценки
            for field in form.cleaned_data:
                if hasattr(application, field):
                    setattr(application, field, form.cleaned_data[field])

            # Расчет итоговой оценки
            if application.innovation_type == 'proposal':
                application.total_score = (
                    form.cleaned_data['relevance'] +
                    form.cleaned_data['cost_effectiveness'] +
                    form.cleaned_data['solution_quality']
                )
            elif application.innovation_type == 'process':
                application.total_score = (
                    form.cleaned_data['novelty_level'] +
                    form.cleaned_data['scalability'] +
                    form.cleaned_data['implementation_scale'] +
                    form.cleaned_data['effect_on_indicators']
                )
            elif application.innovation_type == 'scientific':
                application.total_score = (
                    form.cleaned_data['scalability'] +
                    form.cleaned_data['financial_effect'] +
                    form.cleaned_data['comparison_with_analogues']
                )

            application.status = 'under_review'
            application.save()
            return redirect('expert_dashboard')
    else:
        initial_data = {
            field: getattr(application, field) 
            for field in FormClass().base_fields
            if hasattr(application, field)
        }
        form = FormClass(initial=initial_data)

    return render(request, 'home/review_application.html', {
        'form': form,
        'application': application,
        'total_score': application.total_score or 0
    })

def is_admin(user):
    return user.is_superuser

def all_applications_view(request):
    applications = Application.objects.all()
    return render(request, 'home/all_applications.html', {'applications': applications})
@login_required

@user_passes_test(is_admin)
def manage_users(request):
    users = User.objects.all()
    groups = Group.objects.all()

    if request.method == "POST":
        user_id = request.POST.get("user_id")
        action = request.POST.get("action")

        if action == "delete":
            User.objects.filter(id=user_id).delete()
        elif action == "update_group":
            new_group = request.POST.get("group")
            user = User.objects.get(id=user_id)
            user.groups.clear()  # Убираем старые группы
            if new_group:
                group = Group.objects.get(name=new_group)
                user.groups.add(group)

        return redirect("manage_users")  # Обновляем страницу

    return render(request, "manage_users.html", {"users": users, "groups": groups})
logger = logging.getLogger(__name__)

@login_required
def expert_dashboard(request):
    if request.user.groups.filter(name="Эксперты").exists():
        applications = Application.objects.filter(expert=request.user)
        return render(request, "home/expert_dashboard.html", {"applications": applications})
    else:
        return redirect("dashboard")
@login_required
def assign_expert(request, application_id):
    if request.method == "POST":
        application = Application.objects.get(id=application_id)
        expert_id = request.POST.get("expert")
        expert = User.objects.get(id=expert_id)
        application.expert = expert
        application.status = "under_review"  # Статус "На рассмотрении"
        application.save()
        return redirect("moderation")
    else:
        application = Application.objects.get(id=application_id)
        experts = User.objects.filter(groups__name="Эксперты")
        return render(request, "home/assign_expert.html", {"application": application, "experts": experts})        
@login_required
def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    groups = Group.objects.all()

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        group_name = request.POST.get("group")

        if username:
            user.username = username
        if email:
            user.email = email
        if group_name:
            group = Group.objects.get(name=group_name)
            user.groups.set([group])  # Назначаем выбранную группу
        user.save()

        return redirect("manage_users")

    return render(request, "edit_user.html", {"user": user, "groups": groups})

@login_required
def moderation_page(request):
    if request.user.groups.filter(name="Ответственные сотрудники").exists():
        applications = Application.objects.filter(status="submitted")
        return render(request, "home/moderation_page.html", {"applications": applications})
    else:
        return redirect("dashboard")
@login_required
def assign_expert(request, application_id):
    if request.method == "POST":
        application = Application.objects.get(id=application_id)
        expert_id = request.POST.get("expert")
        expert = User.objects.get(id=expert_id)
        application.expert = expert
        application.status = "under_review"  # Статус "На рассмотрении"
        application.save()
        return redirect("moderation")  # Убедись, что имя маршрута правильное
    else:
        application = Application.objects.get(id=application_id)
        experts = User.objects.filter(groups__name="Эксперты")
        return render(request, "home/assign_expert.html", {"application": application, "experts": experts})
@login_required
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return redirect("manage_users")
class CustomLogoutView(LogoutView):
    next_page = reverse_lazy("home") 
User = get_user_model()

from django.contrib.auth import login as auth_login



        
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Деактивируем пользователя до подтверждения почты
            user.save()

            # Создаем токен подтверждения
            confirmation = EmailConfirmation.objects.create(user=user, email=form.cleaned_data['email'])

            # Отправляем письмо с подтверждением
            subject = 'Подтверждение email'
            html_message = render_to_string('email_confirmation.html', {
                'user': user,
                'confirmation_url': f'{settings.DOMAIN}/confirm-email/{confirmation.token}/'
            })
            plain_message = strip_tags(html_message)
            send_mail(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [form.cleaned_data['email']], html_message=html_message)

            return redirect('email_confirmation_sent')
    else:
        form = RegistrationForm()

    return render(request, 'register.html', {'form': form})


from django.forms import modelformset_factory

def application_page(request):
    if request.method == "POST":
        form = ApplicationForm(request.POST)
        files = request.FILES.getlist("attached_files")  # ✅ Получаем список файлов

        if form.is_valid():
            application = form.save(commit=False)
            application.author = request.user
            application.save()

            # ✅ Сохраняем файлы и привязываем их к заявке
            for file in files:
                attachment = Attachment.objects.create(file=file)
                application.attachments.add(attachment)

            return redirect("dashboard")
    else:
        form = ApplicationForm()

    return render(request, "home/application_page.html", {"form": form})


@login_required
def assign_expert(request, application_id):
    if request.method == "POST":
        application = Application.objects.get(id=application_id)
        expert_id = request.POST.get("expert")
        expert = User.objects.get(id=expert_id)
        application.expert = expert
        application.status = "under_review"  # Статус "На рассмотрении"
        application.save()
        return redirect("moderation")  # Убедись, что имя маршрута правильное
    else:
        application = Application.objects.get(id=application_id)
        experts = User.objects.filter(groups__name="Эксперты")
        return render(request, "home/assign_expert.html", {"application": application, "experts": experts})



def submit_application(request):
    if request.method == "POST":
        form = ApplicationForm(request.POST, request.FILES)
        if form.is_valid():
            application = form.save(commit=False)
            application.author = request.user
            application.save()

            # Обработка файлов для всех типов
            file_types = {
                'educational_files': application.educational_files,
                'scientific_files': application.scientific_files,
                'proposal_files': application.proposal_files
            }

            for field, relation in file_types.items():
                files = request.FILES.getlist(field)
                for f in files:
                    attachment = Attachment.objects.create(file=f)
                    relation.add(attachment)

            return redirect("dashboard")

@login_required
def dashboard_view(request):
    """Личный кабинет с фильтрацией по ролям"""
    
    user = request.user

    if user.groups.filter(name="Авторы").exists():
        # Авторы видят только свои заявки
        applications = Application.objects.filter(author=user)
    
    elif user.groups.filter(name="Эксперты").exists():
        # Эксперты видят только назначенные им заявки
        applications = Application.objects.filter(expert=user)
    
    elif user.groups.filter(name="Ответственные сотрудники").exists():
        # Ответственные сотрудники видят все заявки
        applications = Application.objects.all()
    
    else:
        # Если нет группы, пустой список
        applications = Application.objects.none()

    return render(request, "home/dashboard.html", {"applications": applications})
@csrf_exempt  # Для упрощения, лучше использовать csrf токены в реальном проекте
@require_POST
def send_message(request, application_id):
    try:
        data = json.loads(request.body)
        application = Application.objects.get(id=application_id)
        message_text = data.get('message')
        chat_type = data.get('chat_type')

        if not message_text:
            return JsonResponse({'status': 'error', 'message': 'Message is required'}, status=400)

        # Проверка прав доступа к чату (аналогично view_application)
        available_chats = []
        if request.user == application.author:
            available_chats = ['author_expert', 'author_responsible']
        elif request.user == application.expert:
            available_chats = ['author_expert', 'expert_responsible']
        elif request.user.groups.filter(name="Ответственные сотрудники").exists():
            available_chats = ['author_responsible', 'expert_responsible']

        if chat_type not in available_chats:
            return JsonResponse({'status': 'error', 'message': 'Access denied'}, status=403)

        # Создание сообщения
        message = ChatMessage.objects.create(
            application=application,
            chat_type=chat_type,
            sender=request.user,
            message=message_text,
            read=False
        )

        return JsonResponse({
            'status': 'success',
            'message': {
                'text': message.message,
                'timestamp': message.timestamp.strftime("%d.%m.%Y %H:%M"),
                'sender': message.sender.username
            }
        })

    except Application.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Application not found'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
def debug_file_view(request, file_path):
    full_path = os.path.join(settings.MEDIA_ROOT, file_path)
    if os.path.exists(full_path):
        return FileResponse(open(full_path, 'rb'))
    return HttpResponse("File not found", status=404)
@login_required
def view_application(request, application_id):
    application = get_object_or_404(Application, id=application_id)
    def get_available_chats(user, application):
        chats = []
        if user == application.author:
            chats = [
                ('author_expert', 'Чат с экспертом'),
                ('author_responsible', 'Чат с ответственным'),
            ]
        elif user == application.expert:
            chats = [
                ('author_expert', 'Чат с автором'),
                ('expert_responsible', 'Чат с ответственным'),
            ]
        elif user.groups.filter(name="Ответственные сотрудники").exists():
            chats = [
                ('author_responsible', 'Чат с автором'),
                ('expert_responsible', 'Чат с экспертом'),
            ]
        return chats
    available_chats = get_available_chats(request.user, application)
    active_chat = request.GET.get('chat', available_chats[0][0] if available_chats else None)
      
    if request.method == 'POST' and 'send_message' in request.POST:
        chat_type = request.POST.get('chat_type')
        message_text = request.POST.get('message', '').strip()
        files = request.FILES.getlist('file')  # Получаем список файлов
        # Проверка доступа к чату
        current_chats = get_available_chats(request.user, application)
        allowed_chat_types = [ct for ct, _ in current_chats]
        
        if chat_type not in allowed_chat_types:
            return HttpResponseForbidden("Нет доступа к этому чату")
            
        if message_text or files:
            try:
                message = ChatMessage.objects.create(
                    application=application,
                    chat_type=chat_type,
                    sender=request.user,
                    message=message_text,
                    read=False
                )
                
                for file in files:
                    try:
                        if file.size == 0:
                            raise ValidationError("Пустой файл")
                            
                        attachment = Attachment(file=file)
                        attachment.full_clean()  # Вызывает валидацию
                        attachment.save()
                        message.attachments.add(attachment)
                        
                    except (ValidationError, ValueError) as e:
                        # Логируем ошибку, но продолжаем обработку
                        print(f"Ошибка загрузки файла {file.name}: {e}")
                        # Можно добавить сообщение об ошибке для пользователя
                
                return redirect(f"{application.get_absolute_url()}?chat={chat_type}")
            except Exception as e:
                print(f"Ошибка: {e}")
                # Обработка ошибки создания сообщения
    # Инициализируем chat_messages как словарь по умолчанию
    chat_messages = {}
    
    # Определяем доступные чаты
    available_chats = []
    if request.user == application.author:
        available_chats = [
            ('author_expert', 'Чат с экспертом'),
            ('author_responsible', 'Чат с ответственным'),
        ]
    elif request.user == application.expert:
        available_chats = [
            ('author_expert', 'Чат с автором'),
            ('expert_responsible', 'Чат с ответственным'),
        ]
    elif request.user.groups.filter(name="Ответственные сотрудники").exists():
        available_chats = [
            ('author_responsible', 'Чат с автором'),
            ('expert_responsible', 'Чат с экспертом'),
        ]
    
    # Заполняем chat_messages данными
    for chat_type, _ in available_chats:
        chat_messages[chat_type] = list(
            application.chat_messages.filter(chat_type=chat_type).order_by('timestamp')
        )
    
    active_chat = request.GET.get('chat', available_chats[0][0] if available_chats else None)
    chat_data = {}
    for chat_type, chat_name in available_chats:
        messages = application.chat_messages.filter(chat_type=chat_type).order_by('timestamp')
        unread_count = sum(1 for msg in messages if not msg.read and msg.sender != request.user)
        
        chat_data[chat_type] = {
            'name': chat_name,
            'messages': messages,
            'unread_count': unread_count
        }
    if active_chat:
        application.chat_messages.filter(
            chat_type=active_chat,
            read=False
        ).exclude(
            sender=request.user
        ).update(read=True)
        # Обновляем счетчик непрочитанных
        if active_chat in chat_data:
            chat_data[active_chat]['unread_count'] = 0
    return render(request, "home/view_application.html", {
        'chat_data': chat_data,
        'application': application,
        'available_chats': available_chats,
        'chat_messages': chat_messages or {},  # Гарантируем, что это будет словарь
        'active_chat': active_chat,
    })

from pathlib import Path
from django.http import Http404, FileResponse, HttpResponse
from django.core.exceptions import PermissionDenied
import os

@login_required
def protected_file(request, file_path):
    """
    Защищенный доступ к файлам с проверкой прав
    """
    try:
        # Используем pathlib для корректного объединения путей
        full_path = Path(settings.MEDIA_ROOT) / file_path
        
        # Проверяем существование файла
        if not full_path.exists():
            raise Http404("Файл не найден")
        
        # Проверяем размер файла
        if full_path.stat().st_size == 0:
            return HttpResponse("Файл пуст", status=400)
        
        # Проверяем права доступа
        filename = os.path.basename(file_path)
        attachment = Attachment.objects.filter(file=f"attachments/{filename}").first()
        
        if not attachment:
            raise PermissionDenied("Доступ запрещен")
        
        # Проверяем, имеет ли пользователь доступ
        has_access = False
        if attachment.chatmessage_set.exists():
            message = attachment.chatmessage_set.first()
            if request.user in [message.sender, message.application.author, message.application.expert]:
                has_access = True
        
        if not has_access and not request.user.is_staff:
            raise PermissionDenied("Доступ запрещен")
        
        # Отдаем файл
        return FileResponse(open(full_path, 'rb'))
    
    except Exception as e:
        # Логируем ошибку для отладки
        print(f"Ошибка доступа к файлу: {e}")
        raise Http404("Ошибка доступа к файлу")
        с
def logout_view(request):
    logout(request)
    return redirect("/") 