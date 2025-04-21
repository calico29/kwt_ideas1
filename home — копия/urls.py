from django.contrib import admin
from django.urls import path, include
from .views import submit_application, dashboard_view, view_application
from .views import application_page
from .views import register
from django.contrib.auth import views as auth_views
from .views import CustomLogoutView
from .views import logout_view
from .views import manage_users
from home.views import all_applications_view
from .views import manage_users
from .views import manage_users, edit_user, delete_user
from .views import expert_dashboard
from .views import moderation_page
from .views import assign_expert, review_application
from django.urls import include, path
from django.urls import path
from . import views
from django.urls import re_path
from . import consumers
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve 
from .views import CustomLoginView
from .views import activate
from .views import redirect_email_confirmation
from allauth.account.views import ConfirmEmailView
from django_otp.views import LoginView as OTPLoginView


urlpatterns = [
    #path('', views.home_page, name='home'),  # Добавьте этот маршрут первым
    path('google-login/', views.google_login, name='google_login'),
    path('oauth2callback/', views.oauth2callback, name='oauth2callback'),
    path("applicationpage/", application_page, name="application_page"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("application/<int:application_id>/", view_application, name="view_application"),
    path("register/", register, name="register"),  # ✅ Страница регистрации
    path('account/2fa/authenticate/', views.two_factor_authenticate, name='two-factor-authenticate'),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("logout/", logout_view, name="logout"),
    path("manage-users/", manage_users, name="manage_users"),
    path('applications/', all_applications_view, name='all_applications'),
    path("manage-users/edit/<int:user_id>/", edit_user, name="edit_user"),
    path("manage-users/delete/<int:user_id>/", delete_user, name="delete_user"),
    path("dashboard/", dashboard_view, name="my_applications"),
    path("moderation/", moderation_page, name="moderation"),
    path("expert/", expert_dashboard, name="expert_dashboard"),
    path("assign-expert/<int:application_id>/", assign_expert, name="assign_expert"),
    path("review/<int:application_id>/", review_application, name="review_application"),
  
    path('activate/<str:uidb64>/<str:token>/', views.activate, name='activate'),
    path('application/<int:application_id>/send_message/', views.send_message, name='send_message'),
    path('debug/file/<path:file_path>', views.debug_file_view, name='debug_file'),
    path('protected/media/<path:file_path>', views.protected_file, name='protected_file'),
    path('accounts/login/', OTPLoginView.as_view(), name='account_login'),
    path("profile/edit/", views.edit_profile, name="edit_profile"),
    path("profile/change-email/", views.request_email_change, name="change_email"),
    path("profile/change-password/", views.change_password, name="change_password"),
    path("profile/change-username/", views.change_username, name="change_username"),
    
    path('accounts/', include('allauth.urls')),
    

    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += [
        path('media/<path:path>', serve, {'document_root': settings.MEDIA_ROOT}),
    ]
websocket_urlpatterns = [
    re_path(r'ws/chat/(?P<application_id>\d+)/$', consumers.ChatConsumer.as_asgi()),
]