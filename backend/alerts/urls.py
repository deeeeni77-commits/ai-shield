
from django.urls import path
from .views import alerts_api, dashboard_api
from .auth_views import register_api, login_api, logout_api
from .auth_views import register_api, login_api, logout_api, me_api

urlpatterns = [
    path("alerts/", alerts_api, name="alerts-api"),
    path("dashboard/", dashboard_api, name="dashboard-api"),

    path("register/", register_api, name="register-api"),
    path("login/", login_api, name="login-api"),
    path("logout/", logout_api, name="logout-api"),
    path("me/", me_api, name="me-api"),
]
