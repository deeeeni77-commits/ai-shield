
from django.urls import path

from .views import alerts_api, dashboard_api

urlpatterns = [
    path("alerts/", alerts_api, name="alerts-api"),
    path("dashboard/", dashboard_api, name="dashboard-api"),
]
