from django.contrib import admin
from .models import Alert


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "threat_type",
        "severity",
        "risk_score",
        "status",
        "created_at",
    )

    list_filter = ("severity", "status", "created_at")
    search_fields = ("threat_type", "source_ip", "destination_ip")
    ordering = ("-created_at",)