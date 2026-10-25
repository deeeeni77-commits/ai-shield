from django.db import models
from django.conf import settings


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    ]

    STATUS_CHOICES = [
        ("New", "New"),
        ("Analyzed", "Analyzed"),
        ("Resolved", "Resolved"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="alerts",
        null=True,
        blank=True,
    )

    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
    )
    destination_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    threat_type = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="Low",
    )
    analysis = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="New",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.threat_type} - {self.severity}"