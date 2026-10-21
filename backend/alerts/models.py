
from django.db import models
from django.conf import settings


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    ]

    user = models.ForeignKey(
    settings.AUTH_USER_MODEL,
    on_delete=models.CASCADE,
    related_name="alerts",
    null=True,
    blank=True
    )

    STATUS_CHOICES = [
        ("New", "New"),
        ("Analyzed", "Analyzed"),
        ("Resolved", "Resolved"),
    ]

    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
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
