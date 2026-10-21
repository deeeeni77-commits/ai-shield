
from django.utils import timezone

from rest_framework import status as http_status
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Alert


def analyze_threat(threat_type, description):
    text = f"{threat_type} {description}".lower()

    critical_words = [
        "ransomware", "zero-day", "privilege escalation",
        "باج افزار", "روز صفر", "افزایش سطح دسترسی",
    ]
    high_words = [
        "network scan", "port scan", "malware",
        "unauthorized access", "suspicious",
        "اسکن شبکه", "اسکن پورت", "بدافزار",
        "دسترسی غیرمجاز", "مشکوک",
    ]
    medium_words = [
        "unusual", "anomaly", "reconnaissance",
        "غیرعادی", "ناهنجاری", "شناسایی شبکه",
    ]

    if any(word in text for word in critical_words):
        return {
            "risk_score": 95,
            "severity": "Critical",
            "analysis": "نشانه‌هایی از تهدید بسیار جدی شناسایی شد.",
            "recommendation": "موضوع را فوراً بررسی کنید و از متخصص امنیت کمک بگیرید.",
        }

    if any(word in text for word in high_words):
        return {
            "risk_score": 75,
            "severity": "High",
            "analysis": "نشانه‌هایی از فعالیت مشکوک یا پرخطر مشاهده شد.",
            "recommendation": "منبع فعالیت را بررسی کنید و دسترسی‌های غیرضروری را محدود کنید.",
        }

    if any(word in text for word in medium_words):
        return {
            "risk_score": 45,
            "severity": "Medium",
            "analysis": "فعالیتی غیرمعمول مشاهده شده که نیاز به بررسی دارد.",
            "recommendation": "جزئیات فعالیت را بررسی و در صورت تکرار پیگیری کنید.",
        }

    return {
        "risk_score": 10,
        "severity": "Low",
        "analysis": "بر اساس قوانین ساده فعلی، نشانه‌ی مشخصی از تهدید جدی پیدا نشد.",
        "recommendation": "به پایش امنیتی ادامه دهید.",
    }


def visible_alerts(user):
    # ادمین می‌تواند همه هشدارها را ببیند.
    if user.is_staff:
        return Alert.objects.all()

    # کاربران عادی فقط هشدارهای خودشان را می‌بینند.
    return Alert.objects.filter(user=user)


def alert_to_dict(alert):
    return {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "threat_type": alert.threat_type,
        "description": alert.description,
        "risk_score": alert.risk_score,
        "severity": alert.severity,
        "analysis": alert.analysis,
        "recommendation": alert.recommendation,
        "status": alert.status,
        "created_at": alert.created_at.isoformat(),
    }


@api_view(["GET", "POST"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def alerts_api(request):
    if request.method == "GET":
        alerts = visible_alerts(request.user)
        results = [alert_to_dict(alert) for alert in alerts]

        return Response({
            "count": len(results),
            "results": results,
        })

    source_ip = request.data.get("source_ip")
    destination_ip = request.data.get("destination_ip")
    threat_type = request.data.get("threat_type")
    description = request.data.get("description", "")

    if not source_ip or not destination_ip or not threat_type:
        return Response(
            {"error": "آی‌پی مبدأ، آی‌پی مقصد و نوع تهدید الزامی هستند."},
            status=http_status.HTTP_400_BAD_REQUEST,
        )

    result = analyze_threat(threat_type, description)

    alert = Alert.objects.create(
        user=request.user,
        source_ip=source_ip,
        destination_ip=destination_ip,
        threat_type=threat_type,
        description=description,
        risk_score=result["risk_score"],
        severity=result["severity"],
        analysis=result["analysis"],
        recommendation=result["recommendation"],
        status="Analyzed",
    )

    return Response(
        alert_to_dict(alert),
        status=http_status.HTTP_201_CREATED,
    )


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def dashboard_api(request):
    alerts = visible_alerts(request.user)

    recent_alerts = [
        {
            "id": alert.id,
            "threat_type": alert.threat_type,
            "risk_score": alert.risk_score,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "created_at": alert.created_at.isoformat(),
        }
        for alert in alerts[:10]
    ]

    return Response({
        "total_alerts": alerts.count(),
        "critical_alerts": alerts.filter(severity="Critical").count(),
        "high_alerts": alerts.filter(severity="High").count(),
        "medium_alerts": alerts.filter(severity="Medium").count(),
        "low_alerts": alerts.filter(severity="Low").count(),
        "recent_alerts": recent_alerts,
    })
