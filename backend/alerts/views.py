
import ipaddress

from rest_framework import status as http_status
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from .models import Alert


def analyze_threat(threat_type, description):
    text = f"{threat_type} {description}".lower()

    rules = [
        (
            95,
            "Critical",
            [
                "ransomware",
                "zero-day",
                "privilege escalation",
                "باج افزار",
                "روز صفر",
                "افزایش سطح دسترسی",
            ],
            "نشانه‌ای با ریسک بسیار بالا شناسایی شد.",
            "فعالیت را بررسی کنید، دسترسی‌های مشکوک را محدود کنید "
            "و با مسئول امنیت شبکه تماس بگیرید.",
        ),
        (
            75,
            "High",
            [
                "network scan",
                "port scan",
                "malware",
                "unauthorized access",
                "suspicious",
                "اسکن شبکه",
                "اسکن پورت",
                "بدافزار",
                "دسترسی غیرمجاز",
                "مشکوک",
            ],
            "نشانه‌هایی از فعالیت مشکوک شناسایی شد.",
            "منبع فعالیت را بررسی کنید و گزارش‌های امنیتی را "
            "برای تأیید رخداد بازبینی کنید.",
        ),
        (
            45,
            "Medium",
            [
                "unusual",
                "anomaly",
                "reconnaissance",
                "غیرعادی",
                "ناهنجاری",
                "شناسایی شبکه",
            ],
            "فعالیت ممکن است غیرعادی باشد و نیاز به بررسی بیشتر دارد.",
            "رفتار معمول شبکه را با این فعالیت مقایسه کنید "
            "و در صورت تکرار، بررسی دقیق‌تری انجام دهید.",
        ),
    ]

    for score, severity, keywords, analysis, recommendation in rules:
        if any(keyword in text for keyword in keywords):
            return {
                "risk_score": score,
                "severity": severity,
                "analysis": analysis,
                "recommendation": recommendation,
            }

    return {
        "risk_score": 10,
        "severity": "Low",
        "analysis": "بر اساس قوانین ساده این نسخه، نشانه شناخته‌شده‌ای "
                    "از ریسک بالا شناسایی نشد.",
        "recommendation": "در صورت وجود نگرانی، اطلاعات تکمیلی و "
                          "گزارش‌های شبکه را بررسی کنید.",
    }


def visible_alerts(user):
    if user.is_staff:
        return Alert.objects.all()
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


@api_view(["POST"])
@permission_classes([AllowAny])
def alerts_api(request):
    mode = request.data.get("mode", "ip")
    source_ip = request.data.get("source_ip")
    destination_ip = request.data.get("destination_ip")
    threat_type = str(request.data.get("threat_type", "")).strip()
    description = str(request.data.get("description", "")).strip()

    if mode not in ("ip", "text"):
        return Response(
            {"error": "روش تحلیل معتبر نیست."},
            status=http_status.HTTP_400_BAD_REQUEST,
        )

    if mode == "ip":
        if not source_ip or not destination_ip or not threat_type:
            return Response(
                {"error": "IP مبدأ، IP مقصد و نوع فعالیت الزامی هستند."},
                status=http_status.HTTP_400_BAD_REQUEST,
            )

        try:
            source_ip = str(ipaddress.ip_address(source_ip))
            destination_ip = str(ipaddress.ip_address(destination_ip))
        except ValueError:
            return Response(
                {"error": "یکی از آدرس‌های IP معتبر نیست."},
                status=http_status.HTTP_400_BAD_REQUEST,
            )

    else:
        if len(description) < 10:
            return Response(
                {"error": "توضیح فعالیت باید حداقل ۱۰ نویسه باشد."},
                status=http_status.HTTP_400_BAD_REQUEST,
            )

        if len(description) > 5000:
            return Response(
                {"error": "متن بیش از حد طولانی است؛ حداکثر ۵۰۰۰ نویسه."},
                status=http_status.HTTP_400_BAD_REQUEST,
            )

        source_ip = None
        destination_ip = None
        threat_type = threat_type or "Text Analysis"

    if len(threat_type) > 100:
        return Response(
            {"error": "نوع فعالیت بیش از حد طولانی است."},
            status=http_status.HTTP_400_BAD_REQUEST,
        )

    result = analyze_threat(threat_type, description)

    alert = Alert.objects.create(
        user=(
            request.user
            if request.user.is_authenticated
            else None
        ),
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
