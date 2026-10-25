
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

User = get_user_model()


@api_view(["POST"])
@permission_classes([AllowAny])
def register_api(request):
    username = str(request.data.get("username", "")).strip()
    email = str(request.data.get("email", "")).strip()
    password = request.data.get("password", "")

    if not username or not password:
        return Response(
            {"error": "نام کاربری و رمز عبور الزامی هستند."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if len(username) > 150:
        return Response(
            {"error": "نام کاربری نباید بیشتر از ۱۵۰ کاراکتر باشد."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if User.objects.filter(username__iexact=username).exists():
        return Response(
            {"error": "این نام کاربری قبلاً ثبت شده است."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if email and User.objects.filter(email__iexact=email).exists():
        return Response(
            {"error": "این ایمیل قبلاً ثبت شده است."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        validate_password(password)
    except ValidationError as errors:
        return Response(
            {"error": list(errors.messages)},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
    )

    token = Token.objects.create(user=user)

    return Response(
        {
            "message": "ثبت‌نام موفق بود.",
            "token": token.key,
            "username": user.username,
            "is_staff": user.is_staff,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_api(request):
    username = str(request.data.get("username", "")).strip()
    password = request.data.get("password", "")

    if not username or not password:
        return Response(
            {"error": "نام کاربری و رمز عبور را وارد کنید."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = authenticate(
        request,
        username=username,
        password=password,
    )

    if user is None:
        return Response(
            {"error": "نام کاربری یا رمز عبور اشتباه است."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    token, _ = Token.objects.get_or_create(user=user)

    return Response({
        "message": "ورود موفق بود.",
        "token": token.key,
        "username": user.username,
        "is_staff": user.is_staff,
    })


@api_view(["POST"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout_api(request):
    request.user.auth_token.delete()

    return Response({
        "message": "خروج با موفقیت انجام شد."
    })


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def me_api(request):
    return Response({
        "username": request.user.username,
        "email": request.user.email,
        "is_staff": request.user.is_staff,
    })
