
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated

User = get_user_model()


@api_view(["POST"])
def register_api(request):
    username = request.data.get("username", "").strip()
    email = request.data.get("email", "").strip()
    password = request.data.get("password", "")

    if not username or not password:
        return Response(
            {"error": "نام کاربری و رمز عبور الزامی هستند."},
            status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(username=username).exists():
        return Response(
            {"error": "این نام کاربری قبلاً ثبت شده است."},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        validate_password(password)
    except ValidationError as errors:
        return Response(
            {"error": list(errors.messages)},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password
    )

    token = Token.objects.create(user=user)

    return Response(
        {
            "message": "ثبت‌نام موفق بود.",
            "token": token.key,
            "username": user.username
        },
        status=status.HTTP_201_CREATED
    )


@api_view(["POST"])
def login_api(request):
    username = request.data.get("username", "").strip()
    password = request.data.get("password", "")

    user = authenticate(
        request,
        username=username,
        password=password
    )

    if user is None:
        return Response(
            {"error": "نام کاربری یا رمز عبور اشتباه است."},
            status=status.HTTP_401_UNAUTHORIZED
        )

    token, created = Token.objects.get_or_create(user=user)

    return Response({
        "message": "ورود موفق بود.",
        "token": token.key,
        "username": user.username
    })


@api_view(["POST"])
def logout_api(request):
    token_key = request.data.get("token", "")

    if token_key:
        Token.objects.filter(key=token_key).delete()

    return Response({"message": "خروج انجام شد."})

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def me_api(request):
    return Response({
        "username": request.user.username,
        "is_staff": request.user.is_staff,
    })
