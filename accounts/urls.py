from django.urls import path
from .views import (
    SignupView,
    OTPSingUpVerifyView,
    OTPRequestView,
    PasswordSigninView,
    PasswordChangeView,
    SigninOTPView,
    SignOutView,
    UserinfoView,
    RefreshTokenView,
    DecodeTokenView,
)

urlpatterns = [
    path("signup/", SignupView.as_view()),
    path("signup/otp/verify/", OTPSingUpVerifyView.as_view()),
    path("request/otp/", OTPRequestView.as_view()),
    path("signin/password/", PasswordSigninView.as_view()),
    path("signin/otp/", SigninOTPView.as_view()),
    path("password/change/", PasswordChangeView.as_view()),
    path("signout/", SignOutView.as_view()),
    path("user/information/", UserinfoView.as_view()),
    path("refresh/token/", RefreshTokenView.as_view()),
    path("decode/token/", DecodeTokenView.as_view()),
]
