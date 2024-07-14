from django.urls import path
from .views import (
        SignupView, OTPSingnupVerifyView, OTPRequestView,
        PasswordSigninView, PasswordChangeView, OTPPasswordChangeVerifyView,
        SignoutView, UserinfoView, RefreshTokenView, DecodeTokenView,
        #TestView
    )

urlpatterns = [
    path('signup/', SignupView.as_view()),
    path('signup/otp/verify/', OTPSingnupVerifyView.as_view()),
    path('request/otp/', OTPRequestView.as_view()),
    path('signin/password/', PasswordSigninView.as_view()),
    path('password/otp/verify/', OTPPasswordChangeVerifyView.as_view()),
    path('password/change/', PasswordChangeView.as_view()),
    path('signout/', SignoutView.as_view()),
    path('user/information/', UserinfoView.as_view()),
    path('refresh/token/', RefreshTokenView.as_view()),
    path('decode/token/', DecodeTokenView.as_view()),

    # path('index/', TestView.as_view()),
]

