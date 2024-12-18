from django.urls import path
from .views import (
        SignUpView, VerifyUsernameView, OTPSigninView,
        ChangePaswordView, ProfileView, UserListView,
        UserUpdateView, ProfileUpdateView, PasswordSigninView, 
        UsernameSendOTPView
    )


urlpatterns = [
    path('signup/', SignUpView.as_view(), name='register'),
    path('verify/username/', VerifyUsernameView.as_view(), name='register'),
    path('otp/signin/', OTPSigninView.as_view(), name='register'),
    path('password/signin/', PasswordSigninView.as_view(), name='register'),
    path('change/password/', ChangePaswordView.as_view(), name='register'),
    path('send/OTP/', UsernameSendOTPView.as_view()),
    path('profile/', ProfileView.as_view()),
    path('user/list/', UserListView.as_view()),
    path('profile/update/<str:username>/', ProfileUpdateView.as_view()),
]

