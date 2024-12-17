from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from .models import ProfileModel
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ValidationError
from django.http import Http404
from .serializers import (
        SignUpSerializer, ProfileSerializer, VerifyUsernameSerializer,
        ChangePasswordSerializer, UsernameSendOTPSerializer, UserListSerializer,
        PasswordSignInSerializer, OTPSigninSerializer, UserInfoSerializer,
        DecodeTokenSerializer, RefreshTokenSerializer, LogoutSerializer
    )


class SignUpView(generics.CreateAPIView):
    serializer_class = SignUpSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code
            )

class VerifyUsernameView(APIView):
    serializer_class = VerifyUsernameSerializer

    def post(self, request):
        context = {
            'request':request
        }
        serializer = self.serializer_class(data=request.data, context=context)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            return Response(
                {'message': 'User verified username successfully'}, 
                status=200
            )
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code
            )


class UsernameSendOTPView(APIView):
    serializer_class = UsernameSendOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request":request})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"message":"send otp for you"}, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code 
            )
    

class OTPSigninView(APIView):
    serializer_class = OTPSigninSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request":request})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code
            )


class PasswordSigninView(APIView):
    serializer_class = PasswordSignInSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"request":request})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code
            )


class ChangePaswordView(APIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = []

    def put(self, request):
        context = {
            'request':request
        }
        serializer = self.serializer_class(data=request.data, context=context)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            return Response({'message': 'password change successfully'}, status=status.HTTP_200_OK)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code  
            )


class ProfileView(APIView):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = []

    def get(self, request):
        profile = get_object_or_404(ProfileModel, user=request.user)
        serializer = self.serializer_class(profile, context={"request":request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = self.serializer(data=request.data, context={"request":request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.errors, status=200)

    def put(self, request):
        profile = get_object_or_404(ProfileModel, user=request.user)
        serializer = self.serializer_class(profile, data=request.data, context={"request":request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.errors, status=200)

    def patch(self, request):
        profile = get_object_or_404(ProfileModel, user=request.user)
        serializer = self.serializer_class(profile, data=request.data, partial=True, context={"request":request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.errors, status=200)


class UserListView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserListSerializer
    authentication_classes = []

    def get(self, request):
        if request.user.access != 'NOR':
            objs = get_user_model().objects.all()
        else:
            raise Http404
        serializer = self.serializer_class(objs, many=True, context={"request":request})
        return Response(serializer.data, status=200)


class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserListSerializer
    authentication_classes = []

    def put(self, request, username=None):
        if request.user.is_admin or request.user.access == 'ADM':
            user = get_object_or_404(get_user_model, user__username=username)
        else:
            user = get_object_or_404(get_user_model, user__username=request.user.username, is_active=True)

        serializer = self.serializer_class(user, data=request.data, context={"request":request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.errors, status=200)


class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer
    authentication_classes = []

    def put(self, request, username=None):
        if request.user.is_admin or request.user.access == 'ADM':
            user = get_object_or_404(ProfileModel, user__username=username)
        else:
            user = get_object_or_404(ProfileModel, user__username=request.user.username, is_active=True)

        serializer = self.serializer_class(user, data=request.data, context={"request":request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.errors, status=200)
    

class DecodeView(APIView):
    serializer_class = DecodeTokenSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = []

    def get(self, request):
        serializer = self.serializer_class()
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            return Response({'message': 'password change successfully'}, status=status.HTTP_200_OK)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code  
            )

class SignOutView(APIView):
    """
    remove and delete token refresh from system for logout user
    """
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"message": "user sign out successfully"}, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            return Response(exc.detail, status=code)