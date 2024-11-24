import pytz
import bcrypt
from django.conf import settings
from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.response import Response
from random import randint
from drf_spectacular.utils import extend_schema
from .serializers import (
        SignupSerializer, OTPSingupVerifySerializer, OTPRequestSeriailizer,
        PasswordSinginSerializer, PasswordChangeSerializer, SignoutSerializer,
        RefreshTokenSerializer, GetUserSubSerializer, UserInfoSerializer
    )


class SignupView(APIView):
    """
    register user with username and password in to sso
    """
    serializer_class = SignupSerializer

    @extend_schema(request=SignupSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'username':'user created and go to enabled'}, status=201)
        else:
            return Response(serializer.errors, status=400)


class OTPSingupVerifyView(APIView):
    """
    verify username with otp 
    """
    serializer_class = OTPSingupVerifySerializer

    @extend_schema(request=OTPSingupVerifySerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request":request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'account complete validation'}, status=200)
        else:
            return Response(serializer.errors, status=400)


class OTPRequestView(APIView):
    """
    - send otp for user - this view use for verify username 
    - change password and etc 
    - everywhen need to send otp for username 
    """
    serializer_class = OTPRequestSeriailizer

    @extend_schema(request=OTPRequestSeriailizer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request':request})
        if serializer.is_valid():
            return Response({'message': 'otp set for this device'}, status=200)
        else:
            return Response(serializer.errors, status=400)


'''
class OTPPasswordChangeVerifyView(APIView):
    """
    befor change password user need to verify otp 
    """
    serializer_class = PasswordChangeVerifySerializer

    @extend_schema(request=PasswordChangeVerifySerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request':request})
        if serializer.is_valid():
            return Response({'message':'go to change password'}, status=200)
        else:
            return Response(serializer.errors, status=400)
'''


class PasswordChangeView(APIView):
    """
    - change password with send new password 
    """
    serializer_class = PasswordChangeSerializer

    @extend_schema(request=PasswordChangeSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request":request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'password change successfully'}, status=200)
        else:
            return Response(serializer.errors, status=400)
        

class PasswordSigninView(APIView):
    """
    login user and get token access and refresh  
    """
    serializer_class = PasswordSinginSerializer

    @extend_schema(request=PasswordSinginSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            srz = serializer.save()
            return Response({'access_token':srz['access_token'], 'refresh_token':srz['refresh_token']}, status=200)
        else:
            return Response(serializer.errors, status=400)        


class SignoutView(APIView):
    """
    remove and delete token refresh from system for logout user
    """
    serializer_class = SignoutSerializer

    @extend_schema(request=SignoutSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            srz = serializer.save()
            return Response({"message":"user sign out successfully"}, status=200)
        else:
            return Response(serializer.errors, status=400)
        

class UserinfoView(APIView):
    """
    get user info from keycloak for authorizations
    """
    serializer_class = UserInfoSerializer

    @extend_schema(request=UserInfoSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            srz = serializer.save()
            return Response(srz, status=200)
        else:
            return Response(serializer.errors, status=400)
        

class RefreshTokenView(APIView):
    """
    get and update token access 
    """
    serializer_class = RefreshTokenSerializer

    @extend_schema(request=RefreshTokenSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            srz = serializer.save()
            return Response({'access_token':srz['access_token'],'referesh_token':srz['refresh_token']}, status=200)
        else:
            return Response(serializer.errors, status=400)
        

class DecodeTokenView(APIView):
    """
    get information comlete about token and user
    """
    serializer_class = GetUserSubSerializer

    @extend_schema(request=GetUserSubSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            srz = serializer.save()
            return Response(srz, status=200)
        else:
            return Response(serializer.errors, status=400)
