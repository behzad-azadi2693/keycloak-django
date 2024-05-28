import pytz
import bcrypt
from django.conf import settings
from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .authentication import KeycloakAuthentication
from rest_framework.response import Response
from random import randint
from drf_spectacular.utils import extend_schema
from .serializers import (
        SignupSerializer, OTPSingnupVerifySerializer, OTPRequestSeriailizer,
        OTPSigninSerializer, PasswordSinginSerializer, PasswordChangeSerializer,
        OTPPasswordChangeVerifySerializer, SignoutSerializer, UserInfoSerializer,
        RefreshTokenSerializer, DecodeTokenSerializer
    )


class SignupView(APIView):
    serializer_class = SignupSerializer

    @extend_schema(request=SignupSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'username':'user created and go to enabled'}, status=201)
        else:
            return Response(serializer.errors, status=400)


class OTPSingnupVerifyView(APIView):
    serializer_class = OTPSingnupVerifySerializer

    @extend_schema(request=OTPSingnupVerifySerializer)
    def post(self, request):
        context = {
            'otp': request.session.get('OTP_ITS'),
            'time':  request.session.get('OTP_ITS_TIME'),
            'count':  request.session.get('OTP_ITS_COUNT'),
            'username':  request.session.get('ITS_USERNAME'),
            'request': request
        }
        serializer = self.serializer_class(data=request.data, context=context)
        if serializer.is_valid():
            serializer.save()
            request.session.flush()
            return Response({'message':'account complete validation'}, status=200)
        else:
            return Response(serializer.errors, status=400)


class OTPRequestView(APIView):
    serializer_class = OTPRequestSeriailizer

    @extend_schema(request=OTPRequestSeriailizer)
    def post(self, request):
        otp = randint(10000, 99999)
        serializer = self.serializer_class(data=request.data, context={'otp':otp})
        if serializer.is_valid():
            print('========OTP=========', f"{otp}+{settings.VALUE_HASH}")
            request.session['OTP_ITS'] = bcrypt.hashpw(f"{otp}+{settings.VALUE_HASH}".encode(), bcrypt.gensalt(14)).decode()
            request.session['OTP_ITS_TIME'] = datetime.now().astimezone(pytz.timezone('Asia/Tehran')).isoformat()
            request.session['OTP_ITS_COUNT'] = 0
            request.session['ITS_USERNAME'] = serializer.data['username']
            return Response({'message': 'otp set for this device'}, status=200)
        else:
            return Response(serializer.errors, status=400)


class OTPPasswordChangeVerifyView(APIView):
    serializer_class = OTPPasswordChangeVerifySerializer

    @extend_schema(request=OTPPasswordChangeVerifySerializer)
    def post(self, request):
        context = {
            'otp': request.session.get('OTP_ITS'),
            'time':  request.session.get('OTP_ITS_TIME'),
            'count':  request.session.get('OTP_ITS_COUNT'),
            'username':  request.session.get('ITS_USERNAME'),
            'request': request
        }
        serializer = self.serializer_class(data=request.data, context=context)
        if serializer.is_valid():
            username = serializer.data['username']
            request.session.flush()
            request.session['ITS_USERNAME'] = username
            request.session['ITS_CHANGE_PASSWORD'] = True
            request.session['ITS_CHANGE_PASSWORD_TIME'] = datetime.now().astimezone(pytz.timezone('Asia/Tehran')).isoformat()
            return Response({'message':'go to change password'}, status=200)
        else:
            return Response(serializer.errors, status=400)


class PasswordChangeView(APIView):
    serializer_class = PasswordChangeSerializer

    @extend_schema(request=PasswordChangeSerializer)
    def post(self, request):
        context = {
            'change': request.session.get('ITS_CHANGE_PASSWORD', None),
            'time':  request.session.get('ITS_CHANGE_PASSWORD_TIME', None),
            'username':  request.session.get('ITS_USERNAME', None),
        }
        serializer = self.serializer_class(data=request.data, context=context)
        if serializer.is_valid():
            serializer.save()
            request.session.flush()
            return Response({'message':'password change successfully'}, status=200)
        else:
            return Response(serializer.errors, status=400)
        

class PasswordSigninView(APIView):
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
    serializer_class = DecodeTokenSerializer

    @extend_schema(request=DecodeTokenSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            srz = serializer.save()
            return Response(srz, status=200)
        else:
            return Response(serializer.errors, status=400)
        
'''

class OTPSigninView(APIView):
    serializer_class = OTPSigninSerializer

    @extend_schema(request=OTPSigninSerializer)
    def post(self, request):
        context = {
            'otp': request.session.get('OTP_ITS'),
            'time':  request.session.get('OTP_ITS_TIME'),
            'count':  request.session.get('OTP_ITS_COUNT'),
            'username':  request.session.get('ITS_USERNAME'),
            'request': request
        }
        serializer = self.serializer_class(data=request.data, context=context)
        if serializer.is_valid():
            """
            back token
            """
            return Response({}, status=200)
        else:
            return Response(serializer.errors, status=400)


class TestView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'msg': 'request'} , status=200)
'''