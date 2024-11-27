from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from rest_framework.exceptions import ValidationError
from .serializers import (
        SignupSerializer, OTPSingupVerifySerializer, OTPRequestSeriailizer,
        PasswordSinginSerializer, PasswordChangeSerializer, SignoutSerializer,
        RefreshTokenSerializer, GetUserSubSerializer, UserInfoSerializer,
        OTPSigninSerializer
    )


class SignupView(APIView):
    """
    register user with username and password in to sso
    """
    serializer_class = SignupSerializer

    @extend_schema(request=SignupSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
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


class OTPSingupVerifyView(APIView):
    """
    verify username with otp 
    """
    serializer_class = OTPSingupVerifySerializer

    @extend_schema(request=OTPSingupVerifySerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request":request})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'message':'account complete validation'}, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code 
            )


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
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'message': 'otp set for this device'}, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code 
            )



class SigninOTPView(APIView):
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


class PasswordChangeView(APIView):
    """
    - change password with send new password 
    """
    serializer_class = PasswordChangeSerializer

    @extend_schema(request=PasswordChangeSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request":request})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'message':'password change successfully'}, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code 
            )
        

class PasswordSigninView(APIView):
    """
    login user and get token access and refresh  
    """
    serializer_class = PasswordSinginSerializer

    @extend_schema(request=PasswordSinginSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
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


class SignoutView(APIView):
    """
    remove and delete token refresh from system for logout user
    """
    serializer_class = SignoutSerializer

    @extend_schema(request=SignoutSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"message":"user sign out successfully"}, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code 
            )
        

class UserinfoView(APIView):
    """
    get user info from keycloak for authorizations
    """
    serializer_class = UserInfoSerializer

    @extend_schema(request=UserInfoSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
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

        

class RefreshTokenView(APIView):
    """
    get and update token access 
    """
    serializer_class = RefreshTokenSerializer

    @extend_schema(request=RefreshTokenSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'access_token':srz['access_token'],'referesh_token':srz['refresh_token']}, status=200)
        except ValidationError as exc:
            error_codes = exc.get_codes() or 400
            code = next(iter(error_codes.values()))[0] if error_codes else 400
            print(code)
            return Response(
                exc.detail, 
                status=code 
            )

        

class DecodeTokenView(APIView):
    """
    get information comlete about token and user
    """
    serializer_class = GetUserSubSerializer

    @extend_schema(request=GetUserSubSerializer)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
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
