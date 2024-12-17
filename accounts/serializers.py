import random
import json
import datetime
import re
from django.core.cache import cache
from datetime import datetime
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .tasks import otp_phone_sender, otp_email_sender
from django.shortcuts import get_object_or_404
from .models import ProfileModel
from django.contrib.auth import authenticate
from .service import UserKeyCloak, TokenKeycloak



User = get_user_model()


def valid_username(username):
    phone = re.match(r'^([+]?\d{1,2}[-\s]?|)\d{3}[-\s]?\d{3}[-\s]?\d{4}$', username)
    email = re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', username)
    return phone, email


class SignUpSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    password_confierm = serializers.CharField(required=True)

    def validate_password(self, password):
        """
        Validates that the password meets the following criteria:
        - At least 8 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 2 digits
        - At least 1 special character
        """
        if len(password) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )
        if not re.search(r"[A-Z]", password):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[a-z]", password):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )
        if len(re.findall(r"\d", password)) < 2:
            raise serializers.ValidationError(
                "Password must contain at least two numbers."
            )
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise serializers.ValidationError(
                "Password must contain at least one special character."
            )
        return password

    def validate(self, attrs):
        keycloak = UserKeyCloak()
        if keycloak.check_connect() == 500:
            raise serializers.ValidationError({"message": "Server not found"}, code=500)

        phone, email = valid_username(attrs['username'])
        if not phone and not email:
            raise serializers.ValidationError({"username":"phone or email is not correct"}, code=400)
        
        user = User.objects.filter(username=attrs['username'])
        if user.exists():
            raise serializers.ValidationError({"user": "user is exsits"}, code=401)
        
        if attrs['password'] != attrs['password_confierm']:
            raise serializers.ValidationError({"password":"Passwords is not match."}, code=404)
        
        return attrs

    def create(self, validated_data):
        keycloak = UserKeyCloak()
        phone, email = valid_username(validated_data['username'])
        user = User.objects.filter(username=validated_data['username']).first()
        if user:
            # Update password for the existing user
            if keycloak.check_enable() == 404:
                raise serializers.ValidationError(
                    {"message": "user not available calling with admin"}, code=403
                )
            if user.check_email_verify() == 404:
                raise serializers.ValidationError(
                    {"message": "please call with admin"}, code=401
                )
            user.set_password(validated_data['password'])
            user.save()
        else:
            user = User.objects.create_user(
                username=validated_data['username'],
                password=validated_data['password'],
            )
            user.save()
            keycloak.username = validated_data["username"]
            keycloak.password = validated_data["password"]
            if phone:
                keycloak.create_phone()
            if email:
                keycloak.create_email()

        otp = random.randint(111111, 999999)
        print("===>", otp)
        cache.set(
            f"otp_{validated_data['username']}",
            json.dumps(
                {"otp": otp, "retries": 0, "created_at": datetime.now().isoformat()}
            ),
            timeout=10 * 60,
        )

        if phone:
            otp_phone_sender(user.otp, user.username)
        if email:
            otp_email_sender(user.otp, user.username)

        return user


class PasswordSignInSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, write_only=True)
    password = serializers.CharField(required=True, write_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)

    def validate(self, attrs):
        keycloak = UserKeyCloak()
        keycloak.username = attrs['username']
        
        user = authenticate(username=attrs['username'], password=attrs['password'])
        if not user:
            raise serializers.ValidationError({"error": "Invalid credentials"}, code=401)

        if keycloak.check_connect() == 500:
            raise serializers.ValidationError({"message": "Server not found"}, code=500)

        if keycloak.check_enable() == 404:
            raise serializers.ValidationError(
                {"message": "user not available calling with admin"}, code=403
            )
        if keycloak.check_email_verify() == 404:
            raise serializers.ValidationError(
                {"message": "please call with admin"}, code=401
            )
        
        return attrs

    def create(self, validated_data):
        tokenkeycloak = TokenKeycloak()
        tokenkeycloak.username = validated_data["username"]
        tokenkeycloak.password = validated_data["password"]
        token_info = tokenkeycloak.get_token()
        if token_info in [404, 500]:
            raise serializers.ValidationError(
                {"message": "service authentications error"}, code=500
            )
        return {
            "access_token": '',
            "refresh_token": '',
        }


class VerifyUsernameSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    otp = serializers.IntegerField(required=True)

    def validate(self, attrs):
        keycloak = UserKeyCloak()
        if keycloak.check_connect() == 500:
            raise serializers.ValidationError({"message": "Server not found"}, code=500)

        user = User.objects.filter(username=attrs['username'], is_active=True).first()
        if not user:
            raise serializers.ValidationError({'user': 'User does not exist or is inactive.'}, code=403)

        cached_otp = json.loads(cache.get(f"otp_{user.username}", {}))
        if not cached_otp:
            raise serializers.ValidationError(
                {"message": "otp not found or is expired."}, code=404
            )

        if cached_otp.get("retries") >= 5:
            raise serializers.ValidationError(
                {"message": "you have reached the maximum number of attempts."},
                code=429,
            )

        if cached_otp.get("otp") != attrs["otp"]:
            cached_otp["retries"] += 1
            time_from_creation = datetime.now() - cached_otp.get("created_at")
            cache.set(
                f"otp_{attrs['username']}",
                json.dumps(cached_otp),
                timeout=time_from_creation.seconds,
            )
            raise serializers.ValidationError(
                {"message": "otp is not correct"}, code=401
            )
        
        return attrs

    def create(self, validated_data):
        keycloak = UserKeyCloak()
        user = User.objects.get(username=validated_data['username'])
        user.is_active = True
        user.save()
        keycloak.username = validated_data["username"]
        keycloak.email_verified()
        return user
    

class OTPSigninSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, write_only=True)
    otp = serializers.IntegerField(required=True, write_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)
    token_type = serializers.CharField(read_only=True)
    expires_in = serializers.CharField(read_only=True)

    def validate(self, attrs):
        keycloak = UserKeyCloak()
        keycloak.username = attrs['username']

        user = User.objects.filter(username=attrs['username'], is_active=True).first()
        if not user:
            raise serializers.ValidationError({'username': 'User does not exist or is inactive.'}, code=403)

        otp = cache.get(f"otp_{attrs['username']}", {})
        if otp:
            otp = json.loads(otp)
        else:
            raise serializers.ValidationError(
                {"message": "otp not found or is expired."}, code=404
            )
        if keycloak.check_connect() == 500:
            raise serializers.ValidationError({"message": "server not found"}, code=500)
        if keycloak.check_email_verify() == 404:
            raise serializers.ValidationError(
                {"message": "please first verified username"}, code=401
            )
        if user.check_enable() == 404:
            raise serializers.ValidationError(
                {"message": "user not available calling with admin"}, code=403
            )

        if not otp:
            raise serializers.ValidationError(
                {"message": "otp not found or is expired."}, code=404
            )
        if otp.get("retries") >= 5:
            raise serializers.ValidationError(
                {"message": "you have reached the maximum number of attempts."},
                code=429,
            )
        if otp.get("otp") != attrs["otp"]:
            otp["retries"] += 1
            time_from_creation = datetime.now() - otp.get("created_at")
            cache.set(
                f"otp_{attrs['username']}",
                json.dumps(otp),
                timeout=time_from_creation.seconds,
            )
            raise serializers.ValidationError(
                {"message": "otp is not correct"}, code=401
            )
        cache.delete(f"otp_{attrs['username']}")

        return attrs

    def create(self, validated_data):
        token = UserKeyCloak()
        # Generate tokens
        token.username = validated_data["username"]
        token_info = token.get_token()
        return {
            "access_token": '',
            "refresh_token": '',
        }


class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    password_confierm = serializers.CharField(required=True)

    def validate_password(self, password):
        """
        Validates that the password meets the following criteria:
        - At least 8 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 2 digits
        - At least 1 special character
        """
        if len(password) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )
        if not re.search(r"[A-Z]", password):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[a-z]", password):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )
        if len(re.findall(r"\d", password)) < 2:
            raise serializers.ValidationError(
                "Password must contain at least two numbers."
            )
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise serializers.ValidationError(
                "Password must contain at least one special character."
            )
        return password
    
    def validate(self, attrs):
        keycloak = UserKeyCloak()
        user = User.objects.filter(id=self.context['request'].user.id, is_active=True).first()

        if not user:
            raise serializers.ValidationError({"user":"user is not exsits"}, code=401)
        if attrs['password'] != attrs['password_confierm']:
            raise serializers.ValidationError({"password":"Passwords is not match."}, code=400)
        
        if keycloak.check_enable() == 404:
            raise serializers.ValidationError(
                {"message": "user not available calling with admin"}, code=403
            )
        if keycloak.check_email_verify() == 404:
            raise serializers.ValidationError(
                {"message": "please call with admin"}, code=401
            )
        
        return attrs
        
    def create(self, validated_data):
        user = User.objects.get(id=self.context['request'].user.id)
        # Update password for the existing user
        user.set_password(validated_data['password'])
        user.save()
        keycloak = UserKeyCloak()
        keycloak.username = validated_data["username"]
        keycloak.password = validated_data['password']
        keycloak.change_password()
        return user


class UsernameSendOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', )

    def validate(self, attrs):
        keycloak = UserKeyCloak()
        phone, email = valid_username(attrs['username'])
        if not phone and not email:
            raise serializers.ValidationError({"username":"phone or email is not correct"}, code=400)
        user = get_object_or_404(User, username=attrs['username'], is_active=True)
        
        if keycloak.check_enable() == 404:
            raise serializers.ValidationError(
                {"message": "user not available calling with admin"}, code=403
            )
        if keycloak.check_email_verify() == 404:
            raise serializers.ValidationError(
                {"message": "please call with admin"}, code=401
            )
        
        return attrs
    
    def create(self, validated_data):
        phone, email = valid_username(validated_data['username'])
        otp = random.randint(111111, 999999)
        print("===>", otp)
        cache.set(
            f"otp_{validated_data['username']}",
            json.dumps(
                {"otp": otp, "retries": 0, "created_at": datetime.now().isoformat()}
            ),
            timeout=10 * 60,
        )
        if phone:
            otp_phone_sender(otp, validated_data['username'])
        if email:
            otp_email_sender(otp, validated_data['username'])
        return validated_data


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfileModel
        exclude = ('user', )

    def validate(self, data):
        user_type = data.get('user_type')

        # If user_type is ORGANIZATION, national_id is required
        if user_type == ProfileModel.ORGANIZATION and not data.get('national_id'):
            raise serializers.ValidationError({
                'national_id': 'This field is required when the user is an organization.'
            }, code=400)

        # If user_type is INVOLVED, last_name is required
        if user_type == ProfileModel.INVOLVED and not data.get('last_name'):
            raise serializers.ValidationError({
                'last_name': 'This field is required when the user is involved.'
            }, code=400)

        return data

    def update(self, instance, validated_data):
        # Prevent updating user_type field
        validated_data.pop('user_type', None)  # Remove user_type if present in validated_data

        return super().update(instance, validated_data)


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'is_active', 'is_admin', 'is_staff', 'access')


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfileModel
        fields = '__all__'


class TokenBaseSerializer(serializers.Serializer):
    def create(self, validated_data):
        keycloak = TokenKeycloak()
        if keycloak.check_connect() == 500:
            raise serializers.ValidationError(
                {"message": "service authentications error"}, code=500
            )
        return validated_data
    

class UserInfoSerializer(TokenBaseSerializer):
    access_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        information = TokenKeycloak()
        information.token = validated_data["access_token"]
        user_info = information.user_info()
        if user_info == 404:
            raise serializers.ValidationError(
                {"message": "token dos not validate"}, code=404
            )
        return user_info
    

class RefreshTokenSerializer(TokenBaseSerializer):
    refresh_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        refresh_token = TokenKeycloak()
        refresh_token.token = validated_data["refresh_token"]
        refresh_token = refresh_token.refresh_token()
        if refresh_token in [404, 500]:
            raise serializers.ValidationError(
                {"message": "token dos not validate"}, code=404
            )
        return refresh_token
    

class DecodeTokenSerializer(TokenBaseSerializer):
    access_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        decode_token = TokenKeycloak()
        decode_token.token = validated_data["access_token"]
        information = decode_token.decode_token()
        if information in [404, 500]:
            raise serializers.ValidationError(
                {"message": "token dos not validate"}, code=404
            )
        return information
    

class LogoutSerializer(TokenBaseSerializer):
    refresh_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        logout = TokenKeycloak()
        logout.token = validated_data["refresh_token"]
        logout_response = logout.logout()
        if logout_response == 404:
            raise serializers.ValidationError(
                {"message": "token dos not validate"}, code=500
            )
        return validated_data["refresh_token"]