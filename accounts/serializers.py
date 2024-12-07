import re
import string

import pytz
import bcrypt
import random
import json
from django.conf import settings
from django.core.cache import cache
from datetime import datetime, timedelta
from rest_framework import serializers
from .service import UserKeyCloak, TokenKeycloak
from django.utils.timezone import make_naive
from .tasks import otp_email_sender, otp_phone_sender


def valid_phone_email(username):
    phone = re.match(r'^([+]?\d{1,2}[-\s]?|)\d{3}[-\s]?\d{3}[-\s]?\d{4}$', username)
    email = re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', username)
    return phone, email


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    password_confirm = serializers.CharField(required=True)

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
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if len(re.findall(r'\d', password)) < 2:
            raise serializers.ValidationError("Password must contain at least two numbers.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return password

    def validate(self, attrs):
        user = UserKeyCloak()
        user.username = attrs['username']
        phone, email = valid_phone_email(attrs['username'])

        # Check server connectivity
        if user.check_connect() == 500:
            raise serializers.ValidationError({'message': 'Server not found'}, code=500)

        # Check if user already exists
        if user.check_email_verify() == 200:
            raise serializers.ValidationError({'username': 'User already exists'}, code=403)

        # Check if passwords match
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password_confirm': 'Passwords do not match'}, code=401)

        # Validate password strength
        self.validate_password(attrs['password'])

        # Validate username
        if phone or email:
            return attrs
        else:
            raise serializers.ValidationError({'username': 'Username is not correct'}, code=403)

    def create(self, validated_data):
        print(validated_data.get("username"))
        phone, email = valid_phone_email(validated_data['username'])
        user = UserKeyCloak()
        user.username = validated_data['username']
        user.password = validated_data['password']

        if phone:
            user.create_phone()
        if email:
            user.create_email()

        otp = random.randint(111111, 999999)
        print('===>', otp)
        cache.set(
            f"otp_{validated_data['username']}",
            json.dumps({
                "otp": otp,
                "retries": 0,
                "created_at": datetime.now().isoformat()
            }),
            timeout=10 * 60
        )
        # if phone:
        #     otp_phone_sender.delay(otp, validated_data['username'])
        # if email:
        #     otp_email_sender.delay(otp, validated_data['username'])

        return validated_data


class OTPRequestSeriailizer(serializers.Serializer):
    username = serializers.CharField(required=True)

    def validate(self, attrs):
        phone, email = valid_phone_email(attrs['username'])
        user = UserKeyCloak()
        user.username = attrs['username']

        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=404)
        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if user.get_user_id() == 404:
            raise serializers.ValidationError({'message':'username not exsits'}, code=401)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=403)
        return attrs
    
    def create(self, validated_data):
        phone, email = valid_phone_email(validated_data['username'])
        otp = random.randint(111111, 999999)
        print('===>', otp)
        cache.set(
            f"otp_{validated_data['username']}",
            json.dumps({"otp": otp, "retries": 0, "created_at": datetime.now().isoformat()}),
            timeout=10 * 60
        )
        if phone:
            otp_phone_sender.delay(otp, validated_data['username'])
        if email:
            otp_email_sender.delay(otp, validated_data['username'])
        
        return validated_data['username']


def _generate_password():
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = string.punctuation
    all_characters = lowercase + uppercase + digits + special
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special),
    ]
    password += random.choices(all_characters, k=12)
    random.shuffle(password)
    return ''.join(password)


class OTPSigninSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, write_only=True)
    otp = serializers.IntegerField(required=True, write_only=True)
    access_token = serializers.CharField(read_only=True)
    expires_in = serializers.IntegerField(read_only=True)
    refresh_expires_in = serializers.IntegerField(read_only=True)

    def validate(self, attrs):
    
        user = UserKeyCloak()
        user.username = attrs['username']
        otp = cache.get(f"otp_{attrs['username']}", {})
        if otp:
            otp = json.loads(otp)
        else:
            raise serializers.ValidationError({'message':'otp not found or is expired.'}, code=404)
        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if user.check_email_verify() == 404:
            raise serializers.ValidationError({'message':'please first verified username'}, code=401)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=403)

        if not otp:
            raise serializers.ValidationError({'message':'otp not found or is expired.'}, code=404)
        if otp.get("retries") >= 5:
            raise serializers.ValidationError({'message':'you have reached the maximum number of attempts.'}, code=429)
        if otp.get("otp") != attrs['otp']:
            otp['retries'] += 1
            time_from_creation = datetime.now() - otp.get("created_at")
            cache.set(f"otp_{attrs['username']}", json.dumps(otp), timeout=time_from_creation.seconds)
            raise serializers.ValidationError({'message':'otp is not correct'}, code=401)
        cache.delete(f"otp_{attrs['username']}")
        return attrs
    
    def create(self, validated_data):
        user = UserKeyCloak()
        updated_password = _generate_password()
        user.username = validated_data['username']
        user.password = updated_password
        user.change_password()
        token = TokenKeycloak()
        token.username = validated_data['username']
        token.password = updated_password
        token_info = token.get_token()
        phone, email = valid_phone_email(validated_data['username'])
        if phone:
            otp_phone_sender.delay(updated_password, validated_data['username'])
        if email:
            otp_email_sender.delay(updated_password, validated_data['username'])
        return token_info


class OTPSingupVerifySerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    otp = serializers.IntegerField(required=True)

    def validate(self, attrs):

        phone, email = valid_phone_email(attrs['username'])
        user = UserKeyCloak()
        user.username = attrs['username']
        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=422)

        cached_otp = json.loads(cache.get(f"otp_{user.username}", {}))
        if not cached_otp:
            raise serializers.ValidationError({'message': 'otp not found or is expired.'}, code=404)

        if cached_otp.get("retries") >= 5:
            raise serializers.ValidationError({'message': 'you have reached the maximum number of attempts.'}, code=429)

        if cached_otp.get("otp") != attrs['otp']:
            cached_otp['retries'] += 1
            time_from_creation = datetime.now() - cached_otp.get("created_at")
            cache.set(f"otp_{attrs['username']}", json.dumps(cached_otp), timeout=time_from_creation.seconds)
            raise serializers.ValidationError({'message': 'otp is not correct'}, code=401)

        if user.check_email_verify() == 200:
            raise serializers.ValidationError({'message':'usr befor exsits'}, code=409)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=403)
        return attrs

    def create(self, validated_data):
        user = UserKeyCloak()
        user.username = validated_data['username']
        user.email_verified()
        return validated_data['username']


class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    password_confierm = serializers.CharField(required=True)

    def validate(self, attrs):
        user = UserKeyCloak()
        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        
        access_token = self.context['request'].META.get('HTTP_AUTHORIZATION', '').split('Bearer ')[-1]
        user_token = TokenKeycloak()
        user_token.token = access_token
        info = user_token.decode_token()
        print(info)
        user.username = info['username']
        if user.check_email_verify() == 404:
            raise serializers.ValidationError({'message':'please first verified username'}, code=401)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=403)
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password confirm':'password not matched'}, code=400)
        return attrs

    def put(self, validated_data):
        access_token = self.context['request'].META.get('HTTP_AUTHORIZATION', '').split('Bearer ')[-1]
        user_token = TokenKeycloak()
        user_token.token = access_token
        info = user_token.decode_token

        user_keycloak = UserKeyCloak()
        user_keycloak.username = info['username']
        user_keycloak.password = validated_data['password']
        user_keycloak.change_password()
        
        return validated_data


class PasswordSinginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, write_only=True)
    password = serializers.CharField(required=True, write_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)
    expires_in = serializers.IntegerField(read_only=True)
    refresh_expires_in = serializers.IntegerField(read_only=True)

    def validate(self, attrs):
        user = UserKeyCloak()
        user.username = attrs['username']
        phone, email = valid_phone_email(attrs['username'])

        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=422)
        if user.check_email_verify() == 404:
            raise serializers.ValidationError({'message':'please first verified username'}, code=401)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=403)
        return attrs
    
    def create(self, validated_data):
        token = TokenKeycloak()
        if token.check_connect() == 500:
            raise serializers.ValidationError({'message': 'service authentications error'}, code=500)
    
        token.username = validated_data['username']
        token.password = validated_data['password']
        token_info = token.get_token()
        if token_info in [404, 500]:
            raise serializers.ValidationError({'message': 'service authentications error'}, code=500)
        return token_info
    

class TokenBaseSerializer(serializers.Serializer):
    def create(self, validated_data):
        keycloak = TokenKeycloak()
        if keycloak.check_connect() == 500:
            raise serializers.ValidationError({'message': 'service authentications error'}, code=500)
        return validated_data


class SignoutSerializer(TokenBaseSerializer):
    refresh_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        logout = TokenKeycloak()
        logout.token = validated_data['refresh_token']
        signout_result = logout.signout()
        if signout_result == 404:
            raise serializers.ValidationError({'message': 'token dos not validate'}, code=500)
        return validated_data['refresh_token']


class UserInfoSerializer(TokenBaseSerializer):
    access_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        information = TokenKeycloak()
        information.token = validated_data['access_token']
        user_info = information.user_info()
        if user_info == 404:
            raise serializers.ValidationError({'message':'token dos not validate'}, code=404)
        return user_info


class RefreshTokenSerializer(TokenBaseSerializer):
    refresh_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        refresh_token = TokenKeycloak()
        refresh_token.token = validated_data['refresh_token']
        refresh_token = refresh_token.refresh_token()
        if refresh_token in [404, 500]:
            raise serializers.ValidationError({'message':'token dos not validate'}, code=404)
        return refresh_token


class DecodeTokenSerializer(TokenBaseSerializer):
    access_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        decode_token = TokenKeycloak()
        decode_token.token = validated_data['access_token']
        information = decode_token.decode_token()
        if information in [404, 500]:
            raise serializers.ValidationError({'message':'token dos not validate'}, code=404)
        return information

class GetUserSubSerializer(serializers.Serializer):
    username = serializers.CharField()
    id = serializers.CharField()