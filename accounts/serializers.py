import re
import pytz
import bcrypt
from django.conf import settings
from datetime import datetime, timedelta
from rest_framework import serializers
from .keycloak.service import UserKeyCloak, TokenKeycloak
from django.utils.timezone import make_naive
from .tasks import otp_email_sender, otp_phone_sender


def valid_phone_email(username):
    phone = re.match(r'^([+]?\d{1,2}[-\s]?|)\d{3}[-\s]?\d{3}[-\s]?\d{4}$', username)
    email = re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', username)
    return phone, email


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        user = UserKeyCloak()
        user.username = attrs['username']
        phone, email = valid_phone_email(attrs['username'])

        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if user.check_email_verify() == 200:
            raise serializers.ValidationError('user exsits', code=403)
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError('password not mached', code=401)
        if phone or email:
            return attrs
        else:
            raise serializers.ValidationError('username is not correct', code=403)
        
    def create(self, validated_data):
        phone, email = valid_phone_email(validated_data['username'])
        user = UserKeyCloak()
        user.username = validated_data['username']
        user.password = validated_data['password']
        if phone:
            user.create_phone()
        if email:
            user.create_email()
        return validated_data['username']


class OTPRequestSeriailizer(serializers.Serializer):
    username = serializers.CharField(required=True)

    def validate(self, attrs):
        phone, email = valid_phone_email(attrs['username'])
        user = UserKeyCloak()
        user.username = attrs['username']

        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=400)
        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if user.get_user_id() == 404:
            raise serializers.ValidationError({'message':'username not exsits'}, code=404)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=400)

        '''
        if phone:
            otp_phone_sender(attrs['otp'], phone)
        if email:
            otp_email_sender(attrs['otp'], email)
        '''
        return attrs
    

class OTPSigninSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    otp = serializers.IntegerField(required=True)

    def validate(self, attrs):
        otp, time, count, username = self.context['otp'], self.context['time'], self.context['count'], self.context['username']
        if None in [time, username, otp, count]:
            raise serializers.ValidationError({'message':'you dont access for this page'}, code=404)
    
        phone, email = valid_phone_email(attrs['username'])
        time_delta, now_time = make_naive(datetime.fromisoformat(time) + timedelta(minutes=5)), make_naive(datetime.now().astimezone(pytz.timezone('Asia/Tehran')))
        user = UserKeyCloak()
        user.username = attrs['username']
        self.context['request'].session['OTP_ITS_COUNT'] = count + 1

        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=400)
        if count > 5:
            self.context['request'].session.flush()
            raise serializers.ValidationError({'message':'otp is expired'}, code=410)
        if time_delta < now_time:
            self.context['request'].session.flush()
            raise serializers.ValidationError({'message':'timing is expired for otp'}, code=410)
        if not bcrypt.checkpw(f"{attrs['otp']}+{settings.VALUE_HASH}".encode(), otp.encode()):
            raise serializers.ValidationError({'message':'otp or username is not   correct'}, code=400)
        if user.check_email_verify() == 404:
            raise serializers.ValidationError({'message':'please first verified username'}, code=400)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=400)
        return attrs
    

class OTPPasswordChangeVerifySerializer(OTPSigninSerializer):
    username = serializers.CharField(required=True)
    otp = serializers.IntegerField(required=True)

    def validate(self, attrs):
        otp, time, count, username = self.context['otp'], self.context['time'], self.context['count'], self.context['username']
        if None in [time, username, otp, count]:
            raise serializers.ValidationError({'message':'you dont access for this page'}, code=404)
    
        phone, email = valid_phone_email(attrs['username'])
        time_delta, now_time = make_naive(datetime.fromisoformat(time) + timedelta(minutes=5)), make_naive(datetime.now().astimezone(pytz.timezone('Asia/Tehran')))
        user = UserKeyCloak()
        user.username = attrs['username']
        self.context['request'].session['OTP_ITS_COUNT'] = count + 1

        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=400)
        if count > 5:
            self.context['request'].session.flush()
            raise serializers.ValidationError({'message':'otp is expired'}, code=410)
        if time_delta < now_time:
            self.context['request'].session.flush()
            raise serializers.ValidationError({'message':'timing is expired for otp'}, code=410)
        if not bcrypt.checkpw(f"{attrs['otp']}+{settings.VALUE_HASH}".encode(), otp.encode()):
            raise serializers.ValidationError({'message':'otp or username is not   correct'}, code=400)
        if user.check_email_verify() == 404:
            raise serializers.ValidationError({'message':'please first verified username'}, code=400)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=400)
        return attrs
    

class OTPSingnupVerifySerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    otp = serializers.IntegerField(required=True)

    def validate(self, attrs):
        otp, time, count, username = self.context['otp'], self.context['time'], self.context['count'], self.context['username']
        if None in [time, username, otp, count]:
            raise serializers.ValidationError({'message':'you dont access for this page'}, code=404)
    
        phone, email = valid_phone_email(attrs['username'])
        time_delta, now_time = make_naive(datetime.fromisoformat(time) + timedelta(minutes=5)), make_naive(datetime.now().astimezone(pytz.timezone('Asia/Tehran')))
        user = UserKeyCloak()
        user.username = attrs['username']
        self.context['request'].session['OTP_ITS_COUNT'] = count + 1

        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=400)
        if count > 5:
            self.context['request'].session.flush()
            raise serializers.ValidationError({'message':'otp is expired'}, code=410)
        if time_delta < now_time:
            self.context['request'].session.flush()
            raise serializers.ValidationError({'message':'timing is expired for otp'}, code=410)
        if not bcrypt.checkpw(f"{attrs['otp']}+{settings.VALUE_HASH}".encode(), otp.encode()):
            raise serializers.ValidationError({'message':'otp or username is not   correct'}, code=400)
        if user.check_email_verify() == 200:
            raise serializers.ValidationError({'message':'usr befor exsits'}, code=400)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=400)
        return attrs

    def create(self, validated_data):
        user = UserKeyCloak()
        user.username = validated_data['username']
        user.email_verified()
        return validated_data['username']


class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        time, username, change =  self.context['time'], self.context['username'], self.context['change']
        if None in [time, username, change]:
            raise serializers.ValidationError({'message':'you dont access for this page'}, code=404)

        phone, email = valid_phone_email(username)
        time_delta, now_time = make_naive(datetime.fromisoformat(time) + timedelta(minutes=5)), make_naive(datetime.now().astimezone(pytz.timezone('Asia/Tehran')))
        user = UserKeyCloak()
        user.username = username

        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=400)
        if not change:
            raise serializers.ValidationError({'message':'you can not change password'}, code=400)
        if time_delta < now_time:
            raise serializers.ValidationError({'message':'timing is expired for otp'}, code=410)
        if user.check_email_verify() == 404:
            raise serializers.ValidationError({'message':'please first verified username'}, code=400)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=400)
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({'message': 'password not mached'}, code=401)
        return attrs

    def create(self, validated_data):
        user = UserKeyCloak()
        user.password = validated_data['password']
        user.username = self.context['username']
        user.change_password()
        token = TokenKeycloak()
        token.username = self.context['username']
        token.signout()
        return validated_data['password']


class PasswordSinginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, attrs):
        user = UserKeyCloak()
        user.username = attrs['username']
        phone, email = valid_phone_email(attrs['username'])

        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if not phone and not email:
            raise serializers.ValidationError({'message':'username is not correct'}, code=400)
        if user.check_email_verify() == 404:
            raise serializers.ValidationError({'message':'please first verified username'}, code=400)
        if user.check_enable() == 404:
            raise serializers.ValidationError({'message':'user not available calling with admin'}, code=400)
        return attrs
    
    def create(self, validated_data):
        token = TokenKeycloak()
        if token.check_connect() == 500:
            raise serializers.ValidationError({'message': 'service authentications error'}, code=500)
    
        token.username = validated_data['username']
        token.password = validated_data['password']
        token_info = token.get_token()
        if token_info == 500:
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
    

class UserInfoSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        information = TokenKeycloak()
        information.token = validated_data['access_token']
        user_info = information.user_info()
        if user_info == 404:
            raise serializers.ValidationError({'message':'token dos not validate'}, code=404)
        return user_info
    

class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        refresh_token = TokenKeycloak()
        refresh_token.token = validated_data['refresh_token']
        refresh_token = refresh_token.refresh_token()
        if refresh_token == 404:
            raise serializers.ValidationError({'message':'token dos not validate'}, code=404)
        return refresh_token
    

class DecodeTokenSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

    def create(self, validated_data):
        super().create(validated_data)
        decode_token = TokenKeycloak()
        decode_token.token = validated_data['access_token']
        information = decode_token.decode_token()
        if information == 404:
            raise serializers.ValidationError({'message':'token dos not validate'}, code=404)
        return information