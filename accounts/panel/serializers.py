import re
from rest_framework import serializers
from accounts.service import UserKeyCloak


def valid_phone_email(username):
    phone = re.match(r'^([+]?\d{1,2}[-\s]?|)\d{3}[-\s]?\d{3}[-\s]?\d{4}$', username)
    email = re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', username)
    return phone, email


class UsersSerializer(serializers.Serializer):
    id = serializers.CharField()
    username = serializers.CharField()
    firstName = serializers.CharField()
    lastName = serializers.CharField()
    email = serializers.EmailField()
    emailVerified = serializers.BooleanField()
    enabled = serializers.BooleanField()


class PanelSerializer(serializers.Serializer):
    username = serializers.CharField()
    id = serializers.CharField()


class CreateUserSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    enabled = serializers.BooleanField(required=True)
    email_verify = serializers.BooleanField(required=True)
    password = serializers.CharField(required=True)
    password_confierm = serializers.CharField(required=True)

    def validate(self, attrs):
        user = UserKeyCloak()
        user.username = attrs['username']
        phone, email = valid_phone_email(attrs['username'])

        if attrs['password'] != attrs['password_confierm']:
            raise serializers.ValidationError({'password_confierm': 'password and password confierm is not matched'}, code=400)
        if user.check_connect() == 500:
            raise serializers.ValidationError({'message':'server not found'}, code=500)
        if user.get_user() != 404:
            raise serializers.ValidationError({'username': 'user with username is exsits'}, code=400)
        if phone or email:
            return attrs
        else:
            raise serializers.ValidationError({"username": "username is not valid"}, code=400)
    
    def create(self, validated_data):
        phone, email = valid_phone_email(validated_data['username'])
        user = UserKeyCloak()
        user.username = validated_data['username']
        user.password = validated_data['password']
        if phone:
            user.create_phone()
        if email:
            user.create_email()
        if validated_data['enabled']:
            user.enable()
        if validated_data['email_verify']:
            user.email_verified()
        return validated_data['username']
    
class UpdateUserSerializer(serializers.Serializer):
    old_username = serializers.CharField(required=True)
    new_username = serializers.CharField()
    enabled = serializers.BooleanField()
    email_verify = serializers.BooleanField()

    def validate(self, attrs):
        user = UserKeyCloak()
        user.username = attrs['old_username']
        if user.get_user() == 404:
            raise serializers.ValidationError({'username': 'user is not exsits'}, code=400)
        
        if 'new_username' in attrs:
            user.username = attrs['new_username']
            if user.check_connect() == 500:
                raise serializers.ValidationError({'message':'server not found'}, code=500)
            if user.get_user() != 404:
                raise serializers.ValidationError({'username': 'user with username is exsits'}, code=400)
            phone, email = valid_phone_email(attrs['new_username'])
            if phone or email:
                return attrs
            else:
                raise serializers.ValidationError({'new_username': 'username is not validate'})
        
        return attrs
    
    def update(self, instance, validated_data):
        user = UserKeyCloak()
        user.username = validated_data['old_username']
        if 'enabled' in validated_data:
            if validated_data['enabled']:
                user.enable()
            if not validated_data['enabled']:
                user.disable()
        if 'email_verify' in validated_data:
            if validated_data['email_verify']:
                user.email_verified()
            if not validated_data['email_verify']:
                user.email_unverified()
        if 'new_username' in validated_data:
            user.new_username = validated_data['new_username']
            user.change_username()
        
        return validated_data
    

class UserMnagerSerializer(serializers.Serializer):
    id = serializers.CharField()
    username = serializers.CharField()
    firstName = serializers.CharField()
    lastName = serializers.CharField()
    email = serializers.CharField()