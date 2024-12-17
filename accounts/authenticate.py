from .models import User
from django.contrib.auth.backends import ModelBackend

class UsernameBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            user = User.objects.get(username=username)

            if user.check_password(password):
                return user

            return None
        
        except user.DoesNotExist:
            return None
        
    def get_user(self, user_id):
        try:
            return User.objects.get(id=user_id)
        
        except User.DosNotExist:
            return None
        

