from django.contrib.auth.models import BaseUserManager

# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, username, password):
        if not username:
            raise ValueError("please insert username")
        user = self.model(username=username)
        user.set_password(password)
        user.save(using=self._db)

        return user 

    def create_superuser(self, username, password):
        user = self.create_user(username=username, password=password)
        user.is_admin=True
        user.is_active=True
        user.save(using=self._db)
        return user