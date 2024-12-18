from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from .managers import UserManager
from django.core.validators import RegexValidator


class User(AbstractBaseUser,PermissionsMixin):
    username = models.CharField(max_length=250, unique=True,verbose_name='your username')
    is_staff = models.BooleanField(default=False, verbose_name="user is active")
    is_admin = models.BooleanField(default=False, verbose_name="user is admin")
    
    objects=UserManager()
    USERNAME_FIELD = 'username'

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        app_label = 'accounts'

    def __str__(self) -> str:
        return self.username

    def has_perm(self, perm, obj=None) -> bool:
        return True

    def has_module_perms(self, app_label) -> bool:
        return True
        
    @property
    def is_staff(self) -> bool:
        return self.is_admin

    @property
    def is_active(self) -> bool:
        return self.is_admin
    
    def save(self, *args, **kwargs):
        """saving to DB disabled"""
        super(User, self).save(*args, **kwargs)
    

class UserTypeModel(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return f'{self.name}-({self.id})'


class ProfileModel(models.Model):
    user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True)
    user_type = models.ForeignKey(UserTypeModel, on_delete=models.SET_NULL, null=True, blank=True)
    name = models.CharField(max_length=250)
    last_name = models.CharField(max_length=250, null=True, blank=True)
    national_id = models.PositiveBigIntegerField(null=True, blank=True)
    code = models.PositiveBigIntegerField()
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,11}$', message="Phone number must be entered in the format: '09129876543'. Up to 15 digits allowed.")
    phone_number = models.CharField(validators=[phone_regex], max_length=11, null=True, blank=True) # Validators should be a list
    date = models.DateField()
    title = models.CharField(max_length=250)
    code_id = models.PositiveBigIntegerField()
    wesite = models.URLField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.get_user_type_display()} - {self.user.username} - ({self.id})"
    
