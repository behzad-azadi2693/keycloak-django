from drf_spectacular.views import SpectacularSwaggerView, SpectacularRedocView
from rest_framework.permissions import IsAdminUser


class CustomSpectacularSwaggerView(SpectacularSwaggerView):
    permission_classes = [IsAdminUser]  # فقط کاربران لاگین شده اجازه دسترسی دارند


class CustomSpectacularRedocView(SpectacularRedocView):
    permission_classes = [IsAdminUser] 
