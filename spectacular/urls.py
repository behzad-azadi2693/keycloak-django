from django.urls import path
from .views import CustomSpectacularRedocView, CustomSpectacularSwaggerView


urlpatterns = [
    path('redoc/', CustomSpectacularRedocView.as_view(), name='redoc'),
    path('swagger-ui/', CustomSpectacularSwaggerView.as_view(), name='schema'),
]