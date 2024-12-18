from django.urls import path
from .views import CustomSpectacularRedocView, CustomSpectacularSwaggerView


urlpatterns = [
    path('redoc/', CustomSpectacularRedocView.as_view()),
    path('swagger-ui/', CustomSpectacularSwaggerView.as_view()),
]