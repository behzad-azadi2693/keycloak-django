import requests
from django.conf import settings
from rest_framework import permissions


def get_organization_model(request):
    token = request.META.get("HTTP_AUTHORIZATION", "").split("Bearer ")[-1]
    headers = {"Authorization": f"Bearer {token}"}
    # Send a request to the service with the authentication token
    response = requests.get(
        f"{settings.INVOLVED_SERVICE_URL}v1/organization/information/", headers=headers
    )
    return response


class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            list_permissions = request.user.permissions
            if bool(
                set(["technical_support", "financial_support", "admin"])
                & set(list_permissions)
            ):
                return True
            else:
                return False
        else:
            return False
