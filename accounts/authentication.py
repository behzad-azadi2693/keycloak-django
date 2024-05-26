'''
refrence: https://blog.stackademic.com/integrating-keycloak-with-django-7ae39abe3a0b
'''

from rest_framework.authentication import BaseAuthentication
from django.contrib.auth import get_user_model
from keycloak import KeycloakOpenID
from django.conf import settings

User = get_user_model()


class KeycloakAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Your authentication logic here using python-keycloak
        # Example:
        token = request.META.get('HTTP_AUTHORIZATION', '').split('Bearer ')[-1]

        # Configure client
        keycloak_openid = KeycloakOpenID(server_url=f"{settings.KEYCLOAK_SERVER_URL}/auth",
                                 client_id=settings.KEYCLOAK_CLIENT_ID,
                                 realm_name=settings.KEYCLOAK_REALM_NAME,
                                 client_secret_key=settings.KEYCLOAK_CLIENT_SECRET_KEY)
        try:
            user_info = keycloak_openid.decode_token(token)
        
            # Create or retrieve Django user based on user_info
            # Example:
            user, _ = User.objects.get_or_create(username=user_info['preferred_username'])
        
            return user, None
        
        except:
            return None