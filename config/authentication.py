import logging
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from keycloak import KeycloakOpenID


class KeycloakAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Retrieve the token from the request headers
        token = request.META.get("HTTP_AUTHORIZATION", "").split("Bearer ")[-1]
        if not token:
            return None

        try:
            # Configure Keycloak client using settings
            keycloak_openid = KeycloakOpenID(
                server_url=f"{settings.KEYCLOAK_SERVER_URL}/auth",
                client_id=settings.KEYCLOAK_CLIENT_ID,
                realm_name=settings.KEYCLOAK_REALM_NAME,
                client_secret_key=settings.KEYCLOAK_CLIENT_SECRET_KEY,
            )
        except Exception as e:
            logging.error("Error configuring Keycloak client", e)
            return None

        try:
            # Decode token to get user information
            user_info = keycloak_openid.decode_token(token)
            if not user_info:
                logging.error("No user information found in token")
                return None

            # Instead of returning a Django user, return a mock user object with the necessary info
            class MockUser:
                def __init__(self, user_info):
                    self.sub = user_info.get("sub")
                    self.username = user_info.get("preferred_username")
                    self.name = user_info.get("name")
                    self.email = user_info.get("email")
                    self.first_name = user_info.get("given_name")
                    self.last_name = user_info.get("family_name")
                    self.permissions = user_info.get("realm_access", {}).get("roles", [])
                    self.groups = user_info.get("groups", [])  # Fetch groups list

                def is_authenticated(self):
                    return True

            return MockUser(user_info), None

        except Exception as e:
            logging.error("Error decoding token or retrieving user info", e)
            return None
