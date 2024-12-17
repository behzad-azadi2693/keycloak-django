import logging
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection
from django.conf import settings
from keycloak import KeycloakOpenID
from functools import cache

# Set up logging
logging.basicConfig(level=logging.INFO)


class BaseKeyCloak:
    STATUS_OK = 200
    STATUS_CREATED = 201
    STATUS_NO_CONTENT = 204
    STATUS_NOT_FOUND = 404
    STATUS_FORBIDDEN = 403
    STATUS_SERVER_ERROR = 500

    def __init__(self):
        self._username = None
        self._password = None
        self._new_username = None
        self.keycloak_admin = self.admin_connect()
        self.keycloak_openid = self.openid_connect()
        self.keycloak_passwordless = self.admin_connect_passwordless()

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        if not value:
            raise ValueError("username cannot be empty")
        self._username = value

    @property
    def new_username(self):
        return self._new_username

    @username.setter
    def new_username(self, value):
        if not value:
            raise ValueError("username cannot be empty")
        self._new_username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        if not value:
            raise ValueError("password cannot be empty")
        self._password = value

    def admin_connect(self):
        try:
            keycloak_connection = KeycloakOpenIDConnection(
                server_url=settings.KEYCLOAK_SERVER_URL,
                username=settings.KEYCLOAK_USERNAME,
                password=settings.KEYCLOAK_PASSWORD,
                realm_name=settings.KEYCLOAK_REALM_NAME,
                user_realm_name=settings.KEYCLOAK_USER_REALM_NAME,
                client_id=settings.KEYCLOAK_CLIENT_ID,
                client_secret_key=settings.KEYCLOAK_CLIENT_SECRET_KEY,
                verify=True,
            )

            keycloak_admin = KeycloakAdmin(connection=keycloak_connection)
            return keycloak_admin
        except Exception as e:
            logging.error(f"Error connecting to Keycloak: {e}")
            return None

    def admin_connect_passwordless(self):
        try:
            keycloak_openid = KeycloakOpenID(
                server_url=f"{settings.KEYCLOAK_SERVER_URL}/auth",
                client_id=settings.KEYCLOAK_CLIENT_ID,
                realm_name=settings.KEYCLOAK_REALM_NAME,
                client_secret_key=settings.KEYCLOAK_CLIENT_SECRET_KEY,
            )
            keycloak_openid.well_known()
            return keycloak_openid
        except Exception as e:
            logging.error(f"Error connecting to Keycloak: {e}")
            return self.STATUS_SERVER_ERROR

    def openid_connect(self):
        try:
            keycloak_openid = KeycloakOpenID(
                server_url=f"{settings.KEYCLOAK_SERVER_URL}/auth",
                client_id=settings.KEYCLOAK_CLIENT_ID,
                realm_name=settings.KEYCLOAK_REALM_NAME,
                client_secret_key=settings.KEYCLOAK_CLIENT_SECRET_KEY,
            )
            keycloak_openid.well_known()
            return keycloak_openid
        except Exception as e:
            logging.error(f"Error connecting to Keycloak: {e}")
            return self.STATUS_SERVER_ERROR

    def check_connect(self):
        try:
            self.keycloak_admin.get_realms()
            return self.STATUS_OK
        except Exception as e:
            logging.error(f"Error getting server: {e}")
            return self.STATUS_SERVER_ERROR


class UserKeyCloak(BaseKeyCloak):

    def get_user_id(self):
        user_id = self.keycloak_admin.get_user_id(self.username)
        if user_id is not None:
            return user_id
        else:
            return self.STATUS_NOT_FOUND

    def get_user(self):
        user_id = self.get_user_id()
        if user_id == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        try:
            user = self.keycloak_admin.get_user(user_id)
            return user
        except Exception as e:
            logging.error(f"Error getting user: {e}")
            return self.STATUS_NOT_FOUND

    def check_enable(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        elif user["enabled"]:
            return self.STATUS_OK
        else:
            return self.STATUS_NOT_FOUND

    def check_email_verify(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        elif user["emailVerified"]:
            return self.STATUS_OK
        else:
            return self.STATUS_NOT_FOUND

    def create_email(self):
        user_id = self.get_user_id()
        if user_id == self.STATUS_NOT_FOUND:
            try:
                self.keycloak_admin.create_user(
                    {
                        "email": self.username,
                        "username": self.username,
                        "enabled": True,
                        "firstName": self.username,
                        "lastName": self.username,
                        "credentials": [
                            {
                                "value": self.password,
                                "type": "password",
                                "temporary": False,
                            }
                        ],
                    }
                )
                return self.STATUS_CREATED
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return self.STATUS_NOT_FOUND
        else:
            try:
                self.keycloak_admin.set_user_password(
                    user_id=user_id, password=self.password, temporary=False
                )
                return self.STATUS_NO_CONTENT
            except Exception as e:
                logging.error(f"Error setting user password: {e}")
                return self.STATUS_NOT_FOUND

    def create_phone(self):
        user_id = self.get_user_id()
        if user_id == self.STATUS_NOT_FOUND:
            try:
                self.keycloak_admin.create_user(
                    {
                        "email": f"{self.username}@gmail.com",
                        "username": self.username,
                        "enabled": True,
                        "firstName": self.username,
                        "lastName": self.username,
                        "credentials": [
                            {
                                "value": self.password,
                                "type": "password",
                                "temporary": False,
                            }
                        ],
                    }
                )
                return self.STATUS_CREATED
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return self.STATUS_NOT_FOUND
        else:
            try:
                self.keycloak_admin.set_user_password(
                    user_id=user_id, password=self.password, temporary=False
                )
                return self.STATUS_NO_CONTENT
            except Exception as e:
                logging.error(f"Error setting user password: {e}")
                return self.STATUS_NOT_FOUND

    def enable(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        else:
            try:
                user["enabled"] = True
                self.keycloak_admin.update_user(user_id=user["id"], payload=user)
                return self.STATUS_OK
            except Exception as e:
                logging.error(f"Error enabling user: {e}")
                return self.STATUS_NOT_FOUND

    def disable(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        else:
            try:
                user["enabled"] = False
                self.keycloak_admin.update_user(user_id=user["id"], payload=user)
                return self.STATUS_OK
            except Exception as e:
                logging.error(f"Error disabling user: {e}")
                return self.STATUS_NOT_FOUND

    def email_verified(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        try:
            user["emailVerified"] = True
            self.keycloak_admin.update_user(user_id=user["id"], payload=user)
            return self.STATUS_NO_CONTENT
        except Exception as e:
            logging.error(f"Error updating email verification status: {e}")
            return self.STATUS_NOT_FOUND

    def email_unverified(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        try:
            user["emailVerified"] = False
            self.keycloak_admin.update_user(user_id=user["id"], payload=user)
            return self.STATUS_NO_CONTENT
        except Exception as e:
            logging.error(f"Error updating email verification status: {e}")
            return self.STATUS_NOT_FOUND

    def change_password(self):
        user_id = self.get_user_id()
        if user_id == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        else:
            try:
                self.keycloak_admin.set_user_password(
                    user_id=user_id, password=self.password, temporary=False
                )
                return self.STATUS_CREATED
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return self.STATUS_NOT_FOUND

    def change_username(self):
        user_id = self.get_user_id()
        if user_id == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        else:
            try:
                user = self.get_user()
                user["username"] = self.new_username
                self.keycloak_admin.update_user(user_id=user_id, payload=user)
                return self.STATUS_CREATED
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return self.STATUS_NOT_FOUND

    def list_users(self):
        users = self.keycloak_admin.get_users({})
        return users

    def search_user(self):
        users = self.keycloak_admin.get_users(
            {
                "username": self.username,
                "firstName": self.username,
                "lastName": self.username,
                "email": self.username,
            }
        )
        return users

    def list_roles(self):
        user_id = self.get_user_id()
        roles = self.keycloak_admin.get_all_roles_of_user(user_id)
        if user_id == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        if roles:
            return [role["name"] for role in roles["realmMappings"]]
        else:
            return self.STATUS_NOT_FOUND


class TokenKeycloak(BaseKeyCloak):

    def __init__(self):
        super().__init__()
        self._token = None

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        if not value:
            raise ValueError("username cannot be empty")
        self._token = value

    def get_token(self):
        try:
            token = self.keycloak_openid.token(self.username, self.password)
            return token
        except Exception as e:
            logging.error(f"Error for get user token: {e}")
            return self.STATUS_SERVER_ERROR

    def get_token_passwordless(self):
        try:
            token = self.keycloak_passwordless.token(
                self.username, grant_type=["client_credentials"]
            )
            return token
        except Exception as e:
            logging.error(f"Error for get user token: {e}")
            return self.STATUS_SERVER_ERROR

    def refresh_token(self):
        try:
            token = self.keycloak_openid.refresh_token(self.token)
            return token
        except Exception as e:
            logging.error(f"refresh token error: {e}")
            return self.STATUS_SERVER_ERROR

    def decode_token(self):
        try:
            token_info = self.keycloak_openid.decode_token(self.token)
            return token_info
        except Exception as e:
            logging.error(f"decode token error: {e}")
            return self.STATUS_SERVER_ERROR

    def user_info(self):
        try:
            userinfo = self.keycloak_openid.userinfo(self.token)
            return userinfo
        except Exception as e:
            logging.error(f"user information error: {e}")
            return self.STATUS_NOT_FOUND

    def logout(self):
        try:
            self.keycloak_openid.logout(self.token)
            return self.STATUS_OK
        except Exception as e:
            logging.error(f"user sign out error: {e}")
            return self.STATUS_NOT_FOUND
