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

    @cache
    def __init__(self):
        self._username = None
        self._password = None
        self.keycloak_admin = self.admin_connect()
        self.keycloak_openid = self.openid_connect()

    @property
    @cache
    def username(self):
        return self._username

    @username.setter
    @cache
    def username(self, value):
        if not value:
            raise ValueError('username cannot be empty')
        self._username = value

    @property
    @cache
    def password(self):
        return self._password

    @password.setter
    @cache
    def password(self, value):
        if not value:
            raise ValueError('password cannot be empty')
        self._password = value

    @cache
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
                verify=True
            )

            keycloak_admin = KeycloakAdmin(connection=keycloak_connection)
            return keycloak_admin
        except Exception as e:
            logging.error(f"Error connecting to Keycloak: {e}")
            return None

    @cache
    def openid_connect(self):
        try:
            keycloak_openid = KeycloakOpenID(
                server_url=f"{settings.KEYCLOAK_SERVER_URL}/auth",
                client_id=settings.KEYCLOAK_CLIENT_ID,
                realm_name=settings.KEYCLOAK_REALM_NAME,
                client_secret_key=settings.KEYCLOAK_CLIENT_SECRET_KEY
            )
            keycloak_openid.well_known()
            return keycloak_openid
        except Exception as e:
            logging.error(f"Error connecting to Keycloak: {e}")
            return self.STATUS_SERVER_ERROR
        
    @cache
    def check_connect(self):
        try:
            self.keycloak_admin.get_realms()
            return self.STATUS_OK
        except Exception as e:
            logging.error(f"Error getting server: {e}")
            return self.STATUS_SERVER_ERROR
        

class UserKeyCloak(BaseKeyCloak):

    @cache
    def get_user_id(self):
        user_id = self.keycloak_admin.get_user_id(self.username)
        if user_id is not None:
            return user_id
        else:
            return self.STATUS_NOT_FOUND

    @cache
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

    @cache
    def check_enable(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        elif user['enabled']:
            return self.STATUS_OK
        else:
            return self.STATUS_NOT_FOUND
        
    @cache
    def check_email_verify(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        elif user['emailVerified']:
            return self.STATUS_OK
        else:
            return self.STATUS_NOT_FOUND

    @cache
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
                                "temporary": False
                            }
                        ]
                    }
                )
                return self.STATUS_CREATED
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return self.STATUS_NOT_FOUND
        else:
            try:
                self.keycloak_admin.set_user_password(user_id=user_id, password=self.password, temporary=False)
                return self.STATUS_NO_CONTENT
            except Exception as e:
                logging.error(f"Error setting user password: {e}")
                return self.STATUS_NOT_FOUND

    @cache
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
                                "temporary": False
                            }
                        ]
                    }
                )
                return self.STATUS_CREATED
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return self.STATUS_NOT_FOUND
        else:
            try:
                self.keycloak_admin.set_user_password(user_id=user_id, password=self.password, temporary=False)
                return self.STATUS_NO_CONTENT
            except Exception as e:
                logging.error(f"Error setting user password: {e}")
                return self.STATUS_NOT_FOUND

    @cache
    def enable(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        else:
            try:
                user['enabled'] = True
                self.keycloak_admin.update_user(user_id=user['id'], payload=user)
                return self.STATUS_OK
            except Exception as e:
                logging.error(f"Error enabling user: {e}")
                return self.STATUS_NOT_FOUND

    @cache
    def disable(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        else:
            try:
                user['enabled'] = False
                self.keycloak_admin.update_user(user_id=user['id'], payload=user)
                return self.STATUS_OK
            except Exception as e:
                logging.error(f"Error disabling user: {e}")
                return self.STATUS_NOT_FOUND

    @cache
    def email_verified(self):
        user = self.get_user()
        if user == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        try:
            user['emailVerified'] = True
            self.keycloak_admin.update_user(user_id=user['id'], payload=user)
            return self.STATUS_NO_CONTENT
        except Exception as e:
            logging.error(f"Error updating email verification status: {e}")
            return self.STATUS_NOT_FOUND

    @cache
    def change_password(self):
        user_id = self.get_user_id()
        if user_id == self.STATUS_NOT_FOUND:
            return self.STATUS_NOT_FOUND
        else:
            try:
                self.keycloak_admin.set_user_password(user_id=user_id, password=self.password, temporary=False)
                return self.STATUS_CREATED
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return self.STATUS_NOT_FOUND


class TokenKeycloak(BaseKeyCloak):
    @cache
    def __init__(self):
        super().__init__()
        self._token = None

    @property
    @cache
    def token(self):
        return self._token

    @token.setter
    @cache
    def token(self, value):
        if not value:
            raise ValueError('username cannot be empty')
        self._token = value


    @cache
    def get_token(self):
        try:
            token = self.keycloak_openid.token(self.username, self.password)
            return token
        except Exception as e:
            logging.error(f"Error for get user token: {e}")
            return self.STATUS_SERVER_ERROR

    @cache
    def refresh_token(self):
        try:
            token = self.keycloak_openid.refresh_token(self.token)
            return token
        except Exception as e:
            logging.error(f"refresh token error: {e}")
            return self.STATUS_SERVER_ERROR
             
    @cache
    def decode_token(self):
        try:
            token_info = self.keycloak_openid.decode_token(self.token)
            return token_info
        except Exception as e:
            logging.error(f"decode token error: {e}")
            return self.STATUS_SERVER_ERROR

    @cache
    def user_info(self):
        try:
            userinfo = self.keycloak_openid.userinfo(self.token)
            return userinfo
        except Exception as e:
            logging.error(f"user information error: {e}")
            return self.STATUS_NOT_FOUND           

    @cache
    def signout(self):
        try:
            self.keycloak_openid.logout(self.token)
            return self.STATUS_OK
        except Exception as e:
            logging.error(f"user sign out error: {e}")
            return self.STATUS_NOT_FOUND   
