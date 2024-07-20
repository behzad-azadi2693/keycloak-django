from keycloak import KeycloakOpenIDConnection, KeycloakAdmin

# Configure client
keycloak_connection = KeycloakOpenIDConnection(
                        server_url="http://192.168.100.53:8080/",
                        username='test',
                        password='test',
                        realm_name="test",
                        user_realm_name="test",
                        client_id="test",
                        client_secret_key="frrbAeNm7ZlmR9DQsYc2w8I97eb366NH",
                        verify=False)
import json
keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

users = keycloak_admin.get_users({'username':'tes'})
for user in users:
    print(user['username'])
    user = keycloak_admin.get_all_roles_of_user(user['id'])
    print('admin' in [role['name'] for role in user['realmMappings']])

'''from keycloak import KeycloakOpenIDConnection, KeycloakAdmin, KeycloakOpenID

# Configure client
# Configure client
# For versions older than 18 /auth/ must be added at the end of the server_url.
keycloak_openid = KeycloakOpenID(server_url="http://192.168.100.53:8080/",
                                 client_id="test",
                                 realm_name="test",
                                 client_secret_key="frrbAeNm7ZlmR9DQsYc2w8I97eb366NH")


token = keycloak_openid.token("test", "test")

token_info = keycloak_openid.userinfo(token['access_token'])

import json
print(json.dumps(token_info, indent=4))'''
