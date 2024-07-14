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

keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

users = keycloak_admin.get_users({'username':'test1', 'email':'tes2'})

import json
print(json.dumps(users, indent=4))