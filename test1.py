import logging
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection

# Set up logging
logging.basicConfig(level=logging.INFO)


try:
    keycloak_connection = KeycloakOpenIDConnection(
                        server_url="http://localhost:8080/",
                        username='test',
                        password='test',
                        realm_name="test",
                        user_realm_name="test",
                        client_id="test",
                        client_secret_key="Skus2URuoLJS2oejOkIscFsvAsnrVaPF",
                        verify=True)
    keycloak_admin = KeycloakAdmin(connection=keycloak_connection)
    print('OK')
except Exception as e:
        logging.error(f"Error connecting to Keycloak: {e}")


