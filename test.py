from keycloak import KeycloakOpenID

# Configure client
keycloak_openid = KeycloakOpenID(server_url="http://keycloak:8080/auth",
                                 client_id="test",
                                 realm_name="test",
                                 client_secret_key="gO7miByBsqTmZ07OsUbKORaaFMoSss5m")

# Get WellKnown
config_well_known = keycloak_openid.well_known()


# Get Access Token With Code
token = keycloak_openid.token("test", "test")
print(token['access_token'])

userinfo = keycloak_openid.userinfo(token['access_token'])
print()
print(userinfo)