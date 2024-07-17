from drf_spectacular.extensions import OpenApiAuthenticationExtension

class KeycloakAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = 'config.authentication.KeycloakAuthentication'  # full import path to your authentication class
    name = 'keycloakAuth'  # name used in the 'SECURITY' setting

    def get_security_definition(self, auto_schema):
        return {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
        }