import requests
from django.conf import settings
from accounts.service import UserKeyCloak
from config.authentication import KeycloakAuthentication
from .permissions import IsAdminUser
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from accounts.service import BaseKeyCloak
from django.http import Http404
from .serializers import (
    UsersSerializer,
    PanelSerializer,
    CreateUserSerializer,
    UpdateUserSerializer,
    UserMnagerSerializer,
)


def get_organization_model(request):
    token = request.META.get("HTTP_AUTHORIZATION", "").split("Bearer ")[-1]
    headers = {"Authorization": f"Bearer {token}"}
    # Send a request to the service with the authentication token
    response = requests.get(
        f"{settings.INVOLVED_SERVICE_URL}v1/organization/information/", headers=headers
    )
    return response


def get_organization_model(request):
    token = request.META.get("HTTP_AUTHORIZATION", "").split("Bearer ")[-1]
    headers = {"Authorization": f"Bearer {token}"}
    # Send a request to the service with the authentication token
    response = requests.get(
        f"{settings.INVOLVED_SERVICE_URL}v1/individual/information/", headers=headers
    )
    return response


class UserListView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = UsersSerializer

    def get(self, request):
        keycloak = UserKeyCloak()
        response = keycloak.list_users()
        serializer = self.serializer_class(response, many=True)
        return Response(serializer.data, status=200)


class UserDisableView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = PanelSerializer

    def post(self, request):
        username = request.data.get("username")
        keycloak = UserKeyCloak()
        keycloak.username = username
        roles = keycloak.list_roles()
        if roles in [404, 500] or "admin" in roles:
            return Response({"Admin": "this user is a admin"}, status=response)
        response = keycloak.disable()
        return Response({"message": "user disabled"}, status=200)


class UserEnableView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = PanelSerializer

    def post(self, request):
        username = request.data.get("username")
        keycloak = UserKeyCloak()
        keycloak.username = username
        response = keycloak.enable()
        if response in [404, 500]:
            return Response(
                {"Error": "get user error or connection failed"}, status=response
            )
        return Response({"message": "user enabled"}, status=200)


class EmailUserVerifyView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = PanelSerializer

    def post(self, request):
        username = request.data.get("username")
        keycloak = UserKeyCloak()
        keycloak.username = username
        response = keycloak.email_verified()
        if response in [404, 500]:
            return Response({"Error": "get error"}, status=response)
        return Response({"message": "email verify"}, status=200)


class SearchUserView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = PanelSerializer

    def post(self, request):
        username = request.data.get("username")
        keycloak = UserKeyCloak()
        keycloak.username = username
        response = keycloak.search_user()
        serializer = UsersSerializer(response, many=True)
        return Response(serializer.data, status=200)


class SearchUserRoleLegalView(APIView):
    """
    - in keycloak panel admin create role with name role_legal an role_real
    - this method for search and filter for user organization which have role role_legal in keycloak
    """

    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = UserMnagerSerializer

    def post(self, request):
        username = request.data.get("username")
        keycloak = BaseKeyCloak().keycloak_admin
        users = keycloak.get_users({"username": username})
        response = []
        for user in users:
            roles = keycloak.get_all_roles_of_user(user["id"])
            if roles:
                if "role_legal" in [role["name"] for role in roles["realmMappings"]]:
                    response.append(user)
        serializer = self.serializer_class(response, many=True)
        return Response(serializer.data, status=200)


class CreateUserView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = CreateUserSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=200)
        else:
            return Response(serializer.errors, status=400)


class UpdateUserView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = UpdateUserSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=200)
        else:
            return Response(serializer.errors, status=400)


class ListManagerView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserMnagerSerializer

    def get(self, request):
        if "admin" not in request.user.permissions:
            raise Http404
        try:
            keycloak = BaseKeyCloak().keycloak_admin
            users = []
            users += keycloak.get_realm_role_members("admin")
            users += keycloak.get_realm_role_members("support_financial")
            users += keycloak.get_realm_role_members("support_technical")

            serializer = self.serializer_class(users, many=True)
            return Response(serializer.data, status=200)
        except:
            return Response({"message": "please check keycloak connection"}, status=400)


class ListRoleLegalView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserMnagerSerializer

    def get(self, request):
        if "admin" not in request.user.permissions:
            raise Http404
        try:
            keycloak = BaseKeyCloak().keycloak_admin
            users = []
            users += keycloak.get_realm_role_members("role_legal")
            serializer = self.serializer_class(users, many=True)
            return Response(serializer.data, status=200)
        except:
            return Response({"message": "please check keycloak connection"}, status=400)


class ListRoleRealView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserMnagerSerializer

    def get(self, request):
        if "admin" not in request.user.permissions:
            raise Http404
        try:
            keycloak = BaseKeyCloak().keycloak_admin
            users = []
            users += keycloak.get_realm_role_members("role_real")
            serializer = self.serializer_class(users, many=True)
            return Response(serializer.data, status=200)
        except:
            return Response({"message": "please check keycloak connection"}, status=400)


class AddRoleLegalView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserMnagerSerializer

    def get(self, request):
        response = get_organization_model(request)
        if response.status_code == 200:
            try:
                keycloak = BaseKeyCloak().keycloak_admin
                user = keycloak.get_user(request.user.sub)
                roles = keycloak.get_realm_role("role_legal")
                keycloak.assign_realm_roles(user["id"], roles=[roles])
                serializer = self.serializer_class(user, many=True)
                return Response(serializer.data, status=200)
            except:
                return Response({"user": "cannot found user"}, status=400)
        else:
            return Response(
                {"response": "request to another service error"},
                status=response.status_code,
            )


class AddRoleRealView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserMnagerSerializer

    def get(self, request):
        response = get_organization_model(request)
        if response.status_code == 200:
            try:
                keycloak = BaseKeyCloak().keycloak_admin
                user = keycloak.get_user(request.user.sub)
                roles = keycloak.get_realm_role("role_real")
                keycloak.assign_realm_roles(user["id"], roles=[roles])
                serializer = self.serializer_class(user, many=True)
                return Response(serializer.data, status=200)
            except:
                return Response(
                    {"response": "request to another service error"},
                    status=response.status_code,
                )
