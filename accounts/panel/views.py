from accounts.service import UserKeyCloak
from config.authentication import KeycloakAuthentication
from .permissions import IsAdminUser
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from accounts.service import BaseKeyCloak
from django.http import Http404
from .serializers import (
        UsersSerializer, PanelSerializer, CreateUserSerializer,
        UpdateUserSerializer, UserMnagerSerializer
    )

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
        username = request.data.get('username')
        keycloak = UserKeyCloak()
        keycloak.username = username
        response = keycloak.disable()
        if response in [404, 500]:
            return Response({'Error': 'get error'}, status=400)
        return Response({'message': 'user disabled'}, status=200)
    

class UserEnableView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = PanelSerializer
    
    def post(self, request):
        username = request.data.get('username')
        keycloak = UserKeyCloak()
        keycloak.username = username
        response = keycloak.enable()
        if response in [404, 500]:
            return Response({'Error': 'get error'}, status=400)
        return Response({'message': 'user enabled'}, status=200)
    

class EmailUserVerifyView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = PanelSerializer
    
    def post(self, request):
        username = request.data.get('username')
        keycloak = UserKeyCloak()
        keycloak.username = username
        response = keycloak.email_verified()
        if response in [404, 500]:
            return Response({'Error': 'get error'}, status=400)
        return Response({'message': 'email verify'}, status=200)


class SearchUserView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAdminUser]
    serializer_class = PanelSerializer
    
    def post(self, request):
        username = request.data.get('username')
        keycloak = UserKeyCloak()
        keycloak.username = username
        response = keycloak.search_user()
        serializer = UsersSerializer(response, many=True)
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
    seriailizer_class = UserMnagerSerializer

    def get(self, request):
        if 'admin' not in request.user.permissions:
            raise Http404
        try:
            keycloak = BaseKeyCloak().keycloak_admin
            users = [] 
            users += keycloak.get_realm_role_members('admin')
            users += keycloak.get_realm_role_members('support_financial')
            users += keycloak.get_realm_role_members('support_technical')

            serializer = self.seriailizer_class(users, many=True)
            return Response(serializer.data, status=200)
        except:
            return Response({'message': 'please check keycloak connection'})