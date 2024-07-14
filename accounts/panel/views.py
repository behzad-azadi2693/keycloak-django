from .serializers import UsersSerializer, PanelSerializer, CreateUserSerializer, UpdateUserSerializer
from accounts.service import UserKeyCloak
from config.authentication import KeycloakAuthentication
from .permissions import IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response


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