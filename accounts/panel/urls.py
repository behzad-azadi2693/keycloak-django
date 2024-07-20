from django.urls import path
from .views import (
        UserListView, UserDisableView, UserEnableView,
        EmailUserVerifyView, SearchUserView, CreateUserView,
        UpdateUserView, ListManagerView, #GetUserSubView,
        AddRoleLegalView, AddRoleRealView, ListRoleLegalView,
        ListRoleRealView, SearchUserRoleLegalView
        
    )


urlpatterns = [
    path('list/users/', UserListView.as_view()),
    path('disable/users/', UserDisableView.as_view()),
    path('enable/users/', UserEnableView.as_view()),
    path('email/verify/', EmailUserVerifyView.as_view()),
    path('search/user/', SearchUserView.as_view()),
    path('search/user/legal/', SearchUserRoleLegalView.as_view()),
    path('create/user/', CreateUserView.as_view()),
    path('update/user/', UpdateUserView.as_view()),
    path('list/manager/', ListManagerView.as_view()),
    path('list/organization/', ListRoleLegalView.as_view()),
    path('list/individual/', ListRoleRealView.as_view()),
    #path('get/user/<str:sub>/', GetUserSubView.as_view()),
    path('add/role/legal/', AddRoleLegalView.as_view()),
    path('add/role/real/', AddRoleRealView.as_view()),
]

