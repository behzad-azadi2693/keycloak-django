from django.urls import path
from .views import (
        UserListView, UserDisableView, UserEnableView,
        EmailUserVerifyView, SearchUserView, CreateUserView,
        UpdateUserView, ListManagerView
        
    )


urlpatterns = [
    path('list/users/', UserListView.as_view()),
    path('disable/users/', UserDisableView.as_view()),
    path('enable/users/', UserEnableView.as_view()),
    path('email/verify/', EmailUserVerifyView.as_view()),
    path('search/user/', SearchUserView.as_view()),
    path('create/user/', CreateUserView.as_view()),
    path('update/user/', UpdateUserView.as_view()),
    path('list/manager/', ListManagerView.as_view()),
]

