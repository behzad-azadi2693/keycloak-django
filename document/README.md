# تعریف ورودی و خروجی اندپوینت ها
```
## /decode/token/
گرفتن اطلاعات توکن همراه با اطلاعات کاربر

method: POST
input: access_token
output: {
    'exp': 1717324922, 
    'iat': 1717324622, 
    'jti':'fd716173-b754-4821-b1b0-30a69316830b', 
    'iss': 'http://localhost:8080/realms/test', 
    'aud': ['realm-management', 'broker', 'account'], 
    'sub': 'b8b0cc6a-dc22-4de6-b3a3-0e8f5cc552ba', 
    'typ': 'Bearer', 
    'azp': 'test', 
    'session_state': 
    'f3562269-3d46-4343-a555-f9f0a0d61b27', 
    'acr': '1', 
    'realm_access': {'roles': ['default-roles-test', 'offline_access', 'uma_authorization']}, 
    'resource_access': {   
        'realm-management': {
            'roles': [
                        'view-realm', 'view-identity-providers',
                        'manage-identity-providers', 'impersonation', 'realm-admin', 'create-client', 
                        'manage-users', 'query-realms', 'view-authorization', 'query-clients', 
                        'query-users', 'manage-events', 'manage-realm', 'view-events', 'view-users', 
                        'view-clients', 'manage-authorization', 'manage-clients', 'query-groups'
                    ]
        }, 
    'broker': {
        'roles': ['read-token']
        }, 
    'account': {
            'roles': [
                        'manage-account', 'view-applications', 'view-consent', 'view-groups', 
                        'manage-account-links', 'manage-consent', 'delete-account', 'view-profile'
                    ]
            }
    }, 
    'scope': 'openid email profile', 
    'sid': 'f3562269-3d46-4343-a555-f9f0a0d61b27', 
    'email_verified': True, 
    'name': 'test test',
    'preferred_username': 'test', 
    'given_name': 'test', 
    'family_name': 'test', 
    'email': 'test@gmail.com'
}


============================================
## /password/change/
تغییر پسورد کاربر

method: POST
input: paasword & password2
output: status code and message

============================================
## /password/otp/verify/
تایید و گرفتن رمز یکبار مصرف جهت تایید کاربر و اجازه دسترسی برای تغییر پسورد

method: POST
inputh: username & otp
output: status code and message

============================================
## /refresh/token/
گرفتن توکن دسترسی جدید برای کاربر

method: POST
input: refresh_token
output: status code & refresh token & access_token

============================================
## /resuest/otp/
درخواست رمز یکبار مصرف و ارسال آن

method: POST
input: username
output: status code & message

============================================
## /signin/password/
ورود به حساب کاربری با پسورد

method: POST
input: username & password
output: status code & refresh token & access_token

============================================
## /signout/
خروج از حساب کاربری

method: POST
input: refresh_token
output: status code & message

============================================
## /signup/
ایجاد حساب کاربری جدید

method: POST
input: username & password & password2
output: status code & message

============================================
## /signup/otp/verify/
تایید نام کاربری کاربر ایجاد شده

method: POST
input: username
output: status code & message

============================================
## /user/information/
گرفتن اطلاعات کاربر

method: POST
input: access_token
output: {
        'sub': 'b8b0cc6a-dc22-4de6-b3a3-0e8f5cc552ba', 
        'email_verified': True, 
        'name': 'test test',
        'preferred_username': 'test', 
        'given_name': 'test', 
        'family_name': 'test', 
        'email': 'test@gmail.com'
    }
```
