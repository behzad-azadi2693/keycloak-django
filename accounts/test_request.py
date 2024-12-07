import requests

# تنظیمات Keycloak
keycloak_url = "http://localhost:8080/realms/test/protocol/openid-connect/token"
client_id = "test"
username = "test"

# داده‌های درخواست
data = {
    "grant_type": "password",
    "client_id": "test",
    "client_secret": "h5VYkf6g2FFiFsApChQFtJfajn2gG6lT",
    "username": "test3@gmail.com",
    "password": "test44",
}

# ارسال درخواست به Keycloak
response = requests.post(keycloak_url, data=data)

# بررسی پاسخ
if response.status_code == 200:
    print(response.text)
    tokens = response.json()
    access_token = tokens.get("access_token")
    print("Access Token:", access_token)
else:
    print("Error:", response.status_code, response.text)
