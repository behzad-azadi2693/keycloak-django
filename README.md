run service django 


first ensure install docker, docker compose and nginx and read README.md in keycloak directory for up service keycloak

1- Create a .env file with the following environment variables in this directory:
```
KEYCLOAK_SERVER_URL=keycloak.YOURDOMAIN
KEYCLOAK_CLIENT_ID=client_id
KEYCLOAK_REALM_NAME=realm_name
KEYCLOAK_CLIENT_SECRET_KEY=client_secret_key
KEYCLOAK_USER_REALM_NAME=user_realm_name
KEYCLOAK_USERNAME=username
KEYCLOAK_PASSWORD=password

REDIS_HOST=redis_host
REDIS_PORT=6380
REDIS_PASSWORD=redis_password

SECRET_KEY='django-insecure-=g_^g!*g)_l1-ld9t-pssxp1p^8)q1*nwax^=d=l$vp-*yid(t'
DEBUG=True
WEB_DOMAIN=account.niadad.ir
DJANGO_PORT=8000
ACCOUNT_HOST=accounts
```


2- To run the service, use the command:
```
docker compose up -d
```

3- Wait a few minutes and use the following command to show containers:
```
docker ps
```

4- Configure NGINX for accessibility to the services (accounts.ir):

Go to /etc/nginx/sites-enabled and create file accounts.ir.
```
access_log /var/log/nginx/accounts.log;

server {
    listen 80;
    server_name accounts.YOUR_DOMAIN;
    charset utf-8;

    
	location /static/ {
            alias PATH_YOUR_STATIC_DIRECTORY;
        }

    location / {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect  off;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Script-Name /pgadmin-web;
    }
}
```

save file and use command below for nginx:
```
sudo systemctl restart nginx
```

6- In your favorite DNS provider, configure subdomains (accounts) for the above service. With these subdomain, you can access your service in a browser
