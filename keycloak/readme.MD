this docker compose for running keycloak service with postgresql database:

first ensure install docker, docker compose and nginx 

1- Create a .env file with the following environment variables in this directory:
```
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
KEYCLOAK_PORT=8080

POSTGRES_DB=account
POSTGRES_USER=account
POSTGRES_PASSWORD=account
POSTGRES_DB_PORT=5432
POSTGRES_HOST=postgres

PGADMIN_DEFAULT_PASSWORD=admin
PGADMIN_DEFAULT_EMAIL=admin@gmail.com
```

2- To run the service, use the command:
```
docker compose up -d
```

3- Wait a few minutes and use the following command to show containers:
```
docker ps
```

4- Configure NGINX for accessibility to the services (Keycloak admin console and pgAdmin panel):

Go to /etc/nginx/sites-enabled and create two files named pgadmin.ir and keycloak.ir.


#pgadmin.ir
```
access_log /var/log/nginx/pgadmin.log;

server {
    listen 80;
    server_name pgadmin.YOUR_DOMAIN;
    charset utf-8;

    location / {
        proxy_pass http://pgadmin/;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect  off;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Script-Name /pgadmin-web;
    }
}
```

#keycloak.ir
```
access_log /var/log/nginx/keycloak.log;

server {
        listen 80;
        server_name keycloak.YOURDOAMIN;
        charset utf-8;

        location / {
            proxy_redirect off;
            proxy_set_header  Host $http_host;
            proxy_set_header  X-Real-IP $remote_addr;
            proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header  X-Forwarded-Host $server_name;
            
            proxy_pass http://localhost:8080/;
        }
}
```

save file and use command below for nginx:
```
sudo systemctl restart nginx
```

6- In your favorite DNS provider, configure subdomains (keycloak and pgadmin) for the above services. With these subdomains, you can access your services in a browser. Use the information in the .env file to log into these keycloak consol admin and pgadmin panel

