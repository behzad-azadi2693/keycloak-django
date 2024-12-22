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



# keycloak in the server deployment
```
1- openssl req -newkey rsa:2048 -nodes -keyout keycloak.key -x509 -days 365 -out keycloak.crt -subj "/CN=keycloak.itscom.ir"
2- cat keycloak.key keycloak.crt > tls.pem

save into certs directory
```

# config nginx for deploymn:
```
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name keycloak.itscom.ir;

    return 301 https://$host$request_uri;
}

# HTTPS Reverse Proxy for Keycloak
server {
    listen 443 ssl;
    server_name keycloak.itscom.ir;

    # SSL Certificate and Key
    ssl_certificate /path-to-certs-dir-above/keycloak.crt;
    ssl_certificate_key /path-to-certs-dir-above/keycloak.key;

    # Recommended SSL Protocols and Cipher Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    #add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    # Proxy to Keycloak
    location / {
        proxy_pass https://localhost:8443; # Change localhost if Keycloak is on a different server
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout Settings
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;

        # Handle WebSocket Connections
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

# keycloak service for deployment:
```
services:
  postgres:
    image: postgres
    hostname: ${POSTGRES_HOST}
    container_name: postgres_keycloak
    restart: on-failure
    environment: 
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    env_file:
      - .env
    expose:
      - ${POSTGRES_PORT}
    ports:
      - ${POSTGRES_PORT}:${POSTGRES_PORT}
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    networks: 
      - keycloak_network

  keycloak:
    image: quay.io/keycloak/keycloak:latest
    container_name: keycloak_container
    command: start --https-certificate-file=/certs/tls.pem --https-certificate-key-file=/certs/tls.pem --http-port=8443
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: ${KEYCLOAK_ADMIN}
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres/${POSTGRES_DB}
      KC_DB_USERNAME: ${POSTGRES_USER}
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD}
      KC_HTTPS_CERTIFICATE_FILE: /certs/tls.pem
      KC_HOSTNAME: fanapkeycloak.itscom.ir
    ports:
      - 8443:8443
    volumes:
      - ./certs:/certs
    depends_on:
      - postgres
    networks:
      - keycloak_network


networks:
  keycloak_network:

```