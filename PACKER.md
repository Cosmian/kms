# Install KMS

- sudo apt install docker.io redis certbot python3-certbot-nginx
- créer une conf nginx:

```
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;

        server_name cse.cosmian.com;

        location / {
                return 301 https://$host$request_uri;
        }
}

server {
        server_name cse.cosmian.com;
        listen 443 ssl;

        ssl_certificate /etc/letsencrypt/live/cse.cosmian.com/fullchain.pem; # managed by Certbot
        ssl_certificate_key /etc/letsencrypt/live/cse.cosmian.com/privkey.pem; # managed by Certbot
#        include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
#        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

        location /.well-known/ {
                root /var/www/html;
                # Allow CORS calls: see https://support.google.com/a/answer/10743588?hl=en
                add_header 'Access-Control-Allow-Origin' '*';
        }

        location / {
                proxy_pass http://localhost:9998/;
        }
}
```

- sudo certbot --nginx

## partie config CSE (pas utile pour Packer je pense, si ? en tout cas il faudrait le consigner quelque part)

- configurer CSE:
 https://docs.cosmian.com/cosmian_key_management_system/google_cse/google_cse/
 - .well-known (downloader le JSON de Google Workspace CSE dans le paneau Credentials)

 - créer un 'kms.json'
 - KMS_CLI_CONF=./kms.json cargo run --bin ckms -- login
 se logger avec les creds de 'blue@cosmian.com'
 - créer une clé pour wrap/unwrap: 
 KMS_CLI_CONF=./kms.json cargo run --bin ckms -- sym keys import -t google_cse documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json google_cse
 - ajouter les droits pour faire les opérations:
 KMS_CLI_CONF=./kms.json cargo run --bin ckms -- access-rights grant '*' google_cse destroy

