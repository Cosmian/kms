#!/bin/bash

set +x

export DEBIAN_FRONTEND=noninteractive

# Update packages and install dependencies
apt-get update && apt-get install --no-install-recommends -y unzip nginx && apt-get clean && rm -rf /var/lib/apt/lists/*

# Download KMS zip file
curl -o kms-ubuntu-22_04.zip https://package.cosmian.com/kms/4.12.0/ubuntu_22_04.zip

# Extract content and copy the executable
unzip kms-ubuntu-22_04.zip && cp ubuntu_22_04/cosmian_kms_server /usr/local/sbin/cosmian_kms && chmod 755 /usr/local/sbin/cosmian_kms && rm -rf kms-ubuntu-22_04.zip ubuntu_22_04/

# Configure Supervisor
cat >/etc/supervisor/conf.d/cosmian_kms.conf <<EOF
[program:cosmian_kms]
command=cosmian_kms
directory=/usr/local/sbin
autostart=true
autorestart=true
user=root
stderr_logfile=/var/log/cosmian_kms.err.log
stdout_logfile=/var/log/cosmian_kms.out.log
EOF

# Create KMS configuration directory
mkdir /etc/cosmian_kms

# Configure KMS server
cat >/etc/cosmian_kms/server.toml <<EOF
default_username = "admin"

[http]
port = 8080
hostname = "0.0.0.0"
EOF

# Configure Nginx
cat >/etc/nginx/sites-enabled/default <<EOF
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                return 301 https://$host$request_uri;
        }
}

server {
        server_name _;
        listen 443 ssl;

        ssl_certificate /var/lib/cosmian_vm/data/cert.pem;
        ssl_certificate_key /var/lib/cosmian_vm/data/key.pem;

        location /.well-known/ {
                root /var/www/html;
                # Allow CORS calls: see https://support.google.com/a/answer/10743588?hl=en
                add_header 'Access-Control-Allow-Origin' '*';
        }

        location / {
                proxy_pass http://localhost:8080/;
        }
}
EOF

systemctl start ssh
systemctl enable supervisor
