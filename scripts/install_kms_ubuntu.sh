#!/bin/bash

set +x

export DEBIAN_FRONTEND=noninteractive

systemctl stop supervisor
systemctl disable supervisor

# Update packages and install unzip
apt-get update && apt-get install -y unzip

# Download KMS zip file
curl -o kms-ubuntu-22_04.zip https://package.cosmian.com/kms/4.12.0/ubuntu_22_04.zip

# Extract content and copy the executable
unzip kms-ubuntu-22_04.zip && cp ubuntu_22_04/cosmian_kms_server /usr/local/sbin/cosmian_kms && chmod 755 /usr/local/sbin/cosmian_kms && rm -rf kms-ubuntu-22_04.zip ubuntu_22_04/

# Configure Supervisor
cat > /etc/supervisor/conf.d/cosmian_kms.conf <<EOF
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
cat > /etc/cosmian_kms/server.toml <<EOF
default_username = "admin"

[http]
port = 8080
hostname = "0.0.0.0"
EOF

systemctl start ssh
systemctl enable supervisor