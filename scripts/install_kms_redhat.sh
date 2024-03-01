#!/bin/bash

set +x


# Update packages and install dependencies
yum update -y && yum install -y unzip nginx

# Download KMS zip file
curl -o kms-centos7.zip https://package.cosmian.com/kms/4.12.0/centos7.zip

# Extract content and copy the executable
unzip kms-centos7.zip && cp centos7/cosmian_kms_server /usr/local/sbin/cosmian_kms && chmod 755 /usr/local/sbin/cosmian_kms && rm -rf centos7.zip centos7/

# Configure Supervisor
cat > /etc/supervisord.d/cosmian_kms.ini <<EOF
[program:cosmian_kms]
command=/usr/local/sbin/cosmian_kms
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

# Reload Supervisor and start KMS service
systemctl reload supervisord
systemctl start cosmian_kms
