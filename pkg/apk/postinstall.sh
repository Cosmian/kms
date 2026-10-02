#!/bin/sh
mkdir -p /var/lib/cosmian /var/log/cosmian
chmod 0750 /var/lib/cosmian /var/log/cosmian
echo "Cosmian KMS installed. Enable it with: rc-update add cosmian_kms default && rc-service cosmian_kms start"
exit 0
