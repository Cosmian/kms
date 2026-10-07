#!/bin/sh
mkdir -p /var/lib/cosmian /var/log/cosmian
chmod 0750 /var/lib/cosmian /var/log/cosmian
# The "kms" user/group is created by preinstall.sh, which runs before this
# script. The service (see cosmian_kms.initd's command_user) runs as "kms"
# and needs write access to both directories (sqlite data, OpenRC log output).
chown kms:kms /var/lib/cosmian /var/log/cosmian
echo "Cosmian KMS installed. Enable it with: rc-update add cosmian_kms default && rc-service cosmian_kms start"
exit 0
