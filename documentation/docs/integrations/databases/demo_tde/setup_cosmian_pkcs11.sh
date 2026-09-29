#!/bin/bash
set -ex

# Copy to Oracle's HSM directory
mkdir -p /opt/oracle/extapi/64/hsm/Cosmian/
mv /home/oracle/libcosmian_pkcs11.so /opt/oracle/extapi/64/hsm/Cosmian/
chown oracle:oinstall /opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so

mkdir -p /home/oracle/.cosmian/
mv /home/oracle/ckms.toml /home/oracle/.cosmian/
chown oracle:oinstall /home/oracle/.cosmian/ckms.toml

# Create keystore directories
mkdir -p /etc/ORACLE/KEYSTORES/FREE
chown -R oracle:oinstall /etc/ORACLE/KEYSTORES/FREE

# Setup logging
chown -R oracle:oinstall /var/log
