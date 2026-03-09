#!/bin/bash
set -ex

# Script called by CRONTAB for `cosmian` user on VM `demo-kms.cosmian.dev`
# CRONTAB entry:
# 0 0 * * 0 /home/cosmian/reinitialize_kms.sh

# Pre-requisites
# wget https://package.cosmian.com/kms/X.Y.Z/deb/amd64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_X.Y.Z_amd64.deb
# apt install -y ./cosmian-kms-cli-non-fips-static-openssl_X.Y.Z_amd64.deb
# apt install -y redis-tools

HOST_URL=http://0.0.0.0:8080
KEYS_DIR=~

redis-cli flushall

# Import Google Workspace CSE key
ckms --kms-url $HOST_URL sym keys import -t google_cse $KEYS_DIR/google_cse.json google_cse

# Import Microsoft DKE keys
ckms --kms-url $HOST_URL rsa keys import -t dke_key -p ms_dke_pub_key $KEYS_DIR/priv-demo-kms.cosmian.dev.json ms_dke_priv_key
ckms --kms-url $HOST_URL rsa keys import -t dke_key -k ms_dke_priv_key $KEYS_DIR/demo-kms.cosmian.dev.json ms_dke_pub_key
