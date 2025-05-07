#!/bin/bash
set -ex

# Script called by CRONTAB for `cosmian` user on VM `demo-kms.cosmian.dev`
# CRONTAB entry:
# 0 0 * * 0 /home/cosmian/reinitialize_kms.sh

# Pre-requisites
# wget https://package.cosmian.com/cli/0.1.2/ubuntu-22.04/cosmian-cli_0.1.2-1_amd64.deb
# apt install -y ./cosmian-cli_0.1.2-1_amd64.deb
# apt install -y redis-tools

HOST_URL=http://0.0.0.0:8080
KEYS_DIR=~

redis-cli flushall

# Import Google Workspace CSE key
cosmian --kms-url $HOST_URL kms sym keys import -t google_cse $KEYS_DIR/google_cse.json google_cse

# Import Microsoft DKE keys
cosmian --kms-url $HOST_URL kms rsa keys import -t dke_key -p ms_dke_pub_key $KEYS_DIR/priv-demo-kms.cosmian.dev.json ms_dke_priv_key
cosmian --kms-url $HOST_URL kms rsa keys import -t dke_key -k ms_dke_priv_key $KEYS_DIR/demo-kms.cosmian.dev.json ms_dke_pub_key
