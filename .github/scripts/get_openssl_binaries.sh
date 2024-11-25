#!/bin/bash
set -ex

env

if [ -z "$OPENSSL_DIR" ]; then
    echo "Error: OPENSSL_DIR is not set."
    exit 1
fi

if [ -z "$ARCHITECTURE" ]; then
    export ARCHITECTURE=amd64
fi

OPENSSL_VERSION=3.2.0
echo "Setup for OpenSSL version $OPENSSL_VERSION with FIPS module"
echo "Installing OpenSSL to ${1}..."

# Creating ssl config files directory.
rm -rf "${OPENSSL_DIR}/ssl"
mkdir -p "${OPENSSL_DIR}/ssl"

OS_NAME=$(uname -s)
if [ "$(uname -s)" == "Linux" ]; then
    OS_NAME="linux"
else
    OS_NAME="macos"
fi

# Downloading and installing OpenSSL
wget "https://package.cosmian.com/openssl/3.2.0/${OS_NAME}/$ARCHITECTURE/${OPENSSL_VERSION}.tar.gz"

mv "${OPENSSL_VERSION}.tar.gz" "${OPENSSL_DIR}"
echo -n Extracting compressed archive...
cd "${OPENSSL_DIR}"
tar -xf 3.2.0.tar.gz
rm 3.2.0.tar.gz
