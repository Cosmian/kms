#!/bin/bash
set -ex

export OPENSSL_DIR=/usr/local/openssl

env

if [ -z "$OPENSSL_DIR" ]; then
    echo "Error: OPENSSL_DIR is not set."
    exit 1
fi

if [ -z "$OS_NAME" ]; then
    OS_NAME=ubuntu_20_04
else
    OS_NAME=${OS_NAME#fips_}
fi

if [ -z "$ARCHITECTURE" ]; then
    ARCHITECTURE=$(uname -m)
fi

OPENSSL_VERSION=3.2.0
echo "Setup for OpenSSL version $OPENSSL_VERSION with FIPS module"
echo "Installing OpenSSL to ${1}..."

# Creating ssl config files directory.
rm -rf "${OPENSSL_DIR}/ssl"
mkdir -p "${OPENSSL_DIR}/ssl"

# Downloading and installing OpenSSL
wget "https://package.cosmian.com/openssl/$OPENSSL_VERSION/${OS_NAME}/${ARCHITECTURE}/${OPENSSL_VERSION}.tar.gz"

mv "${OPENSSL_VERSION}.tar.gz" "${OPENSSL_DIR}"
echo -n Extracting compressed archive...
cd "${OPENSSL_DIR}"
tar -xf "$OPENSSL_VERSION.tar.gz"
find .
rm "$OPENSSL_VERSION.tar.gz"
