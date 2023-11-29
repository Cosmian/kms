#!/bin/bash
set -ex

if [ "$#" -eq 0 ]; then
    echo -e "Usage: ./local_ossl_instl.sh <OPENSSL_DIR>"
    exit 1
fi

echo "Setup for OpenSSL version 3.1.0 with FIPS module"
echo "Installing OpenSSL to ${1} ..."

if [[ ! -d "${1}" ]]; then
    echo "ERROR: Specified directory does not exist"
    exit 2
fi

pushd "$1"
OPENSSL_DIR=$(pwd)
export OPENSSL_DIR
popd

# Creating ssl config files directory.
mkdir -p "${OPENSSL_DIR}/ssl"

pushd .

# Downloading and installing OpenSSL 3.1.0.
cd "$(mktemp -d)"
wget https://github.com/openssl/openssl/releases/download/openssl-3.1.0/openssl-3.1.0.tar.gz

echo -n Extracting compressed archive...
tar -xf openssl-3.1.0.tar.gz
rm openssl-3.1.0.tar.gz

cd openssl-3.1.0/
if [ "$2" = "cross-compile-windows" ]; then
    ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix="${OPENSSL_DIR}" --openssldir="${OPENSSL_DIR}/ssl" enable-fips no-shared
else
    ./Configure --prefix="${OPENSSL_DIR}" --openssldir="${OPENSSL_DIR}/ssl" enable-fips no-shared
fi
make depend
make -j
make install

# Hardcode config file changes for FIPS module.
# sed replaces enable fips config and disable the default provider
sed -i.bu 's/# .include fipsmodule.cnf/.include fipsmodule.cnf/' "${OPENSSL_DIR}/ssl/openssl.cnf"
sed -i.bu 's/default = default_sect/# default = default_sect/' "${OPENSSL_DIR}/ssl/openssl.cnf"
sed -i.bu 's/# fips = fips_sect/fips = fips_sect\nbase = base_sect\n\n[ base_sect ]\nactivate = 1\n/' "${OPENSSL_DIR}/ssl/openssl.cnf"

echo -e "\nOpenSSL successfully installed at ${OPENSSL_DIR}"

popd

echo -e "\nIf this program was not sourced, remember to export the absolute path of ${OPENSSL_DIR} as an environment variable."
