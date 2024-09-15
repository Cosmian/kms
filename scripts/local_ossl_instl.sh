#!/bin/bash
set -ex

if [ "$#" -eq 0 ]; then
    echo -e "Usage: ./local_ossl_instl.sh <OPENSSL_DIR>"
    exit 1
fi

if [[ ! "${1}" = /* ]]; then
    echo "Error: path must be absolute (ex: /tmp/openssl_fips)"
    exit 1
fi

OPENSSL_VERSION=3.2.0
echo "Setup for OpenSSL version $OPENSSL_VERSION with FIPS module"
echo "Installing OpenSSL to ${1}..."

OPENSSL_DIR="${1}"

# Creating ssl config files directory.
rm -rf "${OPENSSL_DIR}/ssl"
mkdir -p "${OPENSSL_DIR}/ssl"

# Downloading and installing OpenSSL
cd "$(mktemp -d)"
VERSION="openssl-$OPENSSL_VERSION"
URL_PREFIX=${VERSION}
# VERSION=openssl-1.1.1w
# URL_PREFIX=OpenSSL_1_1_1w
wget https://github.com/openssl/openssl/releases/download/${URL_PREFIX}/${VERSION}.tar.gz

echo -n Extracting compressed archive...
tar -xf ${VERSION}.tar.gz
rm ${VERSION}.tar.gz

cd ${VERSION}/
if [ "${2}" = "cross-compile-windows" ]; then
    ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix="${OPENSSL_DIR}" --openssldir="${OPENSSL_DIR}/ssl" threads enable-fips no-shared enable-weak-ssl-ciphers
else
    ./Configure --prefix="${OPENSSL_DIR}" --openssldir="${OPENSSL_DIR}/ssl" threads enable-fips no-shared enable-weak-ssl-ciphers
fi

# Just in case, clean a previous installation.
make clean
# Build.
make depend
make -j
make -j install

# Hardcode config file changes for FIPS module.
# sed replaces enable fips config and disable the default provider.
# Careful: change sed delimiter to comma when dealing with filepaths.
sed -i.bu "s,# .include fipsmodule.cnf,.include ${OPENSSL_DIR}/ssl/fipsmodule.cnf," "${OPENSSL_DIR}/ssl/openssl.cnf"
sed -i.bu 's/# activate = 1/activate = 1/' "${OPENSSL_DIR}/ssl/openssl.cnf"
sed -i.bu 's/# fips = fips_sect/fips = fips_sect\nbase = base_sect\n\n[ base_sect ]\nactivate = 1\n/' "${OPENSSL_DIR}/ssl/openssl.cnf"
# Remove backup file.
rm -f "${OPENSSL_DIR}/ssl/openssl.cnf.bu"

# Remove non-required folder
rm -rf "${OPENSSL_DIR:?}/bin"
rm -rf "${OPENSSL_DIR:?}/share"
echo -e "\nOpenSSL successfully installed at ${OPENSSL_DIR}"
echo -e "\nIf this program was not sourced, remember to export the absolute path of ${OPENSSL_DIR} as an environment variable."
