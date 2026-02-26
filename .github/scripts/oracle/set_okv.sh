#!/bin/bash

set -ex

#
# Copy the Cosmian PKCS#11 library from the KMS Docker image to the Oracle
# Key Vault (OKV) server, configuring it as a Generic HSM provider.
#
# DOCKER_IMAGE_NAME must be set to the loaded KMS docker image name.
# The OKV server must be reachable via SSH with the alias "okv"
# (configured in ~/.ssh/config).
#
# SSH config example:
# Host okv
#     HostName 192.168.1.210
#     User cosmian
#     IdentityFile ~/.ssh/id_rsa
#

if [ -z "${DOCKER_IMAGE_NAME}" ]; then
    echo "ERROR: DOCKER_IMAGE_NAME must be set to the KMS docker image name."
    echo "  Example: export DOCKER_IMAGE_NAME=cosmian-kms:5.10.0-non-fips"
    exit 1
fi

rm -f libcosmian_pkcs11.so

# Create a temporary (non-running) container from the KMS image to copy the library out.
# Using docker create avoids the entrypoint issue that would cause the container to exit
# immediately when trying to run a shell command (e.g. `tail -f /dev/null`).
docker rm dll_p11 2>/dev/null || true
CONTAINER_ID=$(docker create --name dll_p11 "${DOCKER_IMAGE_NAME}")
docker cp "${CONTAINER_ID}:/usr/lib/libcosmian_pkcs11.so" .
docker rm dll_p11

# Copy the library to the OKV server
scp -O libcosmian_pkcs11.so okv:
ssh okv "sudo cp ~/libcosmian_pkcs11.so /usr/local/okv/hsm/generic/"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/libcosmian_pkcs11.so"
ssh okv "sudo rm -f /var/okv/log/hsm/*"

rm -f libcosmian_pkcs11.so

#
# Copy CLI config
#
scp -O .github/scripts/oracle/cosmian_okv.toml okv:cosmian.toml
ssh okv "sudo mv ~/cosmian.toml /usr/local/okv/hsm/generic"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/cosmian.toml"

#
# Copy OKV generic HSM environment variables file
#
scp -O .github/scripts/oracle/okv_hsm_env okv:
ssh okv "sudo mv ~/okv_hsm_env /usr/local/okv/hsm/generic/okv_hsm_env"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/okv_hsm_env"

#
# Copy OKV generic HSM configuration file
#
scp -O .github/scripts/oracle/okv_hsm_conf okv:
ssh okv "sudo mv ~/okv_hsm_conf /usr/local/okv/hsm/generic/okv_hsm.conf"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/okv_hsm.conf"
