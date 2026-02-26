#!/bin/bash

set -ex

#
# Copy the Cosmian PKCS#11 library from the KMS Docker image.
# The library is bundled inside the KMS Docker image (libcosmian_pkcs11.so).
# DOCKER_IMAGE_NAME must be set (it is exported by nix.sh before calling
# test_docker_image.sh when --test is passed to the docker subcommand).
#

if [ -z "${DOCKER_IMAGE_NAME}" ]; then
    echo "ERROR: DOCKER_IMAGE_NAME must be set to the KMS docker image name."
    echo "  Example: export DOCKER_IMAGE_NAME=cosmian-kms:5.10.0-non-fips"
    exit 1
fi

# Repo root: set_hsm.sh is called from the repository root by test_docker_image.sh.
REPO_ROOT="${REPO_ROOT:-$(pwd)}"

rm -f libcosmian_pkcs11.so

# Determine the KMS variant from the image name (non-fips / fips).
if [[ "${DOCKER_IMAGE_NAME}" == *"-non-fips"* ]]; then
    CLI_STATIC_RESULT="${REPO_ROOT}/result-cli-non-fips-static"
else
    CLI_STATIC_RESULT="${REPO_ROOT}/result-cli-fips-static"
fi

# Prefer the static-linked CLI derivation's library (targets glibc 2.28, works
# on Oracle Linux 8) over the one embedded in the Docker image (which may have
# been built against a newer glibc and would fail with ORA-28376 on OL8).
if [ -f "${CLI_STATIC_RESULT}/lib/libcosmian_pkcs11.so" ]; then
    echo "Using OL8-compatible libcosmian_pkcs11.so from ${CLI_STATIC_RESULT}/lib/"
    cp "${CLI_STATIC_RESULT}/lib/libcosmian_pkcs11.so" .
else
    echo "Static CLI result not found at ${CLI_STATIC_RESULT}; extracting from Docker image."
    # Create a temporary (non-running) container from the KMS image to copy the library out.
    docker rm dll_p11 2>/dev/null || true
    CONTAINER_ID=$(docker create --name dll_p11 "${DOCKER_IMAGE_NAME}")
    docker cp "${CONTAINER_ID}:/usr/lib/libcosmian_pkcs11.so" .
    docker rm dll_p11
fi

# Check that the library is loadable inside the Oracle container.
# The Oracle container is Oracle Linux 8 (glibc 2.28); newer Nix-built libraries
# require glibc 2.34+.  Fail early with a clear message rather than an opaque
# ORA-28376 / ORA-28353 deep inside Oracle.
MISSING_DEPS=$(docker run --rm \
    -v "$(pwd)/libcosmian_pkcs11.so:/tmp/libcosmian_pkcs11.so" \
    --entrypoint ldd \
    oracle \
    /tmp/libcosmian_pkcs11.so 2>&1 | grep "not found" || true)
if [ -n "$MISSING_DEPS" ]; then
    echo "ERROR: libcosmian_pkcs11.so is incompatible with the Oracle container's glibc."
    echo "Missing symbols:"
    echo "$MISSING_DEPS"
    echo ""
    echo "Fix: ensure result-cli-{non-fips,fips}-static contains a glibc-2.28-compatible build"
    echo "     or update default.nix to add pkcs11LibDrv to the docker-image-* derivations."
    exit 1
fi

#
# Install the library and the Cosmian KMS client configuration into the
# Oracle Database container so that Oracle TDE can use Cosmian as its HSM.
#
cat <<'EOF' >setup_cosmian_pkcs11.sh
set -ex

mkdir -p /opt/oracle/extapi/64/hsm/Cosmian/
mv /home/oracle/libcosmian_pkcs11.so /opt/oracle/extapi/64/hsm/Cosmian/
chown oracle:oinstall /opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so

mkdir -p /home/oracle/.cosmian/
mv /home/oracle/cosmian.toml /home/oracle/.cosmian/
chown oracle:oinstall /home/oracle/.cosmian/cosmian.toml

mkdir -p /etc/ORACLE/KEYSTORES/FREE
chown -R oracle:oinstall /etc/ORACLE/KEYSTORES/FREE

chown -R oracle:oinstall /var/log
rm -f /var/log/cosmian-pkcs11.log

mkdir -p /etc/ORACLE/KEYSTORES/FREE
chown -R oracle:oinstall /etc/ORACLE/KEYSTORES/FREE

EOF
chmod +x setup_cosmian_pkcs11.sh

#
# Copy files and run setup script
#
docker cp libcosmian_pkcs11.so oracle:/home/oracle/
docker cp .github/scripts/oracle/cosmian.toml oracle:/home/oracle/
docker cp setup_cosmian_pkcs11.sh oracle:/home/oracle/
docker exec -u root -i oracle bash -c "/home/oracle/setup_cosmian_pkcs11.sh"
rm -f setup_cosmian_pkcs11.sh libcosmian_pkcs11.so

#
# Setup Oracle TDE for HSM
#
bash .github/scripts/oracle/run_sql_commands.sh
