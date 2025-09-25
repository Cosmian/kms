#!/bin/bash

set -exo pipefail

# --- Declare the following variables for tests
# export TARGET=x86_64-unknown-linux-gnu
# export TARGET=x86_64-apple-darwin
# export TARGET=aarch64-apple-darwin
# export DEBUG_OR_RELEASE=debug
# export OPENSSL_DIR=/usr/local/openssl
# export SKIP_SERVICES_TESTS="--skip test_mysql --skip test_pgsql --skip test_redis --skip google_cse --skip hsm"
# export FEATURES="non-fips"

ROOT_FOLDER=$(pwd)

# Build the UI on Ubuntu distributions
if [ -f /etc/lsb-release ]; then
  bash .github/scripts/build_ui.sh
fi

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # First build the Debian and RPM packages. It must come at first since
  # after this step `cosmian` and `cosmian_kms` are built with custom features flags (non-fips for example).
  rm -rf target/"$TARGET"/debian
  rm -rf target/"$TARGET"/generate-rpm
  if [ -f /etc/redhat-release ]; then
    cd crate/server && cargo build --features non-fips --release --target "$TARGET" && cd -
    cargo install --version 0.16.0 cargo-generate-rpm --force
    cd "$ROOT_FOLDER"
    cargo generate-rpm --target "$TARGET" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml
  elif [ -f /etc/debian_version ]; then
    cargo install --version 2.4.0 cargo-deb --force
    if [ -n "$FEATURES" ]; then
      cargo deb --target "$TARGET" -p cosmian_kms_server
    else
      cargo deb --target "$TARGET" -p cosmian_kms_server --variant fips
    fi
  fi
fi

if [ -z "$TARGET" ]; then
  echo "Error: TARGET is not set."
  exit 1
fi

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE="--release"
fi

if [ -n "$FEATURES" ]; then
  FEATURES="--features $FEATURES"
fi

if [ -z "$FEATURES" ]; then
  echo "Info: FEATURES is not set."
  unset FEATURES
fi

if [ -z "$SKIP_SERVICES_TESTS" ]; then
  echo "Info: SKIP_SERVICES_TESTS is not set."
  unset SKIP_SERVICES_TESTS
fi

# Add --skip google_cse for forks and dependabot branches
# Indeed, Google CSE tests require credentials that are not available for forks.
if [ "$GITHUB_REPOSITORY" != "Cosmian/kms" ] || [[ "$GITHUB_REF_NAME" == dependabot/* ]]; then
  if [ -z "$SKIP_SERVICES_TESTS" ]; then
    SKIP_SERVICES_TESTS="--skip google_cse"
  else
    SKIP_SERVICES_TESTS="$SKIP_SERVICES_TESTS --skip google_cse"
  fi
  echo "Info: Running on fork or dependabot branch, adding --skip google_cse to SKIP_SERVICES_TESTS"
fi

rustup target add "$TARGET"

if [ -f /etc/lsb-release ]; then
  export HSM_USER_PASSWORD="12345678"

  # Install Utimaco simulator and run tests
  bash .github/reusable_scripts/test_utimaco.sh
  cargo test -p utimaco_pkcs11_loader --target "$TARGET" $RELEASE --features utimaco -- tests::test_hsm_all
  # shellcheck disable=SC2086
  HSM_MODEL=utimaco HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID=0 cargo test --target "$TARGET" $FEATURES $RELEASE -- tests::hsm::test_all

  # Install SoftHSM2 and run tests
  sudo apt-get install -y libsofthsm2

  sudo softhsm2-util --init-token --slot 0 --label "my_token_1" --so-pin "$HSM_USER_PASSWORD" --pin "$HSM_USER_PASSWORD"
  HSM_SLOT_ID=$(sudo softhsm2-util --show-slots | grep -o "Slot [0-9]*" | head -n1 | awk '{print $2}')

  # shellcheck disable=SC2086
  sudo -E env "PATH=$PATH" HSM_MODEL=softhsm2 HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" cargo test $FEATURES $RELEASE -- tests::hsm::test_all

  cd crate/hsm/softhsm2
  sudo -E env "PATH=$PATH" HSM_USER_PASSWORD="$HSM_USER_PASSWORD" HSM_SLOT_ID="$HSM_SLOT_ID" cargo test --features softhsm2 $RELEASE -- tests::test_hsm_all
  cd ../../..
fi

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set."
  exit 1
fi

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE $FEATURES

COSMIAN_KMS_EXE="target/$TARGET/$DEBUG_OR_RELEASE/cosmian_kms"

# Must use OpenSSL with this specific version 3.2.0
OPENSSL_VERSION_REQUIRED="3.2.0"
correct_openssl_version_found=$(./"$COSMIAN_KMS_EXE" --info | grep "$OPENSSL_VERSION_REQUIRED")
if [ -z "$correct_openssl_version_found" ]; then
  echo "Error: The correct OpenSSL version $OPENSSL_VERSION_REQUIRED is not found."
  exit 1
fi

if [ "$(uname)" = "Linux" ]; then
  ldd "$COSMIAN_KMS_EXE" | grep ssl && exit 1
else
  otool -L "$COSMIAN_KMS_EXE" | grep openssl && exit 1
fi

find . -type d -name cosmian-kms -exec rm -rf \{\} \; -print || true
rm -f /tmp/*.toml

export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE $FEATURES

declare -a DATABASES=('redis-findex' 'sqlite' 'postgresql' 'mysql')
for KMS_TEST_DB in "${DATABASES[@]}"; do
  echo "Database KMS: $KMS_TEST_DB"

  # Skip redis-findex in FIPS mode since it is not supported in FIPS mode
  if [ "$KMS_TEST_DB" = "redis-findex" ] && [ -z "$FEATURES" ]; then
    echo "Skipping redis-findex in FIPS mode."
    continue
  fi

  # for now, discard tests on mysql
  if [ "$KMS_TEST_DB" = "mysql" ]; then
    continue
  fi

  # no docker containers on macOS Github runner
  if [ "$(uname)" = "Darwin" ] && [ "$KMS_TEST_DB" != "sqlite" ]; then
    continue
  fi

  # only tests all databases on release mode - keep sqlite for debug
  if [ "$DEBUG_OR_RELEASE" = "debug" ] && [ "$KMS_TEST_DB" != "sqlite" ]; then
    continue
  fi

  export KMS_TEST_DB="$KMS_TEST_DB"

  # shellcheck disable=SC2086
  cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture $SKIP_SERVICES_TESTS
done

# shellcheck disable=SC2086
cargo test --workspace --bins --target $TARGET $RELEASE $FEATURES

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # shellcheck disable=SC2086
  cargo bench --target $TARGET $FEATURES $RELEASE --no-run
fi
