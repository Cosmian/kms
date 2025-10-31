#!/usr/bin/env bash
# Common build utilities for Cosmian KMS build and packaging scripts
# Source this file to use the functions

# Initialize common environment variables and flags
# Sets: DEBUG_OR_RELEASE, FEATURES, RELEASE_FLAG, FEATURES_FLAG array, VARIANT_NAME
init_build_env() {
  # Set defaults if not already set
  DEBUG_OR_RELEASE="${DEBUG_OR_RELEASE:-debug}"
  FEATURES="${FEATURES:-}"

  RELEASE_FLAG=""
  [ "$DEBUG_OR_RELEASE" = "release" ] && RELEASE_FLAG="--release"

  FEATURES_FLAG=()
  [ -n "$FEATURES" ] && FEATURES_FLAG=(--features "$FEATURES")

  VARIANT_NAME="FIPS"
  [ -n "$FEATURES" ] && VARIANT_NAME="non-FIPS"

  # Export variables so they're available in the calling script
  export DEBUG_OR_RELEASE FEATURES VARIANT_NAME
}

# Get repository root directory
get_repo_root() {
  local script_dir="${1:-.}"
  cd "$script_dir" || exit
  git rev-parse --show-toplevel 2>/dev/null || (cd "$script_dir/../.." && pwd)
}

# Setup RUST_LOG for tests
setup_test_logging() {
  export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"
}

# Check if a TCP port is open (portable bash implementation)
check_port() {
  local host="$1" port="$2"
  (exec 3<>/dev/tcp/"$host"/"$port") 2>/dev/null &
  local pid=$!
  local count=0
  while [ $count -lt 20 ]; do
    kill -0 $pid 2>/dev/null || {
      wait $pid 2>/dev/null
      return $?
    }
    sleep 0.1
    count=$((count + 1))
  done
  kill -9 $pid 2>/dev/null
  wait $pid 2>/dev/null
  return 1
}

# Run database tests (library and specific)
# Usage: run_db_tests <db_type> [extra_test_args]
run_db_tests() {
  local db_type="$1"
  shift

  echo "Running $db_type library tests..."
  KMS_TEST_DB="$db_type" cargo test --workspace --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture "$@"

  echo "Running $db_type database-specific tests..."
  local test_name="test_db_${db_type//-/_}"
  KMS_TEST_DB="$db_type" cargo test -p cosmian_kms_server_database --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture "$test_name" --ignored
}

# Check database service availability and run tests
# Usage: check_and_test_db <db_name> <db_type> <host_var> <port_var>
check_and_test_db() {
  local db_name="$1" db_type="$2" host_var="$3" port_var="$4"
  local host="${!host_var}" port="${!port_var}"

  if check_port "$host" "$port"; then
    echo "$db_name is running at $host:$port"
    run_db_tests "$db_type"
    echo "$db_name tests completed successfully."
  else
    echo "Error: $db_name is not running at $host:$port" >&2
    exit 1
  fi
}

# Prepare OpenSSL staging directory for packaging
prepare_openssl_staging() {
  local repo_root="${1:-$(pwd)}"
  : "${FEATURES:=}"

  local variant_name="FIPS" module_name="fips"
  [ -n "$FEATURES" ] && variant_name="non-FIPS" && module_name="legacy"

  echo "Preparing OpenSSL artifacts for ${variant_name} packaging..."

  local openssl_staging="$repo_root/target/openssl-staging"
  rm -rf "$openssl_staging"
  mkdir -p "$openssl_staging/lib64/ossl-modules"

  local openssl_path openssl_dir
  openssl_path=$(type -p openssl || command -v openssl)
  [ -z "$openssl_path" ] && {
    echo "Error: openssl not found in PATH" >&2
    return 1
  }

  openssl_dir=$(dirname "$(dirname "$openssl_path")")
  echo "Using OpenSSL from: $openssl_dir"
  echo "Staging OpenSSL artifacts to: $openssl_staging"

  # Determine module extension (.so for Linux, .dylib for macOS)
  local module_ext="so"
  [ "$(uname)" = "Darwin" ] && module_ext="dylib"

  # Copy the appropriate module
  local module_found=false
  for libdir in lib64 lib; do
    if [ -f "$openssl_dir/$libdir/ossl-modules/${module_name}.${module_ext}" ]; then
      cp "$openssl_dir/$libdir/ossl-modules/${module_name}.${module_ext}" "$openssl_staging/lib64/ossl-modules/${module_name}.so"
      echo "Copied ${module_name}.${module_ext} from $libdir (saved as ${module_name}.so)"
      module_found=true
      break
    fi
  done

  [ "$module_found" = "false" ] && {
    echo "Error: ${module_name}.${module_ext} not found in lib or lib64/ossl-modules" >&2
    return 1
  }

  # Copy SSL configuration files for FIPS variant
  if [ -z "$FEATURES" ]; then
    mkdir -p "$openssl_staging/ssl"

    if [ -f "$openssl_dir/ssl/openssl.cnf" ]; then
      cp "$openssl_dir/ssl/openssl.cnf" "$openssl_staging/ssl/"
      sed -i "s|$openssl_dir/ssl|/usr/local/lib/openssl|g" "$openssl_staging/ssl/openssl.cnf"
      echo "Copied and updated openssl.cnf"
    fi

    if [ -f "$openssl_dir/ssl/fipsmodule.cnf" ]; then
      "$openssl_path" fipsinstall \
        -module "$openssl_staging/lib64/ossl-modules/fips.so" \
        -out "$openssl_staging/ssl/fipsmodule.cnf"
      sed -i '/^\[fips_sect\]/a module-filename = /usr/local/lib/openssl/lib64/ossl-modules/fips.so' \
        "$openssl_staging/ssl/fipsmodule.cnf"
      echo "Regenerated fipsmodule.cnf with correct MAC and paths"
    fi
  fi

  echo "OpenSSL ${variant_name} artifacts prepared at: $openssl_staging"
  ls -la "$openssl_staging/lib64/ossl-modules/"
  if [ -z "$FEATURES" ]; then
    ls -la "$openssl_staging/ssl/"
  fi
}
