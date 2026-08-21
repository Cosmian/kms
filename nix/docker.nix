{
  pkgs ? import <nixpkgs> { },
  # KMS server derivation to include in the image (must include UI)
  kmsServer ? null,
  # Variant: "fips" or "non-fips"
  variant ? "fips",
  # KMS version (from Cargo.toml)
  version,
  # Optional: pass the OpenSSL derivation used to build the server (e.g., from nix/openssl.nix).
  # When provided (recommended for FIPS), Docker will copy configs/modules from here
  # instead of from the server output, ensuring strict reuse of the original derivation configs.
  opensslDrv ? null,
  # Optional: pass the CLI derivation that provides ckms (bin/) and libcosmian_pkcs11.so (lib/).
  # When provided, both are bundled into the image: ckms at /usr/local/bin/ so it can be
  # invoked from within the container, and libcosmian_pkcs11.so at /usr/lib/ so that
  # Oracle TDE HSM tests can extract it via `docker create` + `docker cp`.
  pkcs11LibDrv ? null,
}:

# Note: The kmsServer derivation must be built with a UI parameter
# to include the web interface at /usr/local/cosmian/ui/dist

let

  # Determine the actual KMS server to use
  actualKmsServer =
    if kmsServer != null then
      kmsServer
    else
      builtins.throw "kmsServer parameter is required. Pass it from default.nix";

  # Image name and tag
  imageName = "cosmian-kms";
  imageTag = "${version}-${variant}";

  # Optional OpenSSL derivation absolute path (empty string when not provided)
  opensslDrvPath = if opensslDrv == null then "" else toString opensslDrv;

  # When pkcs11LibDrv is provided, create thin wrapper packages so that ckms and
  # libcosmian_pkcs11.so land in the image via the contents mechanism (proper
  # Nix layers). This is more reliable than fakeRootCommands which can fail
  # with Permission Denied when proot tries to create existing directories.
  pkcs11Contents =
    if pkcs11LibDrv != null then
      [
        (pkgs.runCommand "pkcs11-lib" { } ''
          mkdir -p $out/usr/lib
          cp -L ${pkcs11LibDrv}/lib/libcosmian_pkcs11.so $out/usr/lib/libcosmian_pkcs11.so
        '')
        (pkgs.runCommand "ckms-bin" { } ''
          mkdir -p $out/usr/local/bin
          cp -L ${pkcs11LibDrv}/bin/ckms $out/usr/local/bin/ckms
        '')
      ]
    else
      [ ];

  # Create a minimal runtime environment
  # Include necessary libraries for the KMS server
  # pkcs11Contents items (if any) are added here so that buildEnv merges usr/
  # as a real directory rather than a symlink. Without this, lndir creates
  # old_out/usr as a symlink → read-only nix store path, causing fakeRootCommands
  # mkdir failures and preventing pkcs11-lib/ckms from landing in the image layer.
  runtimeEnv = pkgs.buildEnv {
    name = "kms-runtime-env";
    paths = [
      actualKmsServer
      pkgs.tzdata # Timezone data
      pkgs.coreutils # Basic utilities
      pkgs.bash # Shell for scripts
      pkgs.gnugrep # grep (not provided by coreutils) — required by the CA
      # bundle smoke test and any script relying on grep at runtime.
      # wget, curl, and netcat are required for Docker/Kubernetes health checks.
      # wget: CMD-SHELL health checks (HTTP /health endpoint)
      # curl: Kubernetes liveness/readiness probes and docker-compose wait scripts
      # netcat-openbsd: nc -z TLS port probes (-z flag requires BSD/OpenBSD semantics)
      # These replace the previous busybox dependency which caused
      # "failed to register layer: openat dev/pts/ptmx" errors on older containerd versions.
      pkgs.wget
      pkgs.curl
      pkgs.netcat-openbsd
    ]
    ++ pkcs11Contents;
  };

  # CA bundle derivation used in fakeRootCommands to copy into /etc/ssl/certs/
  caBundle = pkgs.cacert;

  # Create home and data directories
  kmsDirectories = pkgs.runCommand "kms-directories" { } ''
    mkdir -p $out/home/kms
    mkdir -p $out/var/lib/cosmian-kms
    mkdir -p $out/tmp
    chmod 1777 $out/tmp
  '';

  # Create a startup script that sets up the environment
  startupScript = pkgs.runCommand "docker-entrypoint" { } ''
        mkdir -p $out/bin
        cat > $out/bin/docker-entrypoint.sh << 'EOF'
    #!${pkgs.bash}/bin/bash
    set -e

          echo "=== Docker Entrypoint Debug Info ==="
          echo "Architecture: $(uname -m)"
          echo "Kernel: $(uname -r)"
          echo "PATH: $PATH"
          echo ""

          echo "=== Checking binary locations ==="
          echo "which cosmian_kms: $(which cosmian_kms || echo 'NOT FOUND IN PATH')"
          echo "ls -la /bin/cosmian_kms:"
          ls -la /bin/cosmian_kms || echo "NOT FOUND"
          echo "ls -la /usr/local/bin/cosmian_kms:"
          ls -la /usr/local/bin/cosmian_kms || echo "NOT FOUND"
          echo ""

          echo "=== Checking dynamic linker and libraries ==="
          ARCH=$(uname -m)
          if [ "$ARCH" = "x86_64" ]; then
            echo "Expected linker: /lib64/ld-linux-x86-64.so.2"
            ls -la /lib64/ld-linux-x86-64.so.2 || echo "NOT FOUND"
            echo "Libraries in /lib/x86_64-linux-gnu/:"
            ls -la /lib/x86_64-linux-gnu/ | head -20 || echo "NOT FOUND"
          elif [ "$ARCH" = "aarch64" ]; then
            echo "Expected linker: /lib/ld-linux-aarch64.so.1"
            ls -la /lib/ld-linux-aarch64.so.1 || echo "NOT FOUND"
            echo "Libraries in /lib/aarch64-linux-gnu/:"
            ls -la /lib/aarch64-linux-gnu/ | head -20 || echo "NOT FOUND"
          fi
          echo ""

          echo "=== Checking binary ELF information ==="
          if command -v readelf >/dev/null 2>&1; then
            echo "Binary interpreter:"
            readelf -l /usr/local/bin/cosmian_kms | grep interpreter || echo "readelf failed or no interpreter found"
          else
            echo "readelf not available"
          fi
          echo ""

          echo "=== Checking ldd output ==="
          if command -v ldd >/dev/null 2>&1; then
            ldd /usr/local/bin/cosmian_kms || echo "ldd failed"
          else
            echo "ldd not available"
          fi
          echo ""

          echo "=== Attempting to execute binary directly ==="
          if [ -x /bin/cosmian_kms ]; then
            echo "/bin/cosmian_kms is executable, trying --version..."
            /bin/cosmian_kms --version || echo "FAILED with exit code $?"
          else
            echo "/bin/cosmian_kms is NOT executable or does not exist"
          fi
          echo "=== End Debug Info ==="
          echo ""

          echo "=== OpenSSL runtime configuration ==="
          echo "OPENSSL_CONF: ''${OPENSSL_CONF:-unset}"
          echo "OPENSSL_MODULES: ''${OPENSSL_MODULES:-unset}"
          if [ -f /usr/local/cosmian/lib/ssl/openssl.cnf ]; then
            echo "Dumping /usr/local/cosmian/lib/ssl/openssl.cnf (first 80 lines):"
            head -n 80 /usr/local/cosmian/lib/ssl/openssl.cnf || true
          else
            echo "/usr/local/cosmian/lib/ssl/openssl.cnf not found"
          fi
          if [ -f /usr/local/cosmian/lib/ssl/fipsmodule.cnf ]; then
            echo "Dumping /usr/local/cosmian/lib/ssl/fipsmodule.cnf:"
            cat /usr/local/cosmian/lib/ssl/fipsmodule.cnf || true
          else
            echo "/usr/local/cosmian/lib/ssl/fipsmodule.cnf not found"
          fi
          echo "=== End OpenSSL runtime configuration ==="
          echo ""

          # Create data directory if it doesn't exist
          mkdir -p /var/lib/cosmian-kms

        # If no arguments provided, try starting from config file, else use defaults
        if [ $# -eq 0 ]; then
          CONF_PATH="$${COSMIAN_KMS_CONF:-}"
          if [ -z "$CONF_PATH" ]; then CONF_PATH="/etc/cosmian/kms.toml"; fi
          if [ -f "$CONF_PATH" ]; then
            echo "Starting Cosmian KMS with configuration: $CONF_PATH"
            exec cosmian_kms -c "$CONF_PATH"
          else
            # No config file found, start with default SQLite configuration
            echo "Starting Cosmian KMS with default SQLite configuration"
            echo "Database location: /var/lib/cosmian-kms/sqlite-data"
            echo "HTTP port: 9998"
            echo ""
            echo "To use a custom configuration:"
            echo "  - Mount a config file and set COSMIAN_KMS_CONF environment variable"
            echo "  - Or pass command-line arguments: docker run cosmian-kms --database-type postgres --database-url ..."
            echo ""
            exec cosmian_kms --database-type sqlite --sqlite-path /var/lib/cosmian-kms/sqlite-data
          fi
        else
          # Execute the KMS server with provided arguments
          exec cosmian_kms "$@"
        fi
    EOF
        chmod +x $out/bin/docker-entrypoint.sh
  '';

  # Root filesystem overlay with symlinks for binary and UI under /usr/local

in
pkgs.dockerTools.buildLayeredImage {
  name = imageName;
  tag = imageTag;

  # Set creation time for reproducibility
  created = "1970-01-01T00:00:01Z";

  # Contents to include in the image
  # Note: pkgs.busybox is intentionally omitted — it includes a /dev/pts/ptmx
  # character device node that causes `failed to register layer` errors on older
  # containerd versions (< 1.6.8). coreutils and bash (already in runtimeEnv)
  # cover all basic utilities needed at runtime.
  #
  # Note: /etc content (/etc/passwd, /etc/group, /etc/nsswitch.conf,
  # /etc/ssl/certs/ca-bundle.crt, /etc/cosmian/) is created in fakeRootCommands
  # below. The etc/ directory inherited from runtimeEnv is read-only
  # (dr-xr-xr-x), so fakeRootCommands first chmod 755 it before writing.
  contents = [
    runtimeEnv
    kmsDirectories
    startupScript
  ];

  # For this nixpkgs version, use fakeRootCommands to create root files
  fakeRootCommands = ''
    # buildLayeredImage's `contents` merge (via buildEnv/lndir) keeps a
    # directory as a symlink into the read-only Nix store whenever only a
    # single input derivation contributes that subtree (e.g. usr/local/bin
    # when only the pkcs11 ckms-bin derivation provides it, or etc/ when
    # only runtimeEnv provides it). Any mkdir/cp/tee performed on such a
    # path inside fakeRootCommands then silently fails with "Permission
    # denied", because the symlink target is not writable even under
    # fakeroot/proot. ensure_writable_dir replaces the symlink (if any)
    # with a real, writable directory that preserves the original content,
    # so every directory this script writes into is guaranteed writable
    # regardless of how many contents derivations contributed to it.
    ensure_writable_dir() {
      _dir="$1"
      if [ -L "$_dir" ]; then
        _target=$(readlink "$_dir")
        rm "$_dir"
        mkdir -p "$_dir"
        cp -r "$_target/." "$_dir/" 2>/dev/null || true
      else
        mkdir -p "$_dir"
        chmod u+w "$_dir" 2>/dev/null || true
      fi
    }

    echo "=== fakeRootCommands: Creating directory structure ==="
    ensure_writable_dir bin
    ensure_writable_dir usr
    ensure_writable_dir usr/local
    ensure_writable_dir usr/local/bin
    ensure_writable_dir usr/local/cosmian
    ensure_writable_dir usr/local/cosmian/ui

    echo "=== fakeRootCommands: Creating /etc files ==="
    ensure_writable_dir etc
    mkdir -p etc/ssl/certs
    mkdir -p etc/cosmian
    printf 'root:x:0:0:root:/root:/bin/sh\nkms:x:1000:1000:KMS User:/home/kms:/bin/sh\n' \
      | tee etc/passwd > /dev/null
    printf 'root:x:0:\nkms:x:1000:\n' | tee etc/group > /dev/null
    printf 'hosts: files dns\nnetworks: files\npasswd: files\ngroup: files\nshadow: files\n' \
      | tee etc/nsswitch.conf > /dev/null
    cp ${caBundle}/etc/ssl/certs/ca-bundle.crt etc/ssl/certs/ca-bundle.crt
    # Verify /etc files were created
    test -f etc/passwd         || { echo "FATAL: etc/passwd not created"; exit 1; }
    test -f etc/group          || { echo "FATAL: etc/group not created"; exit 1; }
    test -f etc/nsswitch.conf  || { echo "FATAL: etc/nsswitch.conf not created"; exit 1; }
    test -f etc/ssl/certs/ca-bundle.crt || { echo "FATAL: etc/ssl/certs/ca-bundle.crt not created"; exit 1; }
    test -d etc/cosmian        || { echo "FATAL: etc/cosmian not created"; exit 1; }
    echo "All /etc files verified."

    echo "=== fakeRootCommands: Installing binaries (no symlinks) ==="
    cp -L ${actualKmsServer}/bin/cosmian_kms bin/cosmian_kms || echo "Failed to copy cosmian_kms to /bin"
    cp -L ${actualKmsServer}/bin/cosmian_kms usr/local/bin/cosmian_kms || echo "Failed to copy cosmian_kms to /usr/local/bin"

    echo "=== fakeRootCommands: Installing UI (no symlinks) ==="
    mkdir -p usr/local/cosmian/ui/dist
    cp -r ${actualKmsServer}/usr/local/cosmian/ui/dist/* usr/local/cosmian/ui/dist/ 2>/dev/null || echo "UI dist copy skipped or empty"

    echo "=== fakeRootCommands: Installing OpenSSL FIPS modules and configs (if present) ==="
    # Prefer copying OpenSSL provider modules and configs from the provided OpenSSL derivation
    # (opensslDrv) to strictly reuse the derivation-generated configuration. Fall back to
    # the server output if opensslDrv is not provided.
    ensure_writable_dir usr/local/cosmian/lib
    ensure_writable_dir usr/local/cosmian/lib/ossl-modules
    ensure_writable_dir usr/local/cosmian/lib/ssl
    if [ -n "${opensslDrvPath}" ] && [ -d ${opensslDrvPath}/usr/local/cosmian/lib/ossl-modules ]; then
      cp -L ${opensslDrvPath}/usr/local/cosmian/lib/ossl-modules/* usr/local/cosmian/lib/ossl-modules/ 2>/dev/null || true
    elif [ -d ${actualKmsServer}/usr/local/cosmian/lib/ossl-modules ]; then
      cp -L ${actualKmsServer}/usr/local/cosmian/lib/ossl-modules/* usr/local/cosmian/lib/ossl-modules/ 2>/dev/null || true
    else
      echo "No ossl-modules found in openssl derivation or server output"
    fi
    if [ -n "${opensslDrvPath}" ] && [ -d ${opensslDrvPath}/usr/local/cosmian/lib/ssl ]; then
      cp -L ${opensslDrvPath}/usr/local/cosmian/lib/ssl/* usr/local/cosmian/lib/ssl/ 2>/dev/null || true
    elif [ -d ${actualKmsServer}/usr/local/cosmian/lib/ssl ]; then
      cp -L ${actualKmsServer}/usr/local/cosmian/lib/ssl/* usr/local/cosmian/lib/ssl/ 2>/dev/null || true
    else
      echo "No ssl config dir found in openssl derivation or server output"
    fi
    # Reuse the original openssl.cnf as-is; do not modify/include here
    if [ -f usr/local/cosmian/lib/ssl/openssl.cnf ]; then
      chmod 644 usr/local/cosmian/lib/ssl/openssl.cnf || true
    fi
    if [ -f usr/local/cosmian/lib/ssl/fipsmodule.cnf ]; then
      chmod 644 usr/local/cosmian/lib/ssl/fipsmodule.cnf || true
    fi
    echo "=== fakeRootCommands: Verifying FIPS files ==="
    ls -la usr/local/cosmian/lib/ossl-modules/ || echo "ossl-modules not present"
    ls -la usr/local/cosmian/lib/ssl/ || echo "ssl config not present"

    # ckms and libcosmian_pkcs11.so are now added via pkcs11Contents in the
    # contents list, so no fakeRootCommands step is needed for them.

    echo "=== fakeRootCommands: Verifying installed files ==="
    ls -la bin/ || echo "ERROR: bin not found"
    ls -la usr/local/bin/ || echo "ERROR: usr/local/bin not found"
    ls -la usr/local/cosmian/ui/ || echo "ERROR: usr/local/cosmian/ui not found"
    ls -la etc/ || echo "ERROR: etc not found"
    ls -la etc/cosmian/ || echo "ERROR: etc/cosmian not found"
    ls -la etc/ssl/certs/ || echo "ERROR: etc/ssl/certs not found"

    # Provide system dynamic linker and glibc locations expected by the binary
    # Copy all files from glibc/lib to all possible locations
    # The binary will use the correct one for its architecture

    echo "=== fakeRootCommands: Copying glibc files from ${pkgs.glibc}/lib ==="
    ls -la ${pkgs.glibc}/lib/ || echo "Failed to list glibc lib directory"

    # Create all directory structures
    rm -f lib lib64 || true
    mkdir -p lib lib64 lib/x86_64-linux-gnu lib/aarch64-linux-gnu
    rm -f lib lib64 || true

    # Copy all files from glibc lib directory using find
    # This will include whichever architecture glibc provides
    echo "=== Copying glibc files with find ==="
    find ${pkgs.glibc}/lib -maxdepth 1 -type f -o -type l | while IFS= read -r f; do
      filename=$(basename "$f")
      echo "Copying: $filename"

      # Copy to lib/ (for aarch64 ld-linux-aarch64.so.1)
      cp -L "$f" lib/ 2>/dev/null || true

      # Copy to lib64/ (for x86_64 ld-linux-x86-64.so.2)
      cp -L "$f" lib64/ 2>/dev/null || true

      # Copy to architecture-specific directories
      cp -L "$f" lib/x86_64-linux-gnu/ 2>/dev/null || true
      cp -L "$f" lib/aarch64-linux-gnu/ 2>/dev/null || true
    done

    echo "=== Files copied to lib/ ==="
    ls -la lib/ | head -20 || true
    echo "=== Files copied to lib64/ ==="
    ls -la lib64/ | head -20 || true
    echo "=== Files copied to lib/aarch64-linux-gnu/ ==="
    ls -la lib/aarch64-linux-gnu/ | head -20 || true
    echo "=== Files copied to lib/x86_64-linux-gnu/ ==="
    ls -la lib/x86_64-linux-gnu/ | head -20 || true
  '';

  # Configuration
  config = {
    # Set the entrypoint to our startup script
    Entrypoint = [ "${startupScript}/bin/docker-entrypoint.sh" ];

    # Expose the default KMS ports
    ExposedPorts = {
      "9998/tcp" = { };
      "5696/tcp" = { };
    };

    # Environment variables
    # Ensure OpenSSL uses the packaged configuration and provider modules.
    # Both FIPS and non-FIPS variants need OPENSSL_CONF and OPENSSL_MODULES
    # to locate the correct openssl.cnf and provider modules (fips.so, legacy.so, etc.).
    Env = [
      "PATH=/usr/local/bin:/bin:${runtimeEnv}/bin"
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      "TZDIR=${pkgs.tzdata}/share/zoneinfo"
      "OPENSSL_CONF=/usr/local/cosmian/lib/ssl/openssl.cnf"
      "OPENSSL_MODULES=/usr/local/cosmian/lib/ossl-modules"
      # Default CORS origins for the Web UI served from the container itself.
      # Covers IPv4 localhost (127.0.0.1, 0.0.0.0) and IPv6 equivalents (::1, [::]).
      # Users can override by setting KMS_CORS_ALLOWED_ORIGINS at runtime.
      "KMS_CORS_ALLOWED_ORIGINS=http://localhost:9998,http://127.0.0.1:9998,http://0.0.0.0:9998,http://[::1]:9998,http://[::]:9998"
    ];

    # Set working directory
    WorkingDir = "/var/lib/cosmian-kms";

    # Run as root user initially (can be changed via docker run --user)
    # User = "root";

    # Labels
    Labels = {
      "org.opencontainers.image.title" = "Cosmian KMS";
      "org.opencontainers.image.description" =
        "Cosmian KMS Server ${version} - ${variant} variant (minimal via Nix)";
      "org.opencontainers.image.version" = version;
      "org.opencontainers.image.vendor" = "Cosmian";
      "org.opencontainers.image.source" = "https://github.com/Cosmian/kms";
      "org.opencontainers.image.documentation" = "https://docs.cosmian.com/key_management_system/";
      "org.opencontainers.image.licenses" = "BUSL-1.1";
      "com.cosmian.kms.variant" = variant;
      "com.cosmian.kms.linkage" = "static";
    };
  };

  # Enable reproducible builds
  # proot (required by enableFakechroot) is not available on Darwin;
  # the Docker image is Linux-only so this only matters on Linux builders.
  enableFakechroot = !pkgs.stdenv.hostPlatform.isDarwin;

  # Layer configuration for better caching
  maxLayers = 100;
}
