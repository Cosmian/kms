{
  pkgs ? import <nixpkgs> { },
  # KMS server derivation to include in the image (must include UI)
  kmsServer ? null,
  # Variant: "fips" or "non-fips"
  variant ? "fips",
  # KMS version (from Cargo.toml)
  version,
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

  # Create a minimal runtime environment
  # Include necessary libraries for the KMS server
  runtimeEnv = pkgs.buildEnv {
    name = "kms-runtime-env";
    paths = [
      actualKmsServer
      pkgs.tzdata # Timezone data
      pkgs.coreutils # Basic utilities
      pkgs.bash # Shell for scripts
    ];
  };

  # Create a minimal /etc structure that will be added to the image
  etcPasswd = pkgs.writeTextFile {
    name = "passwd";
    text = ''
      root:x:0:0:root:/root:/bin/sh
      kms:x:1000:1000:KMS User:/home/kms:/bin/sh
    '';
    destination = "/etc/passwd";
  };

  etcGroup = pkgs.writeTextFile {
    name = "group";
    text = ''
      root:x:0:
      kms:x:1000:
    '';
    destination = "/etc/group";
  };

  etcNsswitch = pkgs.writeTextFile {
    name = "nsswitch.conf";
    text = ''
      hosts: files dns
      networks: files
      passwd: files
      group: files
      shadow: files
    '';
    destination = "/etc/nsswitch.conf";
  };

  # Create home and data directories
  kmsDirectories = pkgs.runCommand "kms-directories" { } ''
    mkdir -p $out/home/kms
    mkdir -p $out/var/lib/cosmian-kms
    mkdir -p $out/tmp
    chmod 1777 $out/tmp
  '';

  # Create a startup script that sets up the environment
  startupScript = pkgs.writeScriptBin "docker-entrypoint.sh" ''
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

    # Create data directory if it doesn't exist
    mkdir -p /var/lib/cosmian-kms

    # If no arguments provided, try starting from config file, else show help
    if [ $# -eq 0 ]; then
      CONF_PATH="$(printenv COSMIAN_KMS_CONF)"
      if [ -z "$CONF_PATH" ]; then CONF_PATH="/etc/cosmian/kms.toml"; fi
      if [ -f "$CONF_PATH" ]; then
        echo "Starting Cosmian KMS with configuration: $CONF_PATH"
        exec cosmian_kms -c "$CONF_PATH"
      fi
      echo "Cosmian KMS Server"
      echo "Usage: docker run [docker-options] cosmian-kms [kms-options]"
      echo ""
      echo "Example with SQLite:"
      echo "  docker run -p 9998:9998 -v /path/to/data:/data cosmian-kms"
      echo "    --database-type sqlite --sqlite-path /data"
      echo ""
      exec cosmian_kms --help
    fi

    # Execute the KMS server with provided arguments
    exec cosmian_kms "$@"
  '';

  # Root filesystem overlay with symlinks for binary and UI under /usr/local

in
pkgs.dockerTools.buildLayeredImage {
  name = imageName;
  tag = imageTag;

  # Set creation time for reproducibility
  created = "1970-01-01T00:00:01Z";

  # Contents to include in the image
  contents = [
    runtimeEnv
    etcPasswd
    etcGroup
    etcNsswitch
    kmsDirectories
    startupScript
    # Add busybox for basic utilities
    pkgs.busybox
  ];

  # For this nixpkgs version, use fakeRootCommands to create root files
  fakeRootCommands = ''
    echo "=== fakeRootCommands: Creating directory structure ==="
    mkdir -p bin
    mkdir -p usr/local/bin
    mkdir -p usr/local/cosmian/ui
    mkdir -p etc
    mkdir -p etc/ssl/certs

    echo "=== fakeRootCommands: Installing binaries (no symlinks) ==="
    cp -L ${actualKmsServer}/bin/cosmian_kms bin/cosmian_kms || echo "Failed to copy cosmian_kms to /bin"
    cp -L ${actualKmsServer}/bin/cosmian_kms usr/local/bin/cosmian_kms || echo "Failed to copy cosmian_kms to /usr/local/bin"

    echo "=== fakeRootCommands: Installing UI (no symlinks) ==="
    mkdir -p usr/local/cosmian/ui/dist
    cp -r ${actualKmsServer}/usr/local/cosmian/ui/dist/* usr/local/cosmian/ui/dist/ 2>/dev/null || echo "UI dist copy skipped or empty"

    echo "=== fakeRootCommands: Bundling CA certificates locally ==="
    cp -L ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt etc/ssl/certs/ca-bundle.crt || echo "Failed to copy CA bundle"

    echo "=== fakeRootCommands: Verifying installed files ==="
    ls -la bin/ || echo "ERROR: bin not found"
    ls -la usr/local/bin/ || echo "ERROR: usr/local/bin not found"
    ls -la usr/local/cosmian/ui/ || echo "ERROR: usr/local/cosmian/ui not found"
    ls -la etc/ || echo "ERROR: etc not found"
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
    Env = [
      "PATH=/usr/local/bin:/bin:${runtimeEnv}/bin:${pkgs.busybox}/bin"
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      "TZDIR=${pkgs.tzdata}/share/zoneinfo"
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
  enableFakechroot = true;

  # Layer configuration for better caching
  maxLayers = 100;
}
