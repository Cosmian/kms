{
  pkgs ? import <nixpkgs> { },
  # KMS server derivation to include in the image (must include UI)
  kmsServer ? null,
  # Variant: "fips" or "non-fips"
  variant ? "fips",
}:

# Note: The kmsServer derivation must be built with a UI parameter
# to include the web interface at /usr/local/cosmian/ui/dist

let
  # Version from the KMS server
  version = "5.13.0";

  # Determine the actual KMS server to use
  actualKmsServer =
    if kmsServer != null then
      kmsServer
    else
      builtins.throw "kmsServer parameter is required. Pass it from default.nix";

  # Image name and tag
  imageName = "cosmian-kms";
  imageTag = "${version}-${variant}-alpine";

  # Create a minimal runtime environment
  # Include necessary libraries for the KMS server
  runtimeEnv = pkgs.buildEnv {
    name = "kms-runtime-env";
    paths = [
      actualKmsServer
      pkgs.cacert # CA certificates
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

    # Create data directory if it doesn't exist
    mkdir -p /var/lib/cosmian-kms

    # If no arguments provided, show help
    if [ $# -eq 0 ]; then
      echo "Cosmian KMS Server ${version} (${variant})"
      echo "Usage: docker run [docker-options] cosmian-kms [kms-options]"
      echo ""
      echo "Example with SQLite:"
      echo "  docker run -p 9998:9998 -v /path/to/data:/data cosmian-kms \\"
      echo "    --database-type sqlite --sqlite-path /data"
      echo ""
      exec /bin/cosmian_kms --help
    fi

    # Execute the KMS server with provided arguments
    exec /bin/cosmian_kms "$@"
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
    # Add busybox for basic Alpine-like utilities
    pkgs.busybox
  ];

  # For this nixpkgs version, use fakeRootCommands to create root files
  fakeRootCommands = ''
    mkdir -p usr/local/bin
    ln -s ${actualKmsServer}/bin/cosmian_kms usr/local/bin/cosmian_kms
    mkdir -p usr/local/cosmian/ui
    ln -s ${actualKmsServer}/usr/local/cosmian/ui/dist usr/local/cosmian/ui/dist

    # Provide system dynamic linker and glibc locations expected by the binary
    # x86_64-linux
    mkdir -p lib64
    if [ ! -e lib64/ld-linux-x86-64.so.2 ]; then
      ln -s ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2 || true
    fi
    mkdir -p lib/x86_64-linux-gnu
    ln -s ${pkgs.glibc}/lib/* lib/x86_64-linux-gnu/ 2>/dev/null || true
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
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
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
        "Cosmian KMS Server ${version} - ${variant} variant (Alpine-style via Nix)";
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
