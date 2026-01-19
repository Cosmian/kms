{
  pkgs ? import <nixpkgs> { },
  lib ? pkgs.lib,
}:

let
  # Utimaco HSM simulator version/URL
  simulatorUrl = "https://package.cosmian.com/ci/hsm-utimaco-simulator.tar.xz";
  # Update this hash when the simulator archive changes
  # To get the hash: nix-prefetch-url <url> (without --unpack for fetchurl)
  simulatorSha256 = "sha256-xrg/BE+Ony0yERw6aBBZf+Kk0ReMvGhNkUFXLnhFqBs=";
in
pkgs.stdenv.mkDerivation rec {
  pname = "utimaco-hsm-simulator";
  version = "unstable";

  src = pkgs.fetchurl {
    url = simulatorUrl;
    sha256 = simulatorSha256;
  };

  nativeBuildInputs = with pkgs; [
    autoPatchelfHook
    patchelf
  ];

  buildInputs =
    with pkgs;
    [
      stdenv.cc.cc.lib # libstdc++
      glibc
    ]
    ++ lib.optionals pkgs.stdenv.isLinux [
      # The simulator binary (bl_sim5) is 32-bit, requires 32-bit glibc
      pkgs.pkgsi686Linux.glibc
      pkgs.pkgsi686Linux.stdenv.cc.cc.lib
    ];

  # No build phase needed - this is a binary distribution
  dontBuild = true;
  dontConfigure = true;

  unpackPhase = ''
    runHook preUnpack
    mkdir -p hsm-simulator
    tar -xf $src
    runHook postUnpack
  '';

  installPhase = ''
        runHook preInstall

        # Create output directory structure
        mkdir -p $out/{bin,lib,share/utimaco,etc/utimaco}

        # Install simulator binary
        install -D -m755 hsm-simulator/sim5_linux/bin/bl_sim5 $out/bin/bl_sim5

        # Install devices directory (required for simulator)
        cp -r hsm-simulator/sim5_linux/devices $out/share/utimaco/

        # Install PKCS#11 library
        install -D -m755 hsm-simulator/libcs_pkcs11_R3.so $out/lib/libcs_pkcs11_R3.so

        # Install default config template
        cat > $out/etc/utimaco/cs_pkcs11_R3.cfg <<EOF
    [Global]
    Logpath = /tmp
    Logging = 3

    [CryptoServer]
    Device = 3001@localhost
    EOF

        # Install administration tools
        mkdir -p $out/share/utimaco/admin
        cp -r hsm-simulator/Administration/* $out/share/utimaco/admin/
        chmod +x $out/share/utimaco/admin/p11tool2

        # Create wrapper script for starting simulator
        cat > $out/bin/utimaco-simulator <<EOF
    #!/usr/bin/env bash
    set -euo pipefail

    # Utimaco HSM Simulator wrapper
    # The simulator needs a writable devices directory, so copy from Nix store to temp location
    RUNTIME_DIR="\''${UTIMACO_RUNTIME_DIR:-\$PWD/.utimaco}"
    DEVICES_DIR="\$RUNTIME_DIR/devices"
      LOG_FILE="\$RUNTIME_DIR/simulator.log"

    # Create runtime directory and copy devices if not exists or if template is newer
    if [ ! -d "\$DEVICES_DIR" ] || [ "$out/share/utimaco/devices" -nt "\$DEVICES_DIR" ]; then
      echo "Setting up Utimaco runtime environment at \$RUNTIME_DIR..."
      mkdir -p "\$RUNTIME_DIR"
      rm -rf "\$DEVICES_DIR"
      cp -r "$out/share/utimaco/devices" "\$DEVICES_DIR"
      chmod -R u+w "\$DEVICES_DIR"
    fi

    # Kill any existing simulator
    pkill -9 bl_sim5 2>/dev/null || true

    # Start simulator in background
    echo "Starting Utimaco HSM simulator..."
    $out/bin/bl_sim5 -h -o -d "\$DEVICES_DIR" >"\$LOG_FILE" 2>&1 &
    SIMULATOR_PID=\$!

    # Wait for simulator to be ready
    sleep 5

    if kill -0 \$SIMULATOR_PID 2>/dev/null; then
      echo "Utimaco HSM simulator started (PID: \$SIMULATOR_PID)"
      echo "Runtime directory: \$RUNTIME_DIR"
      echo "Logs: \$LOG_FILE"
      echo "Simulator will run in background. Use 'pkill bl_sim5' to stop."
    else
      echo "ERROR: Failed to start simulator" >&2
      exit 1
    fi
    EOF
        chmod +x $out/bin/utimaco-simulator

        # Create initialization script
        cat > $out/bin/utimaco-init <<EOF
    #!/usr/bin/env bash
    set -euo pipefail

    # Initialize Utimaco HSM with default PINs
    ADMIN_DIR="$out/share/utimaco/admin"
    P11TOOL="\$ADMIN_DIR/p11tool2"

    if [ ! -x "\$P11TOOL" ]; then
      echo "ERROR: p11tool2 not found or not executable" >&2
      exit 1
    fi

    cd "\$ADMIN_DIR"

    echo "Initializing Utimaco HSM..."

    # Set the SO PIN to 11223344
    ./p11tool2 Slot=0 login=ADMIN,./key/ADMIN_SIM.key InitToken=11223344

    # Change the SO PIN to 12345678
    ./p11tool2 Slot=0 LoginSO=11223344 SetPin=11223344,12345678

    # Set the User PIN to 11223344
    ./p11tool2 Slot=0 LoginSO=12345678 InitPin=11223344

    # Change the User PIN to 12345678
    ./p11tool2 Slot=0 LoginUser=11223344 SetPin=11223344,12345678

    # Display slot info
    ./p11tool2 Slot=0 GetSlotInfo

    echo "Utimaco HSM initialized successfully"
    echo "SO PIN: 12345678"
    echo "User PIN: 12345678"
    EOF
        chmod +x $out/bin/utimaco-init

        runHook postInstall
  '';

  # Ensure the 32-bit simulator uses the system 32-bit loader, not Nix's 64-bit one
  postFixup = lib.optionalString pkgs.stdenv.isLinux ''
    if file "$out/bin/bl_sim5" | grep -q "ELF 32-bit"; then
      echo "Fixing 32-bit interpreter for bl_sim5 (pure Nix)"
      # Point to the Nix store 32-bit glibc interpreter to avoid host dependency
      patchelf --set-interpreter ${pkgs.pkgsi686Linux.glibc}/lib/ld-linux.so.2 "$out/bin/bl_sim5" || true
      # Ensure the simulator can find required 32-bit runtime libraries in Nix store
      patchelf --set-rpath ${pkgs.pkgsi686Linux.stdenv.cc.cc.lib}/lib:${pkgs.pkgsi686Linux.glibc}/lib "$out/bin/bl_sim5" || true
    fi
  '';

  # Provide environment setup script
  setupHook = pkgs.writeText "setup-utimaco-env.sh" ''
    export UTIMACO_PKCS11_LIB="@out@/lib/libcs_pkcs11_R3.so"
    export CS_PKCS11_R3_CFG="''${CS_PKCS11_R3_CFG:-@out@/etc/utimaco/cs_pkcs11_R3.cfg}"

    # Add lib directory to LD_LIBRARY_PATH
    addToSearchPath LD_LIBRARY_PATH "@out@/lib"
  '';

  passthru = {
    # Expose key paths for use in other derivations
    pkcs11Lib = "${placeholder "out"}/lib/libcs_pkcs11_R3.so";
    configTemplate = "${placeholder "out"}/etc/utimaco/cs_pkcs11_R3.cfg";
    simulator = "${placeholder "out"}/bin/bl_sim5";
  };

  meta = with lib; {
    description = "Utimaco HSM Simulator for testing PKCS#11 integration";
    homepage = "https://www.utimaco.com/";
    license = licenses.unfree;
    platforms = [ "x86_64-linux" ];
    maintainers = [ ];
  };
}
