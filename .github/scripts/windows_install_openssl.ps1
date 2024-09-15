function Install-Openssl {

    # Set up environment for vcpkg
    $env:VCPKG_INSTALLATION_ROOT
    dir $env:VCPKG_INSTALLATION_ROOT
    vcpkg install openssl[fips,weak-ssl-ciphers]

    vcpkg integrate install
    $env:VCPKGRS_DYNAMIC = 1
    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows"
}

