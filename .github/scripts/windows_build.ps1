function Build-Project {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("debug", "release")]
        [string]$BuildType
    )

    # Add target
    rustup target add x86_64-pc-windows-msvc

    # Build `ckms`
    cd crate/cli
    if ($BuildType -eq "release") {
        cargo build --release --target x86_64-pc-windows-msvc
    } else {
        cargo build --target x86_64-pc-windows-msvc
    }

    # Build pkcs11 provider
    cd ../pkcs11/provider
    if ($BuildType -eq "release") {
        cargo build --release --target x86_64-pc-windows-msvc
    } else {
        cargo build --target x86_64-pc-windows-msvc
    }
    cd ../../..

    # Set up environment for vcpkg
    $env:VCPKG_INSTALLATION_ROOT
    dir $env:VCPKG_INSTALLATION_ROOT
    vcpkg install openssl[fips]

    vcpkg integrate install
    $env:VCPKGRS_DYNAMIC = 1
    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows"

    # Build `server`
    cd crate/server
    if ($BuildType -eq "release") {
        cargo build --release --target x86_64-pc-windows-msvc
    } else {
        cargo build --target x86_64-pc-windows-msvc
        cargo test -v --workspace -- --nocapture --skip test_mysql --skip test_pgsql --skip test_redis --skip google_cse
    }
}

# Example usage:
# Build-Project -BuildType debug
# Build-Project -BuildType release
