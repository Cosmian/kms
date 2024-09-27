function BuildProject {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("debug", "release")]
        [string]$BuildType
    )

    # Add target
    rustup target add x86_64-pc-windows-msvc

    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
    Get-ChildItem -Recurse $env:OPENSSL_DIR

    # Build pkcs11 provider
    Get-ChildItem crate\pkcs11\provider
    if ($BuildType -eq "release") {
        cargo build --release --target x86_64-pc-windows-msvc
    }
    else {
        cargo build --target x86_64-pc-windows-msvc
    }
    Get-ChildItem ..\..\..

    # Build `ckms`
    Get-ChildItem crate\cli
    if ($BuildType -eq "release") {
        cargo build --release --target x86_64-pc-windows-msvc
    }
    else {
        cargo build --target x86_64-pc-windows-msvc
    }
    Get-ChildItem ..\..

    # Check dynamic links
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64\dumpbin.exe" /dependents target\x86_64-pc-windows-msvc\$BuildType\ckms.exe | Select-String "libcrypto"
    if ($output) {
        throw "OpenSSL (libcrypto) found in dynamic dependencies. Error: $output"
    }

    # Build `server`
    Set-Location crate\server
    if ($BuildType -eq "release") {
        cargo build --release --target x86_64-pc-windows-msvc
        cargo test --release --target x86_64-pc-windows-msvc -p cosmian_kms_server -- --nocapture --skip test_sql_cipher --skip test_sqlite --skip test_mysql --skip test_postgresql --skip test_redis --skip google_cse
    }
    else {
        cargo build --target x86_64-pc-windows-msvc
        cargo test --target x86_64-pc-windows-msvc -p cosmian_kms_server -- --nocapture --skip test_sql_cipher --skip test_sqlite --skip test_mysql --skip test_postgresql --skip test_redis --skip google_cse
    }
    Get-ChildItem ..\..

    # Check dynamic links
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64\dumpbin.exe" /dependents target\x86_64-pc-windows-msvc\$BuildType\cosmian_kms_server.exe | Select-String "libcrypto"
    if ($output) {
        throw "OpenSSL (libcrypto) found in dynamic dependencies. Error: $output"
    }

    exit 0
}


# Example usage:
# BuildProject -BuildType debug
# BuildProject -BuildType release
