$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $true # might be true by default

function BuildProject
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("debug", "release")]
        [string]$BuildType
    )

    # Add target
    rustup target add x86_64-pc-windows-msvc

    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
    Get-ChildItem -Recurse $env:OPENSSL_DIR

    # Build `cosmian`
    Get-ChildItem cli\crate\cli
    if ($BuildType -eq "release")
    {
        cargo build --release --target x86_64-pc-windows-msvc
    }
    else
    {
        cargo build --target x86_64-pc-windows-msvc
    }
    Get-ChildItem ..\..\..

    # Check dynamic links
    $ErrorActionPreference = "SilentlyContinue"
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64\dumpbin.exe" /dependents target\x86_64-pc-windows-msvc\$BuildType\cosmian.exe -ErrorAction SilentlyContinue | Select-String "libcrypto"
    if ($output)
    {
        throw "OpenSSL (libcrypto) found in dynamic dependencies. Error: $output"
    }
    $ErrorActionPreference = "Stop"

    # Build `server`
    Set-Location crate\server
    if ($BuildType -eq "release")
    {
        cargo build --release --target x86_64-pc-windows-msvc
        cargo test --release --target x86_64-pc-windows-msvc -p cosmian_kms_server -- --nocapture --skip test_sql_cipher --skip test_sqlite --skip test_mysql --skip test_postgresql --skip test_redis --skip google_cse --skip hsm
    }
    else
    {
        cargo build --target x86_64-pc-windows-msvc
        cargo test --target x86_64-pc-windows-msvc -p cosmian_kms_server -- --nocapture --skip test_sql_cipher --skip test_sqlite --skip test_mysql --skip test_postgresql --skip test_redis --skip google_cse --skip hsm
    }
    Get-ChildItem ..\..

    # Check dynamic links
    $ErrorActionPreference = "SilentlyContinue"
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64\dumpbin.exe" /dependents target\x86_64-pc-windows-msvc\$BuildType\cosmian_kms.exe | Select-String "libcrypto"
    if ($output)
    {
        throw "OpenSSL (libcrypto) found in dynamic dependencies. Error: $output"
    }

    exit 0
}


# Example usage:
# BuildProject -BuildType debug
# BuildProject -BuildType release
