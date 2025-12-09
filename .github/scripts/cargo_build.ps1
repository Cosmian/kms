$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $true # might be true by default

function BuildProject
{
    # Add target
    rustup target add x86_64-pc-windows-msvc

    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
    Get-ChildItem -Recurse $env:OPENSSL_DIR

    cargo install --version 0.11.7 cargo-packager --force

    # Build `server`
    Set-Location crate\server
    cargo build --release --features "non-fips" --no-default-features
    cargo packager --verbose --formats nsis --release
    Get-ChildItem ..\..

    # Check dynamic links
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64\dumpbin.exe" /dependents target\release\cosmian_kms.exe | Select-String "libcrypto"
    $ErrorActionPreference = $previousErrorActionPreference
    if ($output)
    {
        Write-Error "OpenSSL (libcrypto) found in dynamic dependencies. Error: $output"
        exit 1
    }

    exit 0
}


# Example usage:
# BuildProject
