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

    $env:RUST_LOG = "cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"
    # Add target
    rustup target add x86_64-pc-windows-msvc

    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
    Get-ChildItem -Recurse $env:OPENSSL_DIR

    cargo install --version 0.11.7 cargo-packager --force

    # Build `server`
    Set-Location crate\server
    if ($BuildType -eq "release")
    {
        cargo build --release --features "non-fips"
        cargo packager --verbose --formats nsis --release
    }
    else
    {
        cargo build --features "non-fips"
        cargo packager --verbose --formats nsis
    }
    Get-ChildItem ..\..

    # Check dynamic links
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64\dumpbin.exe" /dependents target\$BuildType\cosmian_kms.exe | Select-String "libcrypto"
    $ErrorActionPreference = $previousErrorActionPreference
    if ($output)
    {
        Write-Error "OpenSSL (libcrypto) found in dynamic dependencies. Error: $output"
        exit 1
    }

    if ($BuildType -eq "release")
    {
        cargo test --lib --workspace  --release --features "non-fips" -- --nocapture
        if ($LASTEXITCODE -ne 0)
        {
            Write-Error "Release tests failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
    }
    else
    {
        cargo test --lib --workspace --features "non-fips" -- --nocapture
        if ($LASTEXITCODE -ne 0)
        {
            Write-Error "Debug tests failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
    }
}


# Example usage:
# BuildProject -BuildType debug
# BuildProject -BuildType release
