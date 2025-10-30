$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $true # might be true by default

function TestProject
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
# TestProject -BuildType debug
# TestProject -BuildType release
