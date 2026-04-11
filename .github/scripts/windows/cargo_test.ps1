$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $true # might be true by default

function TestProject
{
    $env:RUST_LOG = "cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"
    # Add target
    rustup target add x86_64-pc-windows-msvc

    $env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
    Get-ChildItem -Recurse $env:OPENSSL_DIR

    # Tests are always run in debug mode (no --release flag)

    # Build the PKCS#11 cdylib so that cosmian_pkcs11_verify integration tests
    # can dynamically load it at runtime.  `cargo test --lib` does not produce
    # cdylib artifacts, so we build it explicitly before running the test suite.
    cargo build -p cosmian_pkcs11 --features "non-fips"
    if ($LASTEXITCODE -ne 0)
    {
        Write-Error "Failed to build cosmian_pkcs11 cdylib with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    # Run lib tests for all workspace crates
    cargo test --lib --workspace --features "non-fips" -- --nocapture
    if ($LASTEXITCODE -ne 0)
    {
        Write-Error "Workspace lib tests failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    # Run ckms crate tests explicitly (lib + integration)
    cargo test -p ckms --features "non-fips" -- --nocapture
    if ($LASTEXITCODE -ne 0)
    {
        Write-Error "ckms tests failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}


# Example usage:
# TestProject
