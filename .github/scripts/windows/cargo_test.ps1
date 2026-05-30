Set-StrictMode -Version Latest
# Use "Continue" because native commands (cargo, rustup) write progress/info
# to stderr.  With "Stop", PowerShell treats those as terminating errors.
# All failures are caught via explicit $LASTEXITCODE checks after each command.
$ErrorActionPreference = "Continue"

function TestProject
{
    $env:RUST_LOG = "cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"
    # Add target
    rustup target add x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0)
    {
        Write-Error "rustup target add failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    # Set OPENSSL_DIR from VCPKG_INSTALLATION_ROOT (CI) or VCPKG_ROOT (local).
    $vcpkgRoot = if ($env:VCPKG_INSTALLATION_ROOT) { $env:VCPKG_INSTALLATION_ROOT } else { $env:VCPKG_ROOT }
    if ($vcpkgRoot)
    {
        $env:OPENSSL_DIR = "$vcpkgRoot\packages\openssl_x64-windows-static"
    }

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

    # Run lib tests for all workspace crates except cosmian_pkcs11_verify.
    # The loader tests (cosmian_pkcs11_verify) dynamically load cosmian_pkcs11.dll
    # and use a tokio multi-thread runtime inside the DLL.  When run concurrently
    # with other workspace test binaries, a timing-dependent race between the
    # DLL's background runtime threads and FreeLibrary() causes a
    # STATUS_STACK_BUFFER_OVERRUN crash on Windows.  Running the loader tests in
    # isolation (step below) avoids this entirely.
    cargo test --lib --workspace --exclude cosmian_pkcs11_verify --features "non-fips" -- --nocapture
    if ($LASTEXITCODE -ne 0)
    {
        Write-Error "Workspace lib tests failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    # Run the PKCS#11 loader tests ONE AT A TIME in separate cargo invocations.
    # When multiple tests share a process, each test loads then *unloads*
    # cosmian_pkcs11.dll (Library::drop → FreeLibrary).  The DLL contains a
    # static tokio multi-thread runtime; executing DLL_PROCESS_DETACH while
    # background worker threads are still live causes STATUS_STACK_BUFFER_OVERRUN.
    # Running each test in its own cargo process keeps the DLL alive only for that
    # single test and avoids the race entirely.
    $verifyTestNames = & cargo test --lib -p cosmian_pkcs11_verify --features "non-fips" -- --list 2>$null |
        Where-Object { $_ -match ': test$' } |
        ForEach-Object { ($_ -replace ': test$', '').Trim() }
    if ($null -eq $verifyTestNames -or ($verifyTestNames -is [array] -and $verifyTestNames.Count -eq 0) -or ($verifyTestNames -is [string] -and $verifyTestNames.Length -eq 0))
    {
        Write-Error "No cosmian_pkcs11_verify tests found (--list returned nothing)"
        exit 1
    }
    foreach ($testName in @($verifyTestNames))
    {
        Write-Host "==> Running cosmian_pkcs11_verify: $testName" -ForegroundColor Cyan
        cargo test --lib -p cosmian_pkcs11_verify --features "non-fips" -- "$testName" --exact --nocapture
        if ($LASTEXITCODE -ne 0)
        {
            Write-Error "cosmian_pkcs11_verify test '$testName' failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
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
