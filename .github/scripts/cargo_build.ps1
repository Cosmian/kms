$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $true # might be true by default

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

    # Build CLI
    Get-ChildItem crate\cli
    if ($BuildType -eq "release")
    {
        cargo build --release --target x86_64-pc-windows-msvc
    }
    else
    {
        cargo build --target x86_64-pc-windows-msvc
    }
    Get-ChildItem ..\..

    # Build pkcs11 provider
    Get-ChildItem crate\pkcs11\provider
    if ($BuildType -eq "release")
    {
        cargo build --release --target x86_64-pc-windows-msvc
    }
    else
    {
        cargo build --target x86_64-pc-windows-msvc
    }
    Get-ChildItem ..\..\..

    # # Build at root
    # if ($BuildType -eq "release") {
    #     cargo build --release --target x86_64-pc-windows-msvc
    # }
    # else {
    #     cargo build --target x86_64-pc-windows-msvc
    # }

    # Check binaries
    Get-ChildItem target\x86_64-pc-windows-msvc\$BuildType
    Get-ChildItem target
    Get-ChildItem target\$BuildType

    # Check dynamic links
    $ErrorActionPreference = "SilentlyContinue"
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64\dumpbin.exe" /dependents target\x86_64-pc-windows-msvc\$BuildType\cosmian.exe | Select-String "libcrypto"
    if ($output) {
        throw "OpenSSL (libcrypto) found in dynamic dependencies. Error: $output"
    }
    $ErrorActionPreference = "Stop"

    exit 0
}


# Example usage:
# BuildProject -BuildType debug
# BuildProject -BuildType release
