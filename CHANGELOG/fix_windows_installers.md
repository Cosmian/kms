# Changelog (fix/windows_installers)

## Bug Fixes

- Fix server panic on Windows when rolling log directory is not writable by standard users — gracefully disable file logging with a warning instead of panicking
- Fix Windows service not starting: installer now passes `-c kms.toml` in the service `binPath` and creates required data directories
- Change default Windows rolling log directory from `C:\ProgramData\Cosmian KMS Server\logs` to `%LOCALAPPDATA%\Cosmian KMS Server` (guaranteed writable)
- Change Windows installer default `$INSTDIR` from `$PROGRAMFILES64` to `$LOCALAPPDATA\Cosmian KMS Server` so that installer, wizard, and server all use the same path — force `$LOCALAPPDATA` unconditionally to prevent previous installations or cargo-packager from restoring a `Program Files` path
- Change macOS default rolling log directory from `~/Library/Logs/Cosmian KMS Server` to `~/Library/Logs/` (standard per-user log directory)
- **Fix CNG KSP not visible to `certutil -csplist` and `NCryptOpenStorageProvider`**: registry value name was `DllFileName` instead of the standard `Image Path` expected by Windows CNG infrastructure
- **Fix CNG KSP registration with relative DLL path**: `ckms cng register --dll .\cosmian_cng.dll` now canonicalizes to an absolute path before writing to the registry (Windows CNG cannot resolve relative paths)
- Fix `ckms cng verify` "DeleteKey + verify gone" test: expect `NTE_BAD_KEYSET` (0x80090016) instead of wrong `NTE_NO_KEY` constant, matching the actual CNG provider behavior

## Features

- Server and ckms wizards now create directories recursively when paths are entered by the user (covers macOS, Windows, and Linux)
- Windows NSIS installer creates `$INSTDIR\{logs,data}` subdirectories for service use and cleans them on uninstall

## Documentation

- Update logging documentation to reflect the new Windows and macOS default log directories and document the graceful fallback behavior
- Add Intune PFX import workflow documentation (`Add-IntuneKspKey`) to CNG KSP page
- Add `certutil -csplist` verification step to CNG KSP registration docs
