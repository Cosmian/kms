# Changelog (fix/windows_installers)

## Bug Fixes

- Fix server panic on Windows when rolling log directory is not writable by standard users — gracefully disable file logging with a warning instead of panicking
- Fix Windows service not initializing tracing/logging subscriber — service code path now runs the same logging init as the console startup path
- Fix `status_handle` ownership in Windows service: wrap in `Arc` so both the background thread and main task can report SCM status
- Fix `logging_wizard.rs` failing to compile on non-Linux/macOS/Windows targets — use `#[cfg(not(any(...)))]` fallback
- Fix `test_cng_ksp.ps1` TOML backslash escaping — prevent `\t`/`\f` in paths from being interpreted as TOML escape sequences
- Fix documentation claiming rolling log files are enabled by default — file logging requires explicit `rolling_log_dir` configuration
- Fix macOS default rolling log directory references to `~/Library/Logs/` (not `~/Library/Logs/Cosmian KMS Server`)
- Fix Windows service not starting: installer now passes `-c kms.toml` in the service `binPath` and creates required data directories
- Change default Windows rolling log directory from `C:\ProgramData\Cosmian KMS Server\logs` to `C:\Users\<username>\AppData\Local\Cosmian KMS Server` (guaranteed writable)
- **Documentation: warn that Windows env vars (`%LOCALAPPDATA%`) are not expanded in config files** — use fully-resolved paths in `kms.toml`
- Change Windows installer default `$INSTDIR` from `$PROGRAMFILES64` to `$LOCALAPPDATA\Cosmian KMS Server` so that installer, wizard, and server all use the same path — force `$LOCALAPPDATA` unconditionally to prevent previous installations or cargo-packager from restoring a `Program Files` path
- Fix NSIS `$LOCALAPPDATA` resolving to `C:\ProgramData` under `perMachine` mode: temporarily switch to `SetShellVarContext current` before reading `$LOCALAPPDATA` then restore `all` context
- Change macOS default rolling log directory from `~/Library/Logs/Cosmian KMS Server` to `~/Library/Logs/` (standard per-user log directory)
- **Fix CNG KSP not visible to `certutil -csplist` and `NCryptOpenStorageProvider`**: registry value name was `DllFileName` instead of the standard `Image Path` expected by Windows CNG infrastructure
- **Fix CNG KSP registration with relative DLL path**: `ckms cng register --dll .\cosmian_cng.dll` now canonicalizes to an absolute path before writing to the registry (Windows CNG cannot resolve relative paths)
- Fix `ckms cng verify` "DeleteKey + verify gone" test: expect `NTE_BAD_KEYSET` (0x80090016) instead of wrong `NTE_NO_KEY` constant, matching the actual CNG provider behavior
- **Fix `test_cng_ksp.ps1` silently swallowing errors**: `Invoke-Native` no longer uses an empty `catch {}` that hides stderr output; stderr lines are now forwarded to the host so failures are always visible in CI logs
- Fix `ckms cng verify` failure details (`[FAIL]` lines) going to stderr: output now goes to stdout so it is visible alongside other test output regardless of how the calling script handles stderr
- **Fix `Export-IntunePublicKey` failing with NTE_INVALID_PARAMETER**: `open_key` now also locates the public key UUID so `ExportKey` returns the correct SPKI blob instead of trying to export the private key
- **Fix CNG KSP public key export for PKCS#1 format**: `export_public_blob` now falls back to parsing raw PKCS#1 RSAPublicKey when the KMS returns that format instead of SPKI-wrapped

## Features

- Server and ckms wizards now create directories recursively when paths are entered by the user (covers macOS, Windows, and Linux)
- Windows NSIS installer creates `$INSTDIR\{logs,data}` subdirectories for service use and cleans them on uninstall
- **Implement Windows Service Control Manager (SCM) integration**: the server binary now registers with the SCM when launched as a service, reports `Running`/`Stopped` states, and responds to `Stop` signals for graceful shutdown via the `windows-service` crate
- Installer `sc create` fallback: if the service already exists (e.g. pending deletion), use `sc config` to update binPath and start type
- **Implement `Export-IntunePrivateKey` support in CNG KSP**: handle `PKCS8_PRIVATEKEY` blob type in `NCryptExportKey` to return the private key in PKCS#8 DER format
- **Implement `Import-IntunePrivateKey` support in CNG KSP**: handle PEM-encoded private key import via `NCryptSetProperty("RSAFULLPRIVATEBLOB")` + `NCryptFinalizeKey`, detecting PEM vs CNG blob vs raw DER formats
- **Dynamic vendor_id in CNG KSP and PKCS#11 provider**: query the KMS server's `vendor_identification` via KMIP `Query(QueryServerInformation)` at connection time instead of hardcoding `VENDOR_ID_COSMIAN`; falls back to the Cosmian constant if unavailable

## Testing

- **Add Intune PFX Import workflow test** to `test_cng_ksp.ps1`: exercises `Add-IntuneKspKey` + `Export-IntunePublicKey` + `Export-IntunePrivateKey` + `Import-IntunePrivateKey` via the `IntunePfxImportUtilities` module against the registered KSP (requires `INTUNE_PFX_MODULE_PATH` env var)
- **Fix `test_cng_ksp.ps1` PowerShell 5.1 compatibility**: use `cmd /c` wrapper in `Invoke-Native` to prevent PS 5.1 from treating stderr as a terminating `NativeCommandError` when `$ErrorActionPreference = "Stop"`
- **Fix `test_cng_ksp.ps1` registration collision**: unregister the KSP before registering to avoid `STATUS_OBJECT_NAME_COLLISION` (0xc0000035) on repeated runs
- **Fix `test_cng_ksp.ps1` list-keys validation**: check for key existence via output message pattern instead of key name (ckms list-keys outputs UIDs)
- Enhance `ckms cng list-keys` to display CNG key names alongside UIDs (resolved from KMIP tags)

## Documentation

- Update logging documentation to reflect the new Windows and macOS default log directories and document the graceful fallback behavior
- Add Intune PFX import workflow documentation (`Add-IntuneKspKey`) to CNG KSP page
- Add `certutil -csplist` verification step to CNG KSP registration docs
