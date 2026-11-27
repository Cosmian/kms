# Changelog — fix/RUSTSEC-2026-0173 branch

## Security

- Upgrade `mysql_async` from `0.36` to `0.37` and add `default-features = false` to drop the `derive` feature; this removes the transitive `mysql-common-derive → proc-macro-error2` chain and eliminates `RUSTSEC-2026-0173` from the dependency graph without requiring an advisory ignore.

## Build

- Fix `shell.nix`: replace the unpinned `github.com/oxalica/rust-overlay` `fetchTarball` (no hash, fetches latest `stable` HEAD) with the same Cosmian-mirrored URL + `sha256` already used in `default.nix`, preventing transient GitHub curl failures on macOS CI runners.
- Fix Windows build/test: `vcpkg.json` puts vcpkg in manifest mode, which installs packages to `vcpkg_installed\x64-windows-static\` (project-relative, on `D:\`) instead of the classic-mode path `%VCPKG_INSTALLATION_ROOT%\packages\openssl_x64-windows-static` (on `C:\`). Updated `cargo_build.ps1`, `cargo_test.ps1`, and `build_windows.yml` to prefer the manifest-mode path and fall back to the classic-mode path.
