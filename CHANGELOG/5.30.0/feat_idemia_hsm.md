## Features

### HSM

- Add the `idemia_sphere` HSM model (`--hsm-model idemia_sphere`, `hsm_model = "idemia_sphere"`), tested against the Idemia HSM Simulator; the PKCS#11 library is overridable with `IDEMIA_SPHERE_PKCS11_LIB` (default on Windows: `C:\Idemia_HSM_Simulator\librooky-simulator.dll`).
- The KMS server now starts with an HSM on Windows (`idemia_sphere`, `softhsm2` and `other`); other models keep their Linux/macOS gates.

### CI

- Add the Windows CI job `test-hsm-idemia` (`non-fips` and `fips` variants) and the `test:hsm:idemia-sphere-simulator` mise task, driven by `.github/reusable_scripts/prepare_idemia_hsm.ps1`, `.mise/scripts/windows/test_hsm_idemia.ps1` and `.mise/scripts/windows/test_hsm_other.ps1`.
- Windows FIPS builds are tested against the OpenSSL FIPS provider (`fips.dll`, built by `.mise/scripts/windows/prepare_windows_fips_provider.ps1`); the PKCS#11 IV shim (`.mise/scripts/test/pkcs11_fips_iv_shim.c`) now runs on Windows and isolates its OpenSSL-based backend from the KMS's `OPENSSL_CONF`.
- `test:hsm:other` runs on Windows (SoftHSM2 behind the IV shim) in both FIPS variants.
- Package a Windows FIPS server installer, `cosmian-kms-server-fips-static-openssl_<version>_x86_64.exe` (job `windows-package-fips`, `build_windows.yml` `variant: fips`): it ships the OpenSSL 3.1.2 FIPS provider under `<install dir>\openssl` and gives the `CosmianKMS` service `OPENSSL_CONF`, `OPENSSL_MODULES` and `OPENSSL_CONF_INCLUDE` through its registry `Environment` value; `openssl\cosmian_kms_fips.cmd` runs the server from a console. CI signs it, installs it silently, checks the service answers `GET /version`, that the server refuses to start without the provider, and uninstalls it (`.mise/scripts/windows/test_windows_package.ps1`); it is published under `windows/x86_64/fips/static-openssl`. The non-FIPS installers now also carry `openssl\variant.txt`.
- Move the helpers shared by the Windows build, packaging and HSM scripts into `.mise/scripts/windows/common.ps1`; the installer renaming and version parsing of `build_windows.yml` now live in `cargo_build.ps1`.

## Documentation

- Add the [Idemia SPHERE](documentation/docs/hsm_support/idemia_sphere.md) HSM page: simulator setup, KMS configuration, observed `FIPS` mode limitations.
- Describe the Windows FIPS server installer in [Getting started](documentation/docs/installation/installation_getting_started.md).
