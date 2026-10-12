# PKCS#11 provider: contain internal panics

## Bug Fixes

### PKCS#11

- Return `CKR_GENERAL_ERROR` instead of terminating the host process when the PKCS#11 provider hits an unexpected internal panic.
  Every `C_*` entry point, including `C_GetFunctionList`, `C_GetInterfaceList` and `C_GetInterface`, is now guarded.
  After such an event the library refuses all further calls, including `C_Finalize` and `C_Initialize`, until the host process is restarted.
- Report a failure to start the internal Tokio runtime or to seed the key RNG as an ordinary PKCS#11 error instead of aborting the host.
- Reject oversized symmetric key lengths before any allocation or entropy is drawn.
- Return an error from `C_OpenSession` instead of panicking when the session table is unusable.

## Build

- Build the shipped PKCS#11 library (`libcosmian_pkcs11.so` / `.dylib` / `cosmian_pkcs11.dll`) with the new `pkcs11-provider` Cargo profile (release settings with `panic = "unwind"`) so that panics can be contained.
  `ckms` and the server keep `panic = "abort"`.
  Nix, Windows packaging and `ckms` PKCS#11 tests use this profile.
- Packaging now fails when the Nix CLI output does not contain `libcosmian_pkcs11.so`.
- Remove `panic = "abort"` from the Cargo `dev` profile.

## Testing

- Add subprocess tests that load the real shipped-profile library through direct exports and through the function table, trigger a contained panic, and check that later calls are refused.
