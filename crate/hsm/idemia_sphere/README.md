# Idemia SPHERE

PKCS#11 loader for the Idemia SPHERE HSM (`hsm_model = "idemia_sphere"`).

It is tested against the Idemia HSM Simulator, a Windows-only PKCS#11 DLL (`librooky-simulator.dll`) that
forwards every call to a SoftHSM2 backend in `NON_FIPS` mode, hence the SoftHSM2 capability profile.

The PKCS#11 library path defaults, on Windows, to `C:\Idemia_HSM_Simulator\librooky-simulator.dll` and is
overridden by the `IDEMIA_SPHERE_PKCS11_LIB` environment variable (mandatory on Linux and macOS).

## Running the tests

Stage the simulator and a token with `.github/reusable_scripts/prepare_idemia_hsm.ps1`, which writes the
variables to `.idemia-sim\env`, then (PowerShell, `HSM_SLOT_ID` is in that file):

```powershell
$env:PATH = "C:\SoftHSMv2\bin;$env:PATH"
cargo test -p idemia_sphere_pkcs11_loader --features "idemia_sphere non-fips" -- --nocapture --ignored --exact tests::test_hsm_idemia_sphere_all
```

Run the tests one at a time (`--exact`): the simulator DLL does not survive several concurrent
`C_Initialize` / `C_Finalize` cycles in one process.

The whole Windows suite (loader, server, vectors, KEK startup, shared server, real binary) is
`.mise/scripts/windows/test_hsm_idemia.ps1`. See `documentation/docs/hsm_support/idemia_sphere.md`.
