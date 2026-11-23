# Idemia SPHERE

The Idemia SPHERE integration is a native HSM model of the KMS: `hsm_model = "idemia_sphere"`.

It is tested against the **Idemia HSM Simulator** (version 0.0.0.1), a PKCS#11 DLL that runs on
**Windows 10/11 (x86\_64)** only and forwards every call to a SoftHSM2 backend (in `FIPS` mode it refuses the
mechanisms listed [below](#fips-mode)). On Linux and macOS the model is available too, provided
`IDEMIA_SPHERE_PKCS11_LIB` points to the Idemia SPHERE PKCS#11 client library. On Windows the KMS also supports
`softhsm2` and `other`.

## How the KMS connects to the HSM

The KMS loads one PKCS#11 library: by default on Windows `C:\Idemia_HSM_Simulator\librooky-simulator.dll`
(override with `IDEMIA_SPHERE_PKCS11_LIB`, mandatory on Linux and macOS). The simulator DLL reads its own
configuration file (`rooky-simulator.cfg`) and loads the SoftHSM2 DLL it names.

The simulator DLL exports only the classic PKCS#11 `C_*` functions (no `C_GetInterface`, no PKCS#11 v3 message
API): the KMS uses the PKCS#11 v2 calls, with the capability profile of SoftHSM2.

The Idemia SPHERE provisioning functions (`CS_HSMProvisioning`, `CS_ListSE`, …) are not used by the KMS.
Leave `IS_HSM_IDEMIA_SPHERE = false` in the simulator configuration.

## Set up the simulator

### Shortcut: `prepare_idemia_hsm.ps1`

`.github/reusable_scripts/prepare_idemia_hsm.ps1` performs every step of this section, and is what the KMS
CI runs. From the repository root, with the simulator package unpacked in `<PACKAGE_DIR>`
(it must hold `librooky-simulator.dll`, `rooky-simulator.cfg` and `SoftHSM V2.7.0.zip`; the
`hsm-idemia-simulator.zip` in the `reusable_scripts` submodule also bundles `libcrypto-3-x64.dll`, the OpenSSL
runtime SoftHSM2 needs and the GitHub Windows runners do not provide):

```powershell
.\.github\reusable_scripts\prepare_idemia_hsm.ps1 -PackageDir '<PACKAGE_DIR>'
```

| Parameter | Default | Description |
|---|---|---|
| `-PackageDir` | `$env:IDEMIA_SIM_PACKAGE_DIR` | Directory holding the three package files. When empty, the package is taken from `-PackageUrl`, else from the `hsm-idemia-simulator.zip` shipped next to the script in the `reusable_scripts` submodule. |
| `-PackageUrl` | `$env:IDEMIA_SIM_PACKAGE_URL`, else empty | Zip archive of the three package files (HTTP/HTTPS only). |
| `-SimRoot` | `C:\Idemia_HSM_Simulator` | Simulator root folder. |
| `-SoftHsmRoot` | `C:\SoftHSMv2` | SoftHSM2 folder (the leaf must be `SoftHSMv2`). |
| `-SecurityLevel` | `NON_FIPS` | `NON_FIPS` or `FIPS`, written to `SECURITY_LEVEL`. |
| `-LogLevel` | `INFO` | `INFO` or `DEBUG`, written to `LOG_LEVEL`. |
| `-Pin` | see the script | User and SO PIN of the new token. |
| `-EnvFile` | `.idemia-sim\env` in the repository | Receives the variables below. |

Each run installs a fresh token labelled `idemia_sim`. The script writes `IDEMIA_SPHERE_PKCS11_LIB`,
`SOFTHSM2_CONF`, `HSM_MODEL`, `HSM_USER_PASSWORD`, `HSM_SLOT_ID` and `IDEMIA_SOFTHSM_BIN` to `-EnvFile`
(and, in GitHub Actions, to `GITHUB_ENV` and `GITHUB_PATH`).

### Manual set up

1. **SoftHSM2.** Extract `SoftHSM V2.7.0.zip` to `C:\`: it creates `C:\SoftHSMv2\{bin,etc,lib\softhsm,var\softhsm2\tokens}`.
   Its `softhsm2-util.exe` and `libsofthsm2.dll` need the OpenSSL runtime `libcrypto-3-x64.dll`, which the archive
   does not contain: copy it into `C:\SoftHSMv2\bin` (the MSYS2/mingw build shipped by Git for Windows in
   `mingw64\bin` works).
2. **`C:\SoftHSMv2\etc\softhsm2.conf`:**

   ```ini
   directories.tokendir = C:\SoftHSMv2\var\softhsm2\tokens
   objectstore.backend = file
   objectstore.umask = 0077
   log.level = INFO
   slots.removable = false
   slots.mechanisms = ALL
   library.reset_on_fork = false
   ```

3. **Environment.** `C:\SoftHSMv2\bin` must be in `PATH` (the simulator DLL loads SoftHSM2 and its mingw runtime
   through it) and `SOFTHSM2_CONF` must be `C:\SoftHSMv2\etc\softhsm2.conf`:

   ```powershell
   $env:PATH = "C:\SoftHSMv2\bin;$env:PATH"
   $env:SOFTHSM2_CONF = "C:\SoftHSMv2\etc\softhsm2.conf"
   ```

4. **Simulator root.** Create `C:\Idemia_HSM_Simulator\` with `librooky-simulator.dll`, `rooky-simulator.cfg`
   and an empty `log\` folder (it must exist before the DLL is loaded). The configuration file is looked up in
   `C:\Idemia_HSM_Simulator\`, then next to the DLL; the `IDEMIA_PKCS11_ROOT` environment variable selects another
   root folder.
5. **`C:\Idemia_HSM_Simulator\rooky-simulator.cfg`**, with the values used by the KMS CI:

   | Key | Value | Description |
   |---|---|---|
   | `SECURITY_LEVEL` | `NON_FIPS` | `NON_FIPS` forwards every call to the backend. `FIPS` disables `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`. |
   | `LOG_PATH` | `C:\Idemia_HSM_Simulator\log\HSM_simulator.log` | Log file. |
   | `LOG_LEVEL` | `INFO` | `INFO` logs the PKCS#11 requests and responses; `DEBUG` also logs every frame (very large). |
   | `PKCS11_DLL_PATH` | `C:\SoftHSMv2\lib\softhsm\libsofthsm2.dll` | Backend PKCS#11 DLL. |
   | `IS_HSM_IDEMIA_SPHERE` | `false` | Enables the SPHERE-only `CS_*` functions, which the KMS never calls. |

6. **Token.** Initialise a token. The slot number is reassigned from the token serial number:

   ```powershell
   C:\SoftHSMv2\bin\softhsm2-util.exe --init-token --free --label idemia_sim --so-pin <PIN> --pin <PIN>
   ```

   The output ends with `The token has been initialized and is reassigned to slot <SLOT_ID>`: use that number
   as `hsm_slot`. `softhsm2-util.exe --show-slots` lists the slots again.

## KMS configuration

At least one slot and its PIN must be configured.

### Configuration via config file

Set the HSM parameters in the [TOML configuration file](../configuration/server_configuration_file.md):

```toml
hsm_model = "idemia_sphere"
hsm_admin = ["<HSM_ADMIN_USERNAME>"] # defaults to "admin"
hsm_slot = [<SLOT_ID>]
hsm_password = ["<PIN>"]
```

`hsm_slot` and `hsm_password` are arrays, in the same order. See [HSM keys & operations](hsm_operations.md)
for the HSM administrator role, and [Multi-HSM support](multi_hsm.md) to combine several HSMs.

### Configuration via command-line

```shell
--hsm-model idemia_sphere \
--hsm-admin "<HSM_ADMIN_USERNAME>" \
--hsm-slot <SLOT_ID> --hsm-password <PIN>
```

### Start the server on Windows

```powershell
$env:PATH = "C:\SoftHSMv2\bin;$env:PATH"
$env:SOFTHSM2_CONF = "C:\SoftHSMv2\etc\softhsm2.conf"
cosmian_kms.exe -c kms.toml
```

To load another library than the default simulator DLL, set `IDEMIA_SPHERE_PKCS11_LIB`:

```powershell
$env:IDEMIA_SPHERE_PKCS11_LIB = "<PATH_TO_THE_PKCS11_LIBRARY>"
```

If the library cannot be loaded, the server exits with
`Failed to instantiate the Idemia SPHERE HSM (lib: <path>)`. A `LoadLibrary` error 126 means a dependency
DLL is not found (check `PATH` and `libcrypto-3-x64.dll`), 193 that the DLL is not 64-bit.

### HSM-held key encryption key

An HSM key can wrap every key the KMS stores, with `key_encryption_key`. See
[Automatically using the server configuration](hsm_operations.md#automatically-using-the-server-configuration).

## PKCS#11 capabilities of the simulator DLL

Observed on `librooky-simulator.dll` (V0.0.0.1, x86\_64) by loading it, calling `C_GetFunctionList`, `C_GetInfo`,
`C_GetMechanismList` and `C_GetMechanismInfo` on a SoftHSM2 2.7 token, once per `SECURITY_LEVEL`.

### PKCS#11 version

- **v2.x function table, no v3 interface.** The DLL exports `C_GetFunctionList` and no `C_GetInterfaceList` /
  `C_GetInterface`, and the returned `CK_FUNCTION_LIST` has the 68 v2 entries: none of the v3.0 message-based
  functions (`C_MessageEncryptInit`, `C_EncryptMessage`, `C_SignMessage`, …) or v3.2 additions exist.
- The version field of the function list is `0.0` (never set by the simulator); do not use it to detect the version.
- `C_GetInfo` is forwarded to the backend and reports the backend's data (`cryptokiVersion` 3.2 and manufacturer
  `SoftHSM` for SoftHSM2 2.7). That is the backend's version, not a v3 capability of the DLL.
- Tokens report the backend's identity (`SoftHSM project`, model `SoftHSM v2`); the label is the one set at
  `--init-token` (`idemia_sim`).

### Exported functions

78 exports: 61 standard `C_*` functions and 17 Idemia `CS_*` functions.

| Group | Functions | Status |
|---|---|---|
| General | `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList` | available |
| Slots and tokens | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_WaitForSlotEvent` | available |
| Sessions | `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_GetOperationState`, `C_SetOperationState`, `C_Login`, `C_Logout` | available |
| Objects | `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetObjectSize`, `C_GetAttributeValue`, `C_SetAttributeValue`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal` | available |
| Encryption | `C_EncryptInit`, `C_Encrypt`, `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptInit`, `C_Decrypt`, `C_DecryptUpdate`, `C_DecryptFinal` | available |
| Digest | `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestKey`, `C_DigestFinal` | available |
| Sign / verify | `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal`, `C_VerifyInit`, `C_Verify`, `C_VerifyUpdate`, `C_VerifyFinal` | available |
| Key management | `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey` | available in `NON_FIPS`; refused in `FIPS` (per the configuration file) |
| Random | `C_SeedRandom`, `C_GenerateRandom` | available |
| Legacy | `C_GetFunctionStatus`, `C_CancelFunction` | exported |
| Not provided | `C_SignRecoverInit`, `C_SignRecover`, `C_VerifyRecoverInit`, `C_VerifyRecover`, `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` | NULL in the function list (neither exported nor forwarded) |
| Idemia SPHERE | `CS_ClusterAllocate/Deallocate/Sync`, `CS_DomainAllocate/Deallocate/Sync`, `CS_FarmAllocate/Deallocate/Sync`, `CS_GetInfo`, `CS_HSMProvisioning`, `CS_HSMDeprovisioning`, `CS_ListCluster`, `CS_ListDomain`, `CS_ListFarm`, `CS_ListSE`, `CS_SendFrame` | forwarded to the backend only when `IS_HSM_IDEMIA_SPHERE = true`, else `CKR_FUNCTION_NOT_SUPPORTED`; not used by the KMS |

The eight functions of the "Not provided" row are non-NULL in the SoftHSM2 function table but NULL in the
simulator's, so the simulator does not forward them.

### Mechanisms

The simulator filters the backend's 79 mechanisms: `C_GetMechanismList` returns **48** in `NON_FIPS` and **39** in
`FIPS`; `C_GetMechanismInfo` refuses (`CKR_MECHANISM_INVALID`) every mechanism not in the list, except as noted.
Sizes are key bits (RSA, EC), bytes (AES), or the size range reported by SoftHSM2.

| Family | Mechanisms (`CKM_`) | `NON_FIPS` | `FIPS` |
|---|---|---|---|
| RSA key pair | `RSA_PKCS_KEY_PAIR_GEN` (512–16384) | yes | yes |
| RSA raw / OAEP | `RSA_PKCS` (encrypt, decrypt, sign, verify, wrap, unwrap), `RSA_PKCS_OAEP` (encrypt, decrypt, wrap, unwrap) | yes | no |
| RSA signatures with digest | `SHA224/256/384/512_RSA_PKCS`, `SHA224/256/384/512_RSA_PKCS_PSS`, `RSA_PKCS_PSS` | yes | yes |
| RSA signatures with SHA-1 | `SHA1_RSA_PKCS`, `SHA1_RSA_PKCS_PSS` | yes | no |
| RSA key wrap | `RSA_AES_KEY_WRAP` | yes | yes |
| EC key pair | `ECDSA_KEY_PAIR_GEN` (112–521 bits) | yes | yes |
| ECDSA | `ECDSA_SHA224/256/384/512` | yes | yes |
| ECDSA raw / SHA-1 | `ECDSA`, `ECDSA_SHA1` | yes | no |
| ECDH | `ECDH1_DERIVE` | yes | yes |
| AES | `AES_KEY_GEN` (16–32), `AES_ECB`, `AES_CBC`, `AES_CBC_PAD`, `AES_CTR`, `AES_GCM`, `AES_CMAC`, `AES_ECB_ENCRYPT_DATA`, `AES_CBC_ENCRYPT_DATA` | yes | yes |
| AES key wrap | `AES_KEY_WRAP` (RFC 3394) | yes | no |
| Triple-DES | `DES3_KEY_GEN`, `DES3_CBC`, `DES3_CBC_PAD` | yes | yes |
| Double-length DES | `DES2_KEY_GEN` | yes | no |
| Digests | `SHA_1`, `SHA224`, `SHA256`, `SHA384`, `SHA512` | yes | yes |
| HMAC | `SHA224/256/384/512_HMAC` | yes | yes |
| HMAC SHA-1 | `SHA_1_HMAC` | yes | no |
| DSA | `DSA_PARAMETER_GEN` only (512–1024) | yes | yes |

Mechanisms of the backend that the simulator refuses in both modes: `RSA_X_509`, `MD5_RSA_PKCS`, `DSA_KEY_PAIR_GEN`,
`DSA*` signatures, `DH_PKCS_*`, `DES_*` (single DES), `DES3_ECB`, `DES3_CMAC`, `DES*_ENCRYPT_DATA`, `MD5`,
`MD5_HMAC`, `GENERIC_SECRET_KEY_GEN`, `CONCATENATE_*`, `EC_EDWARDS_KEY_PAIR_GEN`, `EDDSA`, `AES_KEY_WRAP_PAD`
(`CKM_AES_KEY_WRAP_KWP`-style wrapping is therefore not available through the simulator).

Notes:

- No EdDSA, Montgomery curves (X25519/X448), ML-KEM/ML-DSA/SLH-DSA, AES-XTS, AES-CCM or HMAC-based
  key-derivation mechanisms are offered.
- `AES_GCM` is listed for encrypt and decrypt only (no wrap/unwrap); in `FIPS` mode the IV is not generated by the
  token (see [FIPS mode](#fips-mode)).
- Every mechanism of the `FIPS` list is also in the `NON_FIPS` list.

## Algorithm support

In `NON_FIPS` mode the simulator exposes the SoftHSM2 PKCS#11 behavior, hence the SoftHSM2 capability profile
in `crate/hsm/idemia_sphere/src/lib.rs`. The shared cross-backend suite passes completely
(`test_hsm_idemia_sphere_all`); see [HSM algorithm support by model](algorithm_support.md).

In `FIPS` mode (`-SecurityLevel FIPS`) the simulator does not offer, as observed with the same suite:

| Step | Result |
|---|---|
| AES key wrap (`CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_KWP`) | the mechanisms are not offered by the slot (the KMS refuses AES-KW / AES-KWP) |
| Raw RSA PKCS#1 v1.5 (`CKM_RSA_PKCS`), raw `CKM_ECDSA`, RSA-OAEP | listed, but refused at use: `FIPS REJECTED: ... not permitted in FIPS mode`. The KMS signs RSA PKCS#1 v1.5 digests (`RsaPkcsV15Digest`) and EC digests through the raw mechanisms, so the RSA and EC sub-CA flows do not work on a `FIPS` simulator |
| AES-GCM with a token-generated IV | the simulator forwards `CKM_AES_GCM` to SoftHSM2 and writes no IV back |
| Every other step (key generation, AES-CBC/MAC, hash-and-sign RSA-SHA/PSS and ECDSA signatures, EdDSA, metadata, search) | passes |

### FIPS mode

A KMS built without the `non-fips` feature only lets a token seal AES-GCM when the token generates the IV itself
(FIPS 140-3 IG C.H). The `FIPS` simulator does not, so the KMS refuses an HSM-held AES-GCM `key_encryption_key`
at startup (set `key_encryption_key_wrapping_algorithm` to a key-wrap algorithm on a token that offers one).

The FIPS-build tests therefore run on Windows with:

- the **OpenSSL FIPS provider** (`fips.dll`, 3.1.2), built by `.mise/scripts/windows/prepare_windows_fips_provider.ps1`
  and activated for the KMS through `OPENSSL_CONF` / `OPENSSL_MODULES`;
- a **PKCS#11 IV shim** (`.mise/scripts/test/pkcs11_fips_iv_shim.c`) in front of the simulator, which plays a FIPS
  module that generates the AES-GCM IV and refuses a caller IV. It also sets `SHIM_BACKEND_ISOLATE_OPENSSL`: the
  SoftHSM2 backend runs OpenSSL in the same process and must not load the KMS's FIPS provider a second time
  (SoftHSM2 then fails with `CKR_PIN_INCORRECT`). The shim logs each call to the file named by
  `FIPS_IV_SHIM_MARKER`, which the scripts check (every GCM init got a zero IV buffer and returned a generated IV).

This proves the KMS FIPS-mode policy and wiring on Windows; it does not make the build a validated module
deployment. Without the shim, the simulator is only used to prove the refusal.

## Testing

On a Windows host, with the simulator package in `<PACKAGE_DIR>`:

```powershell
$env:IDEMIA_SIM_PACKAGE_DIR = '<PACKAGE_DIR>'
.\.mise\scripts\windows\test_hsm_idemia.ps1          # NON_FIPS simulator, --features non-fips
.\.mise\scripts\windows\test_hsm_idemia.ps1 -Fips    # FIPS simulator, FIPS build, IV shim
.\.mise\scripts\windows\test_hsm_other.ps1 [-Fips]   # hsm_model = other: SoftHSM2 behind the IV shim
```

or, from Git Bash, `mise run test:hsm:idemia-sphere-simulator --variant <fips|non-fips>` and
`mise run test:hsm:other --variant <fips|non-fips>` (on Windows these dispatch to the scripts above). The
`test_hsm_idemia.ps1` script stages the simulator at the matching `SECURITY_LEVEL`, then runs the loader tests,
the server HSM tests, the HSM test vectors, the KMS startup with an HSM-held KEK, the shared-server suite twice
(without and with `KMS_HSM_KEK`), and finally starts `cosmian_kms.exe` with `hsm_model = "idemia_sphere"`. In
`-Fips` mode it ends with the check that a module that does not generate the IV is refused.

The Windows CI leg `windows-hsm-idemia` (`.github/workflows/test-group.yml`) runs both scripts for the `non-fips`
and `fips` variants.
