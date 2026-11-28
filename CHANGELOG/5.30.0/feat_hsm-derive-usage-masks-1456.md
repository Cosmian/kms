## Features

### HSM

- Derive the KMIP `CryptographicUsageMask` of HSM AES and RSA keys from their PKCS#11 `CKA_ENCRYPT`/`CKA_DECRYPT`/`CKA_SIGN`/`CKA_VERIFY`/`CKA_WRAP`/`CKA_UNWRAP` attributes instead of a hardcoded mask (AES `CKA_SIGN`/`CKA_VERIFY` map to `MACGenerate`/`MACVerify`). HSMs that do not expose these attributes keep the previous mask. ([#1456](https://github.com/Cosmian/kms/issues/1456))
