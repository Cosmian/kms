## Features

### Server
- Add AES-CMAC (NIST SP 800-38B) and AES-GMAC (NIST SP 800-38D) to the KMIP `MAC` and `MACVerify` operations, single-part and multi-part, with AES-128/192/256 keys. `Cryptographic Parameters` select the algorithm: `Block Cipher Mode` = `CMAC` or `GCM`. A GMAC `MAC Data` is the random 12-byte IV followed by the 16-byte tag, so a verifier needs no extra field ([#1367](https://github.com/Cosmian/kms/issues/1367))
- GMAC runs through the OpenSSL provider's `GMAC` `EVP_MAC` (IV passed as a parameter, FIPS provider included) instead of AES-GCM with an external IV. The KMIP `MAC` request gains the vendor extension `IVCounterNonce` (12 bytes, GMAC only; random when absent) so a client can choose the IV; the response `MACData` stays `IV || tag`
- Allow the `CMAC` block cipher mode in the default KMIP algorithm policy
- Add NIST known-answer test vectors for AES-CMAC and AES-GMAC

### HSM
- `MacAlgorithm` gains `AesCmac` (`CKM_AES_CMAC`) and `AesGmac` (`CKM_AES_GMAC`); the PKCS#11 HSM backends now delegate AES-CMAC and AES-GMAC to the HSM when the AES key is HSM-resident, instead of answering "not supported". `CKM_AES_GMAC` is sent with a standard `CK_GCM_PARAMS`. The HMAC variants are mapped to `CKM_*_HMAC` too, but only AES-typed HSM keys reach this path, so HMAC on an HSM key stays unavailable until a generic-secret key type is supported

### CLI
- Add `ckms mac compute|verify --mode {hmac,cmac,gmac}`. The AES key needs the `MAC Generate` / `MAC Verify` usage bits, e.g. `ckms sym keys import -f aes key.bin --key-usage mac-generate --key-usage mac-verify`

### PKCS#11
- Add the `CKM_AES_CMAC` and `CKM_AES_GMAC` mechanisms to the PKCS#11 provider. `CKM_AES_GMAC` follows PKCS#11 v3.0 §2.13.4: `CK_GCM_PARAMS` with the caller's 12-byte IV and a 128-bit tag, the `C_Sign` data is the authenticated data and the signature is the 16-byte tag. Both mechanisms run as KMIP `MAC` / `MACVerify` and need the `MAC Generate` / `MAC Verify` usage bits; the GMAC IV is passed in the new `IVCounterNonce` field of `MAC`, so it runs as the OpenSSL provider's `GMAC` (FIPS provider included) instead of AES-GCM with a caller IV

### UI
- Add a MAC type selector (HMAC, AES-CMAC, AES-GMAC) to the MAC compute and verify pages

---

Closes #1367
