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

## Bug Fixes

### FIPS
- A FIPS build generates every AES-GCM IV inside the OpenSSL FIPS provider (NIST SP 800-38D §9.1, FIPS 140-3 IG C.H) and refuses an `Encrypt` or `MAC` (GMAC) request, a PKCS#11 `C_EncryptInit` or an HSM encryption that carries an IV chosen by the client. Client action: leave `IVCounterNonce` out of the request; the server returns the IV it generated, `C_EncryptMessage` with `CKG_GENERATE_RANDOM` is the PKCS#11 way. A FIPS build seals AES-GCM with the full 16-byte tag and decrypts with the 96-bit IV it generates; a non-FIPS build still accepts a caller IV
- Count the AES-GCM invocations made with each key in the new `gcm_invocations` table (created at startup) and refuse `Encrypt`, `MAC` and AES-GCM wrapping with `Permission_Denied` once a key reaches 2^32 invocations (NIST SP 800-38D §8.3); decryption stays possible, rekey to continue
- Enforce the AES-GCM invocation cap on the Redis-findex store too (atomic Lua reservation, non-FIPS builds); it used to grant every reservation
- Fix KMIP `Usage Limits` accounting: the budget is now reserved atomically (version-checked update with retries, `Conflict` after 8 failed attempts) before the operation, so concurrent requests can no longer overrun it; consumption decrements the `Usage Limits Count`, never the Total (KMIP 2.1 §4.59), and objects stored before keep using their Total as the remaining budget. The server sets the Count to the Total on `Create`, `CreateKeyPair`, `Register`, `DeriveKey` and on a client `Add`/`Set`/`Modify Attribute` of `Usage Limits` (a client Count is ignored)
- Refuse to start the FIPS server when the non-validated `default` OpenSSL provider is active (for example through `OPENSSL_CONF`), and set the `fips=yes` default property so that no algorithm is fetched outside the FIPS module
- Refuse, in a FIPS build, to generate an HMAC with a key under 112 bits (NIST SP 800-131A r2) and a PBKDF2 `DeriveKey` with a salt under 16 bytes, fewer than 1,000 iterations or a derived key under 14 bytes (NIST SP 800-132); verifying with a legacy HMAC key stays possible
- Compute the SHA-1 key identifiers of certificates and CRLs, the AWS XKS integrity hash and the JOSE CEK cache key through the OpenSSL EVP interface (the FIPS provider in a FIPS build), and derive and seal the Crypto Officer ceremony records with OpenSSL (SHAKE-256 and AES-256-GCM with a provider-generated IV). Stored ceremony records and Redis key names stay readable
- Refuse `CreateKeyPair` for Ed25519 and Ed448 in a FIPS build: the OpenSSL FIPS provider has no EdDSA
- Fix `Import` of an Ed25519 PKCS#8 key in a FIPS build closing the TLS connection of an in-flight request: the OpenSSL decoder left its failed provider attempts on the thread's error queue and the next `SSL_read` failed on them. The queue is now drained after the parse

### HSM
- Remove `allows_caller_iv_in_fips`: a FIPS build never sends an AES-GCM IV to an HSM, `SoftHSM2` and Kryoptic included, and refuses RSA PKCS#1 v1.5 and SHA-1 OAEP encryption on an HSM key
- Default HSM key wrapping probe tolerates a key encryption key that does not exist yet (the bootstrap flow creates it after startup)

### CLI
- Remove AES-XTS from the data and key encryption algorithms of a FIPS build of `ckms`, where the server does not support it
- `ckms pkcs11 capabilities` skips the caller-IV `CKM_AES_GCM` and `CKM_AES_GMAC` checks in a FIPS build; `C_EncryptMessage` still covers AES-GCM
- `ckms symmetric encrypt` with a client-side key encryption key generates the AES-GCM IV inside the OpenSSL provider and writes it ahead of the ciphertext (file format unchanged); a FIPS build refuses `--nonce` for AES-GCM
- `ckms bench` in a FIPS build skips the HSM AES-GCM and RSA PKCS#1 v1.5 encrypt operations that the FIPS server refuses; `bench:hsm --variant fips` starts the `SoftHSM2` and Kryoptic KEK server with `key_encryption_key_wrapping_algorithm = "aes-key-wrap-padding"`

### UI
- Hide the nonce field of AES-GCM encryption when the server runs in FIPS mode

---

Closes #1367
