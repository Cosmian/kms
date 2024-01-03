The Cosmian server supports a growing list of cryptographic algorithms. When the KMS is built in FIPS mode, some algorithms are disabled to fulfill FIPS-140 standard compliance.

## Key-wrapping

The Cosmian server supports key-wrapping via the `Import`(unwrapping) and `Export` (wrapping) kmip operations.
The (un)wrapping key identifier may be that of a key or a certificate.
In the latter case, the public key (or the associated private key for unwrapping, if any) will be retrieved and used.

### Normal mode
The supported key-wrapping algorithms are:

| Algorithm            | Wrap Key Type              | Description                                                                                                   |
|----------------------|----------------------------|---------------------------------------------------------------------------------------------------------------|
| AES-KWP              | Symmetric key wrapping     | Symmetric key-wrapping with padding as defined in [RFC3394](https://tools.ietf.org/html/rfc5649).             |
| CKM_RSA_AES_KEY_WRAP | Hybrid key wrapping        | RSA OAEP with SHA256 with AES-KWP for RSA key size 2048, 3072 or 4096 bits.                                   |
| Salsa Sealed Box     | X25519, Ed25519            | ECIES compatible with libsodium [Sealed Box](https://doc.libsodium.org/public-key_cryptography/sealed_boxes). |
| ECIES NIST AES-128   | P-192, P-224, P-256, P-384 | ECIES with a NIST curve and AES-128-GCM.                                                                      |

### FIPS mode
When in FIPS mode, the KMS currently only supports:

| Algorithm            | Wrap Key Type          | Description                                                                                       |
|----------------------|------------------------|---------------------------------------------------------------------------------------------------|
| AES-KWP              | Symmetric key wrapping | Symmetric key-wrapping with padding as defined in [RFC3394](https://tools.ietf.org/html/rfc5649). |
| CKM_RSA_AES_KEY_WRAP | Hybrid key wrapping    | RSA OAEP with SHA256 with AES-KWP for RSA key size 2048, 3072 or 4096 bits.                       |



- `Salsa sealed box` uses X25519 and XSalsa20-Poly1305. A Ed25519 wrapping key can be used; it will be converted to
  X25519 first.
- There is no NIST standard for ECIES; `SalsaSealbox` is fast and widely used.

- `AES-KWP` allows to symmetrically wrap keys using [RFC5649](https://tools.ietf.org/html/rfc5649).

- `CKM_RSA_AES_KEY_WRAP` is a PKCS#11 mechanism that is supported by most HSMs. Asymmetrically wrap keys referring to PKCS#11 as described [here](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908). This document describes how to unwrap keys of any size using asymmetric encryption and the RSA algorithm. Since old similar wrapping methods based on RSA used naive RSA encryption and could present some flaws, it aims at a generally more secure method to wrap keys. Receive data of the form `c|wk` where `|` is the concatenation operator. Distinguish `c` and `wk`, respectively the encrypted `kek` and the wrapped key. First decrypt the key-encryption-key `kek` using RSA-OAEP, then proceed to unwrap the key by decrypting `m = dec(wk, kek)` using AES-KWP as specified in [RFC5649](https://tools.ietf.org/html/rfc5649). It is also compatible with Google KMS.

- `Salsa sealed box` uses X25519 and XSalsa20-Poly1305. A Ed25519 wrapping key can be used; it will be converted to X25519 first.

- There is no NIST standard for `ECIES`; `SalsaSealbox` is fast and widely used.


## Encryption schemes

Encryption is supported via the `Encrypt` and `Decrypt` kmip operations.
For bulk operations (i.e. encrypting/decrypting multiple data with the same key),
please refer to [KMIP Messages](./messages.md) that allow combining multiple operations in a single request.

Encryption can be performed using a key or a certificate. Decryption can be performed using a key.

### Normal mode
The supported encryption algorithms are:

| Algorithm                    | Encryption Key Type                                     | Description                                                                                                                                      |
|------------------------------|---------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Covercrypt                   | Covercrypt                                              | A fast post-quantum attribute based scheme: [Covercrypt](https://github.com/Cosmian/cover_crypt).                                                |
| AES-128-GCM<br />AES-256-GCM | Symmetric authenticated encryption with additional data | The NIST standardized symmetric encryption in [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).                         |
| CKM_RSA_AES_KEY_WRAP         | Hybrid encryption                                       | RSA OAEP with SHA256 with AES-KWP for RSA key size 2048, 3072 or 4096 bits. This will change to use AES-GCM instead of AES-KWP in a near future. |
| Salsa Sealed Box             | X25519, Ed25519                                         | ECIES compatible with libsodium [Sealed Box](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).                                    |
| ECIES NIST AES-128           | P-192, P-224, P-256, P-384                              | ECIES with a NIST curve and AES-128-GCM.                                                                                                         |

### FIPS mode
When in FIPS mode, the KMS currently only supports:

| Algorithm                    | Encryption Key Type                                     | Description                                                                                                                                       |
|------------------------------|---------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| AES-128-GCM<br />AES-256-GCM | Symmetric authenticated encryption with additional data | The NIST standardized symmetric encryption in [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).                          |
| CKM_RSA_AES                  | Hybrid encryption                                       | RSA OAEP with SHA256 with AES-KWP for RSA key size 2048, 3072 or 4096 bits.  This will change to use AES-GCM instead of AES-KWP in a near future. |

- [Covercrypt](https://github.com/Cosmian/cover_crypt) is a new post-quantum cryptographic algorithm, being standardized
  at [ETSI](https://www.etsi.org/) that allows creating ciphertexts for a set of attributes and issuing user keys with access policies over these
  attributes. User keys are traceable with a unique fingerprint.

- AES is used in Galois Counter Mode ([GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)) with a 96 bits nonce and a 128 bits tag with a keysize of 128 or 256 bits.

- `CKM_RSA_AES` is a PKCS#11 mechanism that is supported by most HSMs. It is initially used to asymmetrically wrap keys referring to PKCS#11 as described [here](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908). For general hybrid encryption using RSA-DEM, AES-GCM will be used instead of AES-KWP in a near future.

- `Salsa sealed box` uses X25519 and XSalsa20-Poly1305. A Ed25519 wrapping key can be used; it will be converted to X25519 first.

- There is no NIST standard for `ECIES`; `SalsaSealbox` is fast and widely used.

## Signature

Signature is only supported via the `Certify` operation, which is used to create a certificate either by signing a certificate request,
or building it from an existing public key.

### Normal mode
The KMS supports the following algorithms for digital signature:

| Algorithm | Signature Key Type                 | Description                                                                                                               |
|-----------|------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| ECDSA     | P-192, P-224, P-256, P-384, X25519 | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) and NIST.SP.800-186 - Section 3.1.2 table 2. |
| EdDSA     | Ed25519                            | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf).                                             |

### FIPS mode
The FIPS standard restricts specific curves on which to perform digital signature algorithms.

| Algorithm | Signature Key Type         | Description                                                                                                               |
|-----------|----------------------------|---------------------------------------------------------------------------------------------------------------------------|
| ECDSA     | P-224, P-256, P-384, P-521 | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) and NIST.SP.800-186 - Section 3.1.2 table 2. |
| EdDSA     | Ed25519                    | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf).                                             |

- `ECDSA` performs digital signatures on elliptic curves `P-192`, `P-224`, `P-256`, `P-384`, `P-512` and `X25519`.

- `EdDSA` performs digital signatures on Edwards curves `Ed25519`.


## Password-based key derivation
The randomness of cryptographic keys is essential for the security of cryptographic applications. Sometimes, passwords may be the only input required from the users who are eligible to access the data. Due to the low entropy and possibly poor randomness of those passwords, they are not suitable to be used directly as cryptographic keys. The KMS addresses this problem by providing methods to derive a password into a secure cryptographic key.

### Normal mode
In normal mode, passwords are derived using `Argon2` hash algorithm with constant salt. Argon2 has the property of being computationally intensive making it significantly harder to crack by brute force only.

### FIPS mode
In FIPS mode, passwords are derived using FIPS compliant `PBKDF2_HMAC` with `SHA512` and recommended 210,000 iterations by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) which follows FIPS recommendations as well. An additional random 128-bits salt is used.
