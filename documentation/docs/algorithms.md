The Cosmian server supports a large, and growing, list of cryptographic algorithms.
This page lists the supported algorithms, their details and their reference in various standards.
FIPS compliant
algorithms are also listed with the corresponding NIST standard.

Keys and certificates for all the listed algorithms can be generated, imported, exported, wrapped,
unwrapped... using
the Cosmian KMS server [API](./kmip_2_1/json_ttlv_api.md)
or [command line interface tool](./cli/cli.md)

Should you require a specific algorithm or standard to be supported, please directly open a ticket
or pull request on
the [Github repository](https://github.com/Cosmian/kms).

## Key-wrapping schemes

The Cosmian server supports key-wrapping via the `Import`(unwrapping) and `Export` (wrapping) kmip
operations.
The (un)wrapping key identifier may be that of a key or a certificate.
In the latter case, the public key (or the associated private key for unwrapping, if any) will be
retrieved and used.

The supported key-wrapping algorithms are:

| Algorithm            | Wrap Key Type                        | FIPS mode           | Description                                                                                                     |
|----------------------|--------------------------------------|---------------------|-----------------------------------------------------------------------------------------------------------------|
| AES-KWP              | Symmetric key wrapping               | NIST SP 800-38F     | Symmetric key-wrapping with padding as defined in [RFC5649](https://tools.ietf.org/html/rfc5649).               |
| CKM_RSA_PKCS         | RSA PKCS#1 v1.5                      | Not anymore         | RSA WITH PKCS#1 v1.5 padding - removed by NIST approved algorithms for key wrapping in FIPS 140-3               |
| CKM_RSA_PKCS_OAEP    | RSA key wrapping                     | NIST 800-56B rev. 2 | RSA OAEP with NIST approved hashing functions for RSA key size 2048, 3072 or 4096 bits.                         |
| CKM_RSA_AES_KEY_WRAP | RSA-AES hybrid key wrapping          | NIST SP 800-38F     | RSA OAEP with NIST approved hashing functions and AES-KWP for RSA key size 2048, 3072 or 4096 bits.             |
| Salsa Sealed Box     | X25519, Ed25519 and Salsa20 Poly1305 | No                  | ECIES compatible with libsodium [Sealed Boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes). |
| ECIES                | P-192, P-224, P-256, P-384, P-521    | No                  | ECIES with a NIST curve and using SHAKE 128 and AES 128 GCM (P-192, P-224, P-256) AES 256 GCM otherwise.        |

Any encryption scheme below can be used for key-wrapping as well.

## Encryption schemes

Encryption is supported via the `Encrypt` and `Decrypt` kmip operations.
For bulk operations (i.e. encrypting/decrypting multiple data with the same key),
please refer to [KMIP Messages](kmip_2_1/messages.md) that allow combining multiple operations in a
single request.

Encryption can be performed using a key or a certificate. Decryption can be performed using a key.

The supported encryption algorithms are:

| Algorithm         | Encryption Key Type                                     | FIPS mode           | Description                                                                                                              |
|-------------------|---------------------------------------------------------|---------------------|--------------------------------------------------------------------------------------------------------------------------|
| Covercrypt        | Covercrypt                                              | No                  | A fast post-quantum attribute based scheme: [Covercrypt](https://github.com/Cosmian/cover_crypt).                        |
| AES GCM           | Symmetric authenticated encryption with additional data | NIST FIPS 197       | The NIST standardized symmetric encryption in [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). |
| AES XTS           | Symmetric, not authenticated                            | NIST SP 800-38E     | Used in disk encryption. Requires 2 keys (e.g. a dopuble-sixed key)                                                      |
| AES GCM-SIV       | Symmetric, authenticated, synthetic IV                  | No                  | Used for deterministic encryption and encryption of very large data sets.                                                |
| ChaCha20-Poly1305 | Symmetric authenticated encryption with additional data | No                  | A popular symmetric encryption algorithm standardised in [RFC-8439](https://www.rfc-editor.org/rfc/rfc8439)              |
| CKM_RSA_PKCS      | RSA PKCS#1 v1.5                                         | Not anymore         | RSA WITH PKCS#1 v1.5 padding - removed by NIST approved algorithms for encryption in FIPS 140-3                          |
| CKM_RSA_PKCS_OAEP | RSA encryption with OAEP paddding                       | NIST 800-56B rev. 2 | RSA OAEP with NIST approved hashing functions for RSA key size 2048, 3072 or 4096 bits.                                  |
| Salsa Sealed Box  | X25519, Ed25519 and Salsa20 Poly1305                    | No                  | ECIES compatible with libsodium [Sealed Boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).          |
| ECIES             | P-192, P-224, P-256, P-384, P-521                       | No                  | ECIES with a NIST curve and using SHAKE 128 and AES-128-GCM.                                                             |

## Algorithms Details

### Covercrypt

[Covercrypt](https://github.com/Cosmian/cover_crypt) is a new post-quantum cryptographic algorithm,
being standardized at [ETSI](https://www.etsi.org/) that allows creating ciphertexts for a set of
attributes and issuing user keys with access policies over these attributes. User keys are traceable
with a unique fingerprint.

### AES GCM

AES is described in  [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf). In
Cosmian KMS it is used as a data encryption mechanism (DEM) with the Galois Counter Mode of
operation ([GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)) with a 96 bits nonce, a 128 bits tag
with and key sizes of 128 or 256 bits.

### ChaCha20-Poly1305

ChaCha20-Poly1305 is a symmetric authenticated encryption algorithm that is described
in [RFC-8439](https://www.rfc-editor.org/rfc/rfc8439). The algorithm is not standardized by NIST but
is a popular secure alternative to AES-GCM and is used in the same way, in particular by Google.

### AES-KWP

Allows to symmetrically wrap keys using [RFC5649](https://tools.ietf.org/html/rfc5649) which is also
standardized as PKCS#11 CKM_AES_KEY_WRAP_PAD and described
in [NIST SP 800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf).

### CKM_RSA_PKCS

A.k.a PKCS #1 v1.5 RSA as specified in
[PKCS#11 v2.40](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061135).

The algorithm is not recommended by NIST for encryption or key wrapping in FIPS 140-3. It is still
supported for signature operations.

The maximum plaintext length is `k-11` where `k` is the length in octets of the RSA modulus
The output length is the same as the modulus length.

### CKM_RSA_PKCS_OAEP

A.k.a PKCS #1 RSA OAEP as specified
in [PKCS#11 v2.40](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226895).
This scheme is part of
the [NIST 800-56B rev. 2 recommendation](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf)
available at section 7.2.2.

The maximum plaintext length is `k-2-2*hLen` where

- `k` is the length in octets of the RSA modulus
- `hLen` is the length in octets of the hash function output

The output length is the same as the modulus length.

The default hash function is SHA-256 but any NIST approved hash functions can be used for the OAEP
scheme as
listed in

- [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf): SHA-1, SHA-224,
  SHA-256, SHA-384,
  SHA-512
- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): SHA3-224, SHA3-256,
  SHA3-384,
  SHA3-512

Set the corresponding name of the hash function in the `Cryptographic Parameters` when performing a
KMIP operation.

To request this algorithm using the KMIP `Encrypt/Decrypt` operation, or key-wrapping as part of
the `Import/Export`
operations, specify the id/tags of an RSA key and set the `Cryptographic Algorithm` to `RSA`.

### CKM_RSA_AES_KEY_WRAP

A PKCS#11 key wrapping mechanism that is supported by most HSMs.

The scheme asymmetrically wrap keys as
described [here](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908)
and allows wrapping keys of any size using using a hybrid RSA/AES scheme.

Since old similar wrapping methods based on RSA used naive RSA encryption and could present some
flaws, it aims at a generally more secure method to wrap keys:

- Receive data of the form `c|wk` where `|` is the concatenation operator.
  Distinguish `c` and `wk`, respectively the encrypted `kek` and the wrapped key. First decrypt the
  key-encryption-key `kek` using RSA-OAEP, then proceed to unwrap the key by
  decrypting `m = dec(wk, kek)` using AES-KWP as specified
  in [RFC5649](https://tools.ietf.org/html/rfc5649).

The algorithm can be used with any NIST approved hash function described above; set the
corresponding value in the `Cryptographic Parameters` when performing a KMIP operation.

To request this algorithm using key-wrapping as part of the `Import/Export` operations, specify the
id of an RSA key as the key wrapping key and set the `Cryptographic Algorithm` to `AES`.

This algorithm is compatible with the one used in Google KMS.

### RSA OAEP AES 128 GCM

CKM_RSA_AES_KEY_WRAP can only be used for key wrapping and not for encryption. This scheme adds
authentication by using AES 128 in Galois Counter Mode (GCM). Combined with RSA OAEP to encapsulate
the AES key, this scheme is compatible
with [NIST SP 800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf).

To request this algorithm using the KMIP `Encrypt/Decrypt` operation, specify the id/tags of an RSA
key and set the `Cryptographic Algorithm` to `AES`.

### Salsa sealed box

An ECIES scheme that uses X25519 and XSalsa20-Poly1305 and is compatible with
libsodium [Sealed Boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).

An Ed25519 key can be used; it will be automatically converted to X25519 first.

### Ecies with NIST Curves

Although there is no specific FIPS standard for hybrid encryption, the ECIES encryption scheme is
based on FIPS compliant cryptographic primitives only and uses the same algorithm as the Salsa
Sealed Boxes. It supports the entire family of NIST P curves, with the exception of `P-192` in FIPS
mode, and uses AES-128-GCM and SHAKE128 for curves with security strength $s \leq 128$ bits:

- `P-192`
- `P-224`
- `P-256`

and AES-256-GCM and SHAKE256 for curves with security strength $s > 128$ bits:

- `P-384`
- `P-512`

## Signature

Signature is only supported via the `Certify` operation, which is used to create a certificate
either by signing a certificate request, or building it from an existing public key.

| Algorithm | Signature Key Type                                    | FIPS mode                                               | Description                                                                                                               |
|-----------|-------------------------------------------------------|---------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| ECDSA     | P-192, P-224, P-256, P-384, P384, P-521, X25519, X448 | **Restricted** to curves P-224, P-256, P-384 and P-521. | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) and NIST.SP.800-186 - Section 3.1.2 table 2. |
| EdDSA     | Ed25519, Ed448                                        | Yes                                                     | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf).                                             |

- `ECDSA` performs digital signatures on elliptic
  curves `P-192`, `P-224`, `P-256`, `P-384`, `P-512`, `X25519` and `X448`.
- `EdDSA` performs digital signatures on Edwards curves `Ed25519` and `Ed448`.

## Password-based key derivation

The randomness of cryptographic keys is essential for the security of cryptographic applications.
Sometimes, passwords may be the only input required from the users who are eligible to access the
data. Due to the low entropy and possibly poor randomness of those passwords, they are not suitable
to be used directly as cryptographic keys. The KMS addresses this problem by providing methods to
derive a password into a secure cryptographic key.

In normal mode, passwords are derived using `Argon2` hash algorithm with a random 128-bit salt.
Argon2 has the property of being computationally intensive making it significantly harder to crack
by brute force only.

In FIPS mode, passwords are derived using FIPS compliant `PBKDF2_HMAC` with `SHA512` and recommended
210,000 iterations
by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)
which follows FIPS recommendations as well. An additional random 128-bit salt is used.

## References

- NIST.FIPS.140-3, Implementation Guidance for FIPS 140-3 and the Cryptographic Module Validation
  Program, *August 1,
  2023*
    - General information and pointers to other NIST documents concerning the FIPS standard.

- NIST.SP.800-186, Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve
  Domain Parameters, *February 2023*
    - Recommended curves for specific usage (ECDH, ECDSA, EdDSA, ...) and associated security
      strength. Describes each
      curves parameters in details.

- NIST.SP.800-38F, Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping,
  *December 2012*
    - Description of symmetric key wrapping using AES-KW and AES-KWP. Approving RFC 5649.

- NIST.FIPS.800-132, Recommendation for Password-Based Key Derivation, *December 2010*
    - Description of low-entropy data derivation into secure master key.

- NIST.SP.800-56Cr2, Recommendation for Key-Derivation Methods in Key-Establishment Schemes, *August
  2020*
    - Description of high-entropy data derivation into secure master key.

- NIST.SP.800-131Ar2, Transitioning the Use of Cryptographic Algorithms and Key Lengths, *March
  2019*
    - Key length specification for different domain parameters, algorithms and cryptographic
      schemes.

- NIST.SP.800-56Ar3, Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm
  Cryptography,
  *April 2018*
    - General information on discrete logarithm parameters.

- NIST.SP.800-56Br2, Recommendation for Pair-Wise Key Establishment Using Integer Factorization
  Cryptography, *March
  2019*
    - Information regarding RSA primitive specifications: key length, encryption, decryption and
      padding to use.

- NIST.FIPS.180-4, Secure Hash Standard (SHS), *August 2015*
    - Specification regarding SHA family of hash functions.

- NIST.FIPS.202, SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, *August
  2015*
    - Specification for SHA3.

- NIST.FIPS.186-5, Digital Signature Standard (DSS), *February 3, 2023*
    - Information on ECDSA, EdDSA and key generation.

- NIST.FIPS.800-135r1, Recommendation for Existing Application-Specific Key Derivation Functions,
  *December 2011*

- OpenSSL FIPS 140-2 Security Policy, *26 January 2023*
    - OpenSSL official documentation
