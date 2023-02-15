The Cosmian Key Management System (KMS) is a high-performance server application written in [**Rust**](https://www.rust-lang.org/) that provides an API to store and manage keys and secrets used with Cosmian cryptographic stacks.

The server exposes a **KMIP 2.1** API that follows the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the OASIS-normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

The server is usually queried using one of the Java, Javascript, or Python **Cloudproof libraries**. Check the [Cloudproof documentation](https://docs.cosmian.com/cloudproof_encryption/application_level_encryption/) and the [Cosmian Github](https://github.com/Cosmian) for details.

<!-- The supported cryptographic schemes are listed below.

#### AES 256 GCM

Used as a building block for other cryptographic primitives below, AES 256 GCM is fully supported in the KMS.
Keys are set to 256 bits to provide ~128 bits quantum resistance and the scheme uses Galois Counter Mode to offer a fast authenticated encryption algorithm.

This implementation uses a 96 bits Nonce, a 128 bits MAC and is based on the AES native instruction when available in the CPU or uses the Rust AES software package otherwise. See the [aes-gcm](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm) Rust crate for details and Cosmian wrapper in [cosmian_crypto_core](https://github.com/Cosmian/crypto_core)

#### xChacha20 Poly1305

As an alternative symmetric cryptographic building block to AES GCM, the xChacha20 Poly1305 construction found in [libsodium](https://doc.libsodium.org/) is also available in the KMS.

#### Ristretto x25519

Base elliptic curve cryptography is provided using curve 25519 on the prime order Ristretto group.

The curve implementation is from the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) repository while the [cosmian_crypto_base](https://github.com/Cosmian/crypto_base) open source library provides an implementation of ECIES on the curve (Elliptic Curve Integrated Encryption Scheme).

#### Multi-user Encryption: CoverCrypt

The KMS encryption implementation is based on [CoverCrypt](https://github.com/Cosmian/cover_crypt) which is a multi‑user encryption solution which provides access rights to users with respect to
an access policy where the policy over attributes can be expressed as a union of users' rights. **CoverCrypt** has been proposed as a more efficient alternative to [Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data](https://eprint.iacr.org/2006/309.pdf) by vipul Goyal, Omkant Pandey, Amit Sahai, Brent Waters.

Please refer to the [Cosmian CoverCrypt documentation](https://github.com/Cosmian/cover_crypt/blob/develop/bib/CoverCrypt.pdf) for more details.

#### Format Preserving Encryption (FPE)

Format Preserving Encryption (FPE) is, as the name implies, used to keep the format of the encrypted data identical to that of the clear text data. Consider a credit card number of 16 digits; after encryption, the cipher text will still look like a 16 digit credit card number. FPE is particularly useful to add encryption in forms or databases where the data format cannot be changed.

Cosmian KMS exposes the [NIST recommended FF1 algorithm](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf). A [recent cryptanalysis paper](https://eprint.iacr.org/2020/1311) has exposed new attacks, and the Cosmian implementation of FF1 includes the increased umber of rounds of the Feistel recommended in the paper. Cosmian has open-sourced its implementation in [cosmian_crypto_base](https://github.com/Cosmian/crypto_base); check the `ff1.rs` files for details. -->
