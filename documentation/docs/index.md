
This document is the main documentation of the Cosmian Key Management System.

## Introduction

The Cosmian Key Management System (KMS) is a high performance server application written in [Rust](https://www.rust-lang.org/) which provides a REST API to store and manage keys and secrets used with Cosmian cryptographic stacks.

The Cosmian KMS server is offered on-premise (see [deployment](./deployment.md)) or as SaaS (create a free account on [console.cosmian.com ](https://console.cosmian.com)).

The server is usually used in called using the [Cosmian Java Library](https://github.com/Cosmian/cosmian_java_lib)

## KMIP 2.1 Support

The REST API follows the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the OASIS normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html). Only a limited set of operations of the KMIP 2.1 specification, described below, is supported but which is sufficient to exercise Cosmian cryptographic stacks.

This KMS completes classic offering of KMS servers on the market which are usually unable to natively support advanced cryptography. Do not hesitate to contact the Cosmian team if you wish to see additional cryptographic objects supported inside the Cosmian KMS.

## Advanced Cryptography

The Cosmian KMS server's primary goal is to provide support for storing, managing and performing cryptographic operations on the advanced cryptographic objects used by Cosmian, such as Attribute Based Encryption keys. Some of these cryptographic stacks, such as Searchable Encryption are built on top of classic symmetric primitives such as AES which are also available through the API of this KMS.

The supported cryptographic schemes are listed below.


#### AES 256 GCM

Used as a building block for other cryptographic primitives below, AES 256 GCM is fully supported in the KMS.
Keys are set to 256 bits to provide ~128 bits quantum resistance and the scheme uses Galois Counter Mode to offer a fast authenticated encryption algorithm. 

This implementation uses a 96 bits Nonce, a 128 bits MAC and is based on the AES native interface when available in the CPU or uses the Rust AES software package otherwise. See the [aes-gcm](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm) Rust crate for details and Cosmian wrapper in [cosmian_crypto_base](https://github.com/Cosmian/crypto_base)


#### xChacha20 Poly1305

As an alternative symmetric cryptographic building block to AES GCM, the xChacha20 Poly1305 construction found in [libsodium](https://doc.libsodium.org/) is also available in the KMS.


#### Ristretto x25519

Base elliptic curve cryptography is provided using curve 25519 on the prime order Ristretto group. 

The curve implementation is from the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) repository while the [cosmian_crypto_base](https://github.com/Cosmian/crypto_base) open source library provides an implementation of ECIES on the curve (Elliptic Curve Integrated Encryption Scheme).

#### Attribute Based Encryption (ABE)

The goal of Attribute Based Encryption is to embed access policies in cipher texts and user decryption keys to strongly control access to data without the use of a centralized authorization system.

The KMS supports a Key Policy Attributes Based Encryption known as GPSW06 based on the paper [Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data ](https://eprint.iacr.org/2006/309.pdf) by vipul Goyal, Omkant Pandey, Amit Sahai, Brent Waters. The implementation uses the BLS12-381 elliptic curve.

Please refer to this (Cosmian abe_gpsw repository)[https://github.com/Cosmian/abe_gpsw] for details on GPSW and BLS12-381.


#### Decentralized Multi-Client Functional Encryption (DMCFE)

DMCFE is used to apply linear functions to data encrypted by multiple data providers under their own key. The result consumer owns a functional key, which gives it with the ability to apply the embedded function to the encrypted data and decrypt the result.

The implementation is based on the paper [Implementation of a Decentralized Multi-Client Inner-Product Functional Encryption in the Random-Oracle Model](https://eprint.iacr.org/2020/788.pdf) by Michel Abdalla, Florian Bourse, Hugo Marival, David Pointcheval, Azam Soleimanian, and Hendrik Waldner. This implementation uses Learning With Errors (LWE) as a cryptographic scheme, a quantum resistant encryption scheme.


#### Format Preserving Encryption (FPE)

Format Preserving Encryption (FPE) is, as the name implies, used to keep the format of the encrypted data identical to that of the clear text data. Consider a credit card number of 16 digits; after encryption, the cipher text will still look like a 16 digit credit card number. FPE is particularly useful to add encryption in forms or databases where the data format cannot be changed.

Cosmian KMS exposes the [NIST recommended FF1 algorithm](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf). A [recent cryptanalysis paper](https://eprint.iacr.org/2020/1311) has exposed new attacks, and the Cosmian implementation of FF1 includes the increased umber of rounds of the Feistel recommended in the paper. Cosmian has open-sourced its implementation in [cosmian_crypto_base](https://github.com/Cosmian/crypto_base); check the `ff1.rs` files for details.


#### Torus Fully Homomorphic Encryption (TFHE)

Cosmian KMS also exposes cryptographic routines, key generation, encryption and decryption using Learning with Errors which are appropriate to use with TFHE. [LWE](https://en.wikipedia.org/wiki/Learning_with_errors) is used in cryptography to build a quantum resistant encryption scheme. [TFHE](https://eprint.iacr.org/2018/421) is a variant of fully homomorphic encryption over the torus, that is appropriate to perform secure computations on boolean circuits.

Please note that encryption with LWE for TFHE may result in very large cipher texts and lead to KMS performance issues.
