use cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
use openssl::{
    hash::MessageDigest,
    md::{Md, MdRef},
    nid::Nid,
    pkey::{HasPublic, Id, PKeyRef},
};

use crate::{CryptoError, crypto_error};

pub fn hashing_algorithm_to_openssl(
    hashing_algorithm: HashingAlgorithm,
) -> Result<MessageDigest, CryptoError> {
    match hashing_algorithm {
        HashingAlgorithm::SHA1 => Ok(MessageDigest::sha1()),
        HashingAlgorithm::SHA224 => Ok(MessageDigest::sha224()),
        HashingAlgorithm::SHA256 => Ok(MessageDigest::sha256()),
        HashingAlgorithm::SHA384 => Ok(MessageDigest::sha384()),
        HashingAlgorithm::SHA512 => Ok(MessageDigest::sha512()),
        HashingAlgorithm::SHA3224 => Ok(MessageDigest::sha3_224()),
        HashingAlgorithm::SHA3256 => Ok(MessageDigest::sha3_256()),
        HashingAlgorithm::SHA3384 => Ok(MessageDigest::sha3_384()),
        HashingAlgorithm::SHA3512 => Ok(MessageDigest::sha3_512()),
        h => Err(crypto_error!(
            "Unsupported hash function: {h:?} for the openssl Message Digest provider"
        )),
    }
}

pub fn hashing_algorithm_to_openssl_ref(
    hashing_algorithm: HashingAlgorithm,
) -> Result<&'static MdRef, CryptoError> {
    match hashing_algorithm {
        HashingAlgorithm::SHA1 => Ok(Md::sha1()),
        HashingAlgorithm::SHA224 => Ok(Md::sha224()),
        HashingAlgorithm::SHA256 => Ok(Md::sha256()),
        HashingAlgorithm::SHA384 => Ok(Md::sha384()),
        HashingAlgorithm::SHA512 => Ok(Md::sha512()),
        HashingAlgorithm::SHA3224 => Ok(Md::sha3_224()),
        HashingAlgorithm::SHA3256 => Ok(Md::sha3_256()),
        HashingAlgorithm::SHA3384 => Ok(Md::sha3_384()),
        HashingAlgorithm::SHA3512 => Ok(Md::sha3_512()),
        h => Err(crypto_error!(
            "Unsupported hash function: {h:?} for the openssl provider"
        )),
    }
}

/// Digest for an X.509 signature (certificate, CRL, CSR, OCSP response) made with `key`.
///
/// RSA: SHA-256. ECDSA: the digest matching the curve strength (RFC 5480 §4): SHA-384 for
/// P-384, SHA-512 for P-521, SHA-256 otherwise. Null for algorithms that hash internally
/// (`EdDSA`, ML-DSA, SLH-DSA).
#[must_use]
pub fn x509_signing_digest<T: HasPublic>(key: &PKeyRef<T>) -> MessageDigest {
    match key.id() {
        Id::RSA => MessageDigest::sha256(),
        Id::EC => match key.ec_key().ok().and_then(|ec| ec.group().curve_name()) {
            Some(Nid::SECP384R1) => MessageDigest::sha384(),
            Some(Nid::SECP521R1) => MessageDigest::sha512(),
            _ => MessageDigest::sha256(),
        },
        _ => MessageDigest::null(),
    }
}
