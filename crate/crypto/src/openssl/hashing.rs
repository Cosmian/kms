use cosmian_kmip::kmip_2_1::kmip_types::HashingAlgorithm;
use openssl::{
    hash::MessageDigest,
    md::{Md, MdRef},
};

use crate::{crypto_error, CryptoError};

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
