impl TryFrom<HashingAlgorithm> for &'static MdRef {
    type Error = KmipError;

    fn try_from(hashing_algorithm: HashingAlgorithm) -> Result<Self, Self::Error> {
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
            h => Err(kmip_error!(
                "Unsupported hash function: {h:?} for the openssl provider"
            )),
        }
    }
}

impl TryFrom<HashingAlgorithm> for MessageDigest {
    type Error = KmipError;

    fn try_from(hashing_algorithm: HashingAlgorithm) -> Result<Self, Self::Error> {
        match hashing_algorithm {
            HashingAlgorithm::SHA1 => Ok(Self::sha1()),
            HashingAlgorithm::SHA224 => Ok(Self::sha224()),
            HashingAlgorithm::SHA256 => Ok(Self::sha256()),
            HashingAlgorithm::SHA384 => Ok(Self::sha384()),
            HashingAlgorithm::SHA512 => Ok(Self::sha512()),
            HashingAlgorithm::SHA3224 => Ok(Self::sha3_224()),
            HashingAlgorithm::SHA3256 => Ok(Self::sha3_256()),
            HashingAlgorithm::SHA3384 => Ok(Self::sha3_384()),
            HashingAlgorithm::SHA3512 => Ok(Self::sha3_512()),
            h => Err(kmip_error!(
                "Unsupported hash function: {h:?} for the openssl Message Digest provider"
            )),
        }
    }
}
