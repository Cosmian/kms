use crate::traits::DigestType;

#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    Ecdsa,
    RsaRaw,
    RsaPkcs1v15Raw,
    RsaPkcs1v15Sha1,
    RsaPkcs1v15Sha384,
    RsaPkcs1v15Sha256,
    RsaPkcs1v15Sha512,
    RsaPss {
        digest: DigestType,
        mask_generation_function: DigestType,
        salt_length: u64,
    },
}
