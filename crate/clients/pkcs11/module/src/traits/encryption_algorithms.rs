#[derive(Debug, Clone, Copy)]
pub enum EncryptionAlgorithm {
    // CKM_RSA_PKCS
    RsaPkcs1v15,
    AesCbcPad,
    AesCbc,
}
