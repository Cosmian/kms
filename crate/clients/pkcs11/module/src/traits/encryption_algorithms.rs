#[derive(Debug, Clone, Copy)]
pub enum EncryptionAlgorithm {
    // CKM_RSA_PKCS
    RsaPkcs1v15,
    // CKM_RSA_PKCS_OAEP (SHA-256 / MGF1-SHA256), matching the KMS server's own OAEP
    // parameter choice (`HsmEncryptionAlgorithm::RsaOaepSha256` in `crate/hsm/base_hsm`).
    RsaOaepSha256,
    AesCbcPad,
    AesCbc,
    // CKM_AES_GCM (PKCS#11 v3.0)
    AesGcm,
}
