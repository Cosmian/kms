#[derive(Debug, Clone, Copy)]
pub enum EncryptionAlgorithm {
    // CKM_RSA_PKCS
    RsaPkcs1v15,
    AesCbcPad,
    AesCbc,
    // CKM_AES_GCM (PKCS#11 v3.0)
    AesGcm,
}
