/// Size in bytes of an AES-CMAC tag (one AES block).
pub const AES_CMAC_TAG_SIZE: usize = 16;

/// Size in bytes of the IV of an AES-GMAC (`CK_GCM_PARAMS.ulIvLen`).
pub const AES_GMAC_IV_SIZE: usize = 12;

/// Size in bytes of an AES-GMAC authentication tag, which is the PKCS#11 signature.
pub const AES_GMAC_TAG_SIZE: usize = 16;

/// What a generated secret key may do besides encrypting: `CKA_SIGN` allows `CKM_AES_CMAC`
/// MACs, `CKA_VERIFY` allows verifying them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacUsage {
    /// `CKA_SIGN`: the key may generate MACs.
    pub generate: bool,
    /// `CKA_VERIFY`: the key may verify MACs.
    pub verify: bool,
}

/// MAC algorithm selected by a `CKM_AES_CMAC` / `CKM_AES_GMAC` mechanism, executed by the KMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    /// `CKM_AES_CMAC` (NIST SP 800-38B), through the KMIP `MAC` operation: the 16-byte tag.
    AesCmac,
    /// `CKM_AES_GMAC` (PKCS#11 v3.0 §2.13.4, NIST SP 800-38D) with the caller's IV, as in
    /// PKCS#11: the signature is the 16-byte tag. The KMS computes it with the KMIP `MAC`
    /// operation, passing the IV in its `IVCounterNonce` field, so it runs as the OpenSSL
    /// provider's `GMAC` (the FIPS provider in a FIPS build).
    AesGmac {
        /// IV from `CK_GCM_PARAMS`; it must not repeat under one key.
        iv: [u8; AES_GMAC_IV_SIZE],
    },
}

impl MacAlgorithm {
    /// Length in bytes of the value produced by `C_Sign` (and expected by `C_Verify`).
    #[must_use]
    pub const fn mac_len(self) -> usize {
        match self {
            Self::AesCmac => AES_CMAC_TAG_SIZE,
            Self::AesGmac { .. } => AES_GMAC_TAG_SIZE,
        }
    }
}
