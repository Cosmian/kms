use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, MaskGenerator, PaddingMethod},
    kmip_2_1::kmip_types::{CryptographicAlgorithm, DigitalSignatureAlgorithm, RecommendedCurve},
};

use crate::config::{AesKeySize, RsaKeySize};

/// Runtime KMIP policy parameters.
///
/// This groups all KMIP policy related config fields (formerly `ServerParams.kmip_*`).
#[derive(Debug, Clone, Default)]
pub struct KmipPolicyParams {
    /// KMIP algorithm policy selector.
    ///
    /// Normalized to uppercase and validated at startup.
    /// Accepted values: `DEFAULT`, `CUSTOM`.
    pub policy_id: String,

    /// Parameter-specific allowlists.
    ///
    /// When a list is `None`, no restriction is applied for that parameter.
    pub allowlists: KmipAllowlistsParams,
}

#[derive(Debug, Clone, Default)]
pub struct KmipAllowlistsParams {
    pub algorithms: Option<Vec<CryptographicAlgorithm>>,
    pub hashes: Option<Vec<HashingAlgorithm>>,
    pub signature_algorithms: Option<Vec<DigitalSignatureAlgorithm>>,
    pub curves: Option<Vec<RecommendedCurve>>,
    pub block_cipher_modes: Option<Vec<BlockCipherMode>>,
    pub padding_methods: Option<Vec<PaddingMethod>>,
    pub mgf_hashes: Option<Vec<HashingAlgorithm>>,
    pub mask_generators: Option<Vec<MaskGenerator>>,

    pub rsa_key_sizes: Option<Vec<RsaKeySize>>,
    pub aes_key_sizes: Option<Vec<AesKeySize>>,
}
