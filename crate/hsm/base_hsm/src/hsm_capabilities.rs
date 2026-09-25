use pkcs11_sys::CK_ULONG;

#[derive(Debug, Clone)]
/// HSM capability flags for vendor-specific PKCS#11 behavior.
/// Multiple bool fields reflect real `CloudHSM` limitations requiring per-operation gating.
#[allow(clippy::struct_excessive_bools)]
pub struct HsmCapabilities {
    /// Maximum data size before switching to AES CBC multi-round operations (in bytes)
    /// If `None`, there is no enforced limit.
    pub max_cbc_data_size: Option<usize>,

    /// Maximum number of objects that can be returned by a single `FindObjects` operation
    /// (also known as `ulMaxObjectCount` in PKCS#11).
    pub find_max_object_count: CK_ULONG,

    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_SENSITIVE` attribute.
    /// AWS `CloudHSM` rejects any explicit value (true or false) for this attribute with
    /// `CKR_ATTRIBUTE_VALUE_INVALID`; its own PKCS#11 default already yields a
    /// non-extractable key, so `CKA_EXTRACTABLE` alone is sent instead when `false`.
    pub supports_aes_sensitive_attribute: bool,

    /// Whether `C_GenerateKeyPair` for RSA accepts an explicit `CKA_SENSITIVE` attribute.
    /// AWS `CloudHSM` rejects any explicit `CKA_SENSITIVE=false` value with
    /// `CKR_ATTRIBUTE_VALUE_INVALID`; its keys are inherently sensitive.
    pub supports_rsa_sensitive_attribute: bool,

    /// Whether `C_GenerateKeyPair` for EC accepts an explicit `CKA_SENSITIVE` attribute.
    /// AWS `CloudHSM` rejects any explicit `CKA_SENSITIVE=false` value with
    /// `CKR_ATTRIBUTE_VALUE_INVALID`; its keys are inherently sensitive.
    pub supports_ec_sensitive_attribute: bool,

    /// Whether `C_EncryptInit` for AES-GCM accepts a caller-provided IV.
    /// AWS `CloudHSM` rejects any non-zero IV for GCM with error 0x71 ("Iv invalid").
    /// When false, encryption proceeds without caller IV (HSM generates internally).
    pub supports_aes_gcm_caller_iv: bool,

    /// Maximum length allowed for `CKA_LABEL` on HSM objects.
    /// If `None`, there is no enforced limit.
    pub max_label_len: Option<usize>,
}

impl Default for HsmCapabilities {
    fn default() -> Self {
        Self {
            max_cbc_data_size: None,
            find_max_object_count: 1,
            supports_aes_sensitive_attribute: true,
            supports_rsa_sensitive_attribute: true,
            supports_ec_sensitive_attribute: true,
            supports_aes_gcm_caller_iv: true,
            max_label_len: None,
        }
    }
}

pub trait HsmProvider: Send + Sync + 'static {
    fn capabilities() -> HsmCapabilities;
}
