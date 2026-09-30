use pkcs11_sys::{CK_ATTRIBUTE_TYPE, CK_ULONG};

#[derive(Debug, Clone)]
/// HSM capability flags for vendor-specific PKCS#11 behavior.
/// Multiple bool fields reflect real vendor PKCS#11 limitations requiring per-operation gating.
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

    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_CLASS` attribute.
    pub supports_aes_class_attribute: bool,

    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_KEY_TYPE` attribute.
    pub supports_aes_key_type_attribute: bool,

    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_VALUE_LEN` attribute.
    pub supports_aes_value_len_attribute: bool,

    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_TOKEN` attribute.
    pub supports_aes_token_attribute: bool,

    /// Whether `C_GenerateKey` for AES accepts explicit usage/private attributes.
    pub supports_aes_usage_attributes: bool,

    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_LABEL` attribute.
    pub supports_aes_label_attribute: bool,

    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_ID` attribute.
    pub supports_aes_id_attribute: bool,

    /// Vendor-specific AES algorithm attribute `(type, value)` for key generation.
    pub aes_algorithm_attribute: Option<(CK_ATTRIBUTE_TYPE, CK_ULONG)>,

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

    /// PKCS#11 mechanism used for AES-GCM encryption and decryption.
    pub aes_gcm_mechanism: CK_ULONG,

    /// Whether the HSM supports PKCS#11 v3.0 message-based AES-GCM encryption.
    pub supports_aes_gcm_message: bool,

    /// Whether RSA-OAEP `C_UnwrapKey` needs a non-null `pSourceData` pointer for an
    /// empty `CKZ_DATA_SPECIFIED` label. `SoftHSM2` rejects `NULL`, while AWS `CloudHSM`
    /// rejects anything but `NULL` (the PKCS#11 default for an empty label).
    pub rsa_oaep_requires_source_data_ptr: bool,

    /// Maximum length allowed for `CKA_LABEL` on HSM objects.
    /// If `None`, there is no enforced limit.
    pub max_label_len: Option<usize>,

    /// Whether `CKA_START_DATE`/`CKA_END_DATE` can be read and written on key objects.
    /// Crypt2pay and AWS `CloudHSM` return `CKR_ATTRIBUTE_TYPE_INVALID` for these attributes;
    /// `SoftHSM2` accepts the write on private objects but then fails every read of them
    /// with `CKR_GENERAL_ERROR`.
    /// When `false`, reads report no dates and writes are refused, so HSM key
    /// auto-rotation scheduling is unavailable.
    pub supports_key_dates: bool,

    /// Whether `CKM_RSA_PKCS_OAEP` `C_WrapKey`/`C_UnwrapKey` of AES keys works.
    /// `SoftHSM2` 2.6.1 returns `CKR_ARGUMENTS_BAD` from OAEP `C_WrapKey`; SmartCard-HSM
    /// does not support it.
    pub supports_rsa_oaep_key_wrap: bool,

    /// Whether the HSM refuses ECDSA signatures whose digest is weaker than the curve
    /// (P-384 with SHA-256; P-521 with SHA-256 or SHA-384). AWS `CloudHSM` enforces this.
    /// The shared test suite reads it to skip those combinations; production calls
    /// surface the HSM's own error.
    pub enforces_ecdsa_digest_strength: bool,
}

impl Default for HsmCapabilities {
    fn default() -> Self {
        Self {
            max_cbc_data_size: None,
            find_max_object_count: 1,
            supports_aes_sensitive_attribute: true,
            supports_aes_class_attribute: true,
            supports_aes_key_type_attribute: true,
            supports_aes_value_len_attribute: true,
            supports_aes_token_attribute: true,
            supports_aes_usage_attributes: true,
            supports_aes_label_attribute: true,
            supports_aes_id_attribute: true,
            aes_algorithm_attribute: None,
            supports_rsa_sensitive_attribute: true,
            supports_ec_sensitive_attribute: true,
            supports_aes_gcm_caller_iv: true,
            aes_gcm_mechanism: pkcs11_sys::CKM_AES_GCM,
            supports_aes_gcm_message: true,
            rsa_oaep_requires_source_data_ptr: false,
            max_label_len: None,
            supports_key_dates: true,
            supports_rsa_oaep_key_wrap: true,
            enforces_ecdsa_digest_strength: false,
        }
    }
}

pub trait HsmProvider: Send + Sync + 'static {
    fn capabilities() -> HsmCapabilities;
}
