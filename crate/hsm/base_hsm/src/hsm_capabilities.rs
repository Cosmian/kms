use pkcs11_sys::CK_ULONG;

/// HSM capability flags for vendor-specific PKCS#11 behavior.
#[derive(Debug, Clone)]
pub struct HsmCapabilities {
    /// Maximum data size before switching to AES CBC multi-round operations (in bytes)
    /// If `None`, there is no enforced limit.
    pub max_cbc_data_size: Option<usize>,

    /// Maximum number of objects that can be returned by a single `FindObjects` operation
    /// (also known as `ulMaxObjectCount` in PKCS#11).
    pub find_max_object_count: CK_ULONG,

    /// AES-specific vendor behavior.
    pub aes: AesCapabilities,

    /// RSA-specific vendor behavior.
    pub rsa: RsaCapabilities,

    /// EC-specific vendor behavior.
    pub ec: EcCapabilities,

    /// Opt-in for the PKCS#11 v3.0 message-based signature API: when `true` and the loaded
    /// library exports the `C_MessageSign*`/`C_MessageVerify*` families, `Session::sign` and
    /// `Session::verify` try `C_MessageSignInit`/`C_MessageVerifyInit` first, keep the message
    /// context open on the session, and fall back to `C_SignInit`/`C_VerifyInit` for every
    /// mechanism the token rejects (`CKR_FUNCTION_NOT_SUPPORTED`, `CKR_MECHANISM_INVALID`,
    /// `CKR_MECHANISM_PARAM_INVALID`). The rejection is cached per slot and mechanism.
    pub supports_message_sign_verify: bool,

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

    /// Whether the provider crashes when the PKCS#11 library is finalized during drop.
    pub skip_finalize_on_drop: bool,
    /// Maximum number of PKCS#11 sessions this slot may have concurrently checked out
    /// (in-flight async HSM operations). Requests beyond this bound await asynchronously
    /// via a `tokio::sync::Semaphore` instead of opening unbounded additional sessions.
    /// Also bounds the idle-session pool size (a pool larger than the concurrency cap
    /// can never be filled).
    pub max_concurrent_sessions: usize,
}

impl Default for HsmCapabilities {
    fn default() -> Self {
        Self {
            max_cbc_data_size: None,
            find_max_object_count: 1,
            aes: AesCapabilities::default(),
            rsa: RsaCapabilities::default(),
            ec: EcCapabilities::default(),
            supports_message_sign_verify: false,
            max_label_len: None,
            supports_key_dates: true,
            skip_finalize_on_drop: false,
            max_concurrent_sessions: 128,
        }
    }
}

/// AES-specific HSM capability flags.
#[derive(Debug, Clone)]
pub struct AesCapabilities {
    /// Whether `C_GenerateKey` for AES accepts an explicit `CKA_SENSITIVE` attribute.
    /// AWS `CloudHSM` rejects any explicit value (true or false) for this attribute with
    /// `CKR_ATTRIBUTE_VALUE_INVALID`; when `false`, `CKA_EXTRACTABLE` alone is sent
    /// instead (`false` for sensitive keys).
    pub supports_sensitive_attribute: bool,

    /// Whether `CKM_AES_KEY_WRAP_PAD` (0x210A) implements RFC 5649 KWP. PKCS#11 v2.40 defines
    /// it as PKCS#7-padded KW, but `SoftHSM2` implements RFC 5649. `CKM_AES_KEY_WRAP_KWP`
    /// (v3.0) is always RFC 5649.
    pub key_wrap_pad_is_rfc5649: bool,

    /// AES-GCM vendor behavior.
    pub gcm: AesGcmCapabilities,
}

impl Default for AesCapabilities {
    fn default() -> Self {
        Self {
            supports_sensitive_attribute: true,
            key_wrap_pad_is_rfc5649: false,
            gcm: AesGcmCapabilities::default(),
        }
    }
}

/// AES-GCM-specific HSM capability flags.
#[derive(Debug, Clone)]
pub struct AesGcmCapabilities {
    /// Whether `C_EncryptInit` for AES-GCM accepts a caller-provided IV.
    /// AWS `CloudHSM` rejects any non-zero IV for GCM with error 0x71 ("Iv invalid").
    /// When false, encryption proceeds without caller IV (HSM generates internally).
    pub supports_caller_iv: bool,

    /// Whether a caller-chosen AES-GCM IV may still be sent in FIPS builds.
    /// Only for development tokens that are not FIPS-validated modules (`SoftHSM2`, Kryoptic).
    /// FIPS 140-3 IG C.H requires GCM encryption IVs to be generated inside the module.
    pub allows_caller_iv_in_fips: bool,

    /// Whether the HSM supports PKCS#11 v3.0 message-based AES-GCM encryption.
    pub supports_message: bool,
}

impl Default for AesGcmCapabilities {
    fn default() -> Self {
        Self {
            supports_caller_iv: true,
            allows_caller_iv_in_fips: false,
            supports_message: true,
        }
    }
}

/// RSA-specific HSM capability flags.
#[derive(Debug, Clone)]
pub struct RsaCapabilities {
    /// Whether `C_GenerateKeyPair` for RSA accepts an explicit `CKA_SENSITIVE` attribute.
    /// AWS `CloudHSM` rejects any explicit `CKA_SENSITIVE=false` value with
    /// `CKR_ATTRIBUTE_VALUE_INVALID`; its keys are inherently sensitive.
    pub supports_sensitive_attribute: bool,

    /// Whether RSA-OAEP `C_UnwrapKey` needs a non-null `pSourceData` pointer for an
    /// empty `CKZ_DATA_SPECIFIED` label. `SoftHSM2` rejects `NULL`, while AWS `CloudHSM`
    /// rejects anything but `NULL` (the PKCS#11 default for an empty label).
    pub oaep_requires_source_data_ptr: bool,

    /// Whether `CKM_RSA_PKCS_OAEP` `C_WrapKey`/`C_UnwrapKey` of AES keys works.
    /// `SoftHSM2` 2.6.1 returns `CKR_ARGUMENTS_BAD` from OAEP `C_WrapKey`; SmartCard-HSM
    /// does not support it.
    pub supports_oaep_key_wrap: bool,
}

impl Default for RsaCapabilities {
    fn default() -> Self {
        Self {
            supports_sensitive_attribute: true,
            oaep_requires_source_data_ptr: false,
            supports_oaep_key_wrap: true,
        }
    }
}

/// EC-specific HSM capability flags.
#[derive(Debug, Clone)]
pub struct EcCapabilities {
    /// Whether `C_GenerateKeyPair` for EC accepts an explicit `CKA_SENSITIVE` attribute.
    /// AWS `CloudHSM` rejects any explicit `CKA_SENSITIVE=false` value with
    /// `CKR_ATTRIBUTE_VALUE_INVALID`; its keys are inherently sensitive.
    pub supports_sensitive_attribute: bool,

    /// Whether the HSM refuses ECDSA signatures whose digest is weaker than the curve
    /// (P-384 with SHA-256; P-521 with SHA-256 or SHA-384). AWS `CloudHSM` enforces this.
    /// The shared test suite reads it to skip those combinations; production calls
    /// surface the HSM's own error.
    pub enforces_ecdsa_digest_strength: bool,
}

impl Default for EcCapabilities {
    fn default() -> Self {
        Self {
            supports_sensitive_attribute: true,
            enforces_ecdsa_digest_strength: false,
        }
    }
}

pub trait HsmProvider: Send + Sync + 'static {
    fn capabilities() -> HsmCapabilities;
}
