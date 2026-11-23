//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

/// Path to the Idemia SPHERE `PKCS#11` shared library.
/// Overridable at runtime via the `IDEMIA_SPHERE_PKCS11_LIB` environment variable.
///
/// On Windows, defaults to the Idemia HSM Simulator DLL.
#[cfg(target_os = "windows")]
pub const IDEMIA_SPHERE_PKCS11_LIB: &str = r"C:\Idemia_HSM_Simulator\librooky-simulator.dll";

/// Path to the Idemia SPHERE `PKCS#11` shared library.
/// Overridable at runtime via the `IDEMIA_SPHERE_PKCS11_LIB` environment variable.
///
/// There is no built-in default outside Windows: `IDEMIA_SPHERE_PKCS11_LIB` must be set.
#[cfg(not(target_os = "windows"))]
pub const IDEMIA_SPHERE_PKCS11_LIB: &str = "";

#[cfg(test)]
#[cfg(feature = "idemia_sphere")]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests;

/// Capability profile of the Idemia SPHERE HSM.
///
/// The Idemia HSM Simulator in `NON_FIPS` mode forwards every call to `SoftHSM2`, hence the
/// `SoftHSM2` profile.
pub struct IdemiaSphereCapabilityProvider;

impl HsmProvider for IdemiaSphereCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            max_cbc_data_size: None,
            find_max_object_count: 32,
            aes: AesCapabilities {
                supports_sensitive_attribute: true,
                key_wrap_pad_is_rfc5649: true,
                gcm: AesGcmCapabilities {
                    supports_caller_iv: true,
                    supports_message: false,
                },
            },
            rsa: RsaCapabilities {
                supports_sensitive_attribute: true,
                oaep_requires_source_data_ptr: true,
                supports_oaep_key_wrap: false,
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: true,
                enforces_ecdsa_digest_strength: false,
            },
            supports_message_sign_verify: false,
            max_label_len: None,
            supports_key_dates: false,
            skip_finalize_on_drop: false,
            max_concurrent_sessions: 128,
        }
    }
}

/// The Idemia SPHERE HSM is fully supported by the `BaseHsm` implementation
pub type IdemiaSphere = cosmian_kms_base_hsm::BaseHsm<IdemiaSphereCapabilityProvider>;
