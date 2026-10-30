//! Copyright 2024 Cosmian Tech SAS
//!
//! Thales Luna HSM PKCS#11 loader and provider implementation.
//!
//! This crate provides integration with the Thales Luna SA Network HSM via PKCS#11.
//! Luna is a full-featured hardware security module supporting symmetric, asymmetric,
//! and lattice-based cryptographic operations on dedicated secure hardware.
//!
//! # Configuration
//!
//! Luna requires:
//! - Thales Luna Client v10.9.x installed at `/usr/safenet/lunaclient/`
//! - Network connectivity to Luna HSM appliance (default port 5656)
//! - NTLS client certificates configured in `Chrystoki.conf`
//! - Partition PIN configured for the assigned slot
//!
//! # Library Path
//!
//! The PKCS#11 library path is configurable via the `LUNA_PKCS11_LIB` environment variable.
//! If not set, defaults to the standard Luna client installation path.
//!
//! # Example
//!
//! ```text
//! # In KMS config.toml:
//! [hsm]
//! hsm_model = "luna"
//! hsm_slot = [5]
//! hsm_password = ["partition_pin"]
//! ```

use cosmian_kms_base_hsm::hsm_capabilities::{
    AesCapabilities, AesGcmCapabilities, EcCapabilities, HsmCapabilities, HsmProvider,
    RsaCapabilities,
};

/// Path to the Thales Luna PKCS#11 shared library.
/// Overridable at runtime via the `LUNA_PKCS11_LIB` environment variable.
///
/// On Linux `x86_64`, Luna Client installs `libCryptoki2_64.so` at:
/// `/usr/safenet/lunaclient/lib/libCryptoki2_64.so`
///
/// This is the only officially supported platform for Cosmian KMS integration.
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
pub const LUNA_PKCS11_LIB: &str = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so";

/// Library name resolved through the dynamic loader search path on platforms other than
/// Linux `x86_64` (unsupported for production; overridable via `LUNA_PKCS11_LIB`).
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub const LUNA_PKCS11_LIB: &str = "libCryptoki2_64.so";

#[cfg(test)]
#[cfg(feature = "luna")]
mod tests;

/// Capability provider for Thales Luna HSM.
///
/// Luna supports large cryptographic operations and extensive object enumeration,
/// so we configure higher `find_max_object_count` than smaller HSMs like `SoftHSM2`.
pub struct LunaCapabilityProvider;

impl HsmProvider for LunaCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities {
            find_max_object_count: 256,
            // Luna rejects an explicit CKA_SENSITIVE=false with CKR_ATTRIBUTE_VALUE_INVALID;
            // omit CKA_SENSITIVE and let CKA_EXTRACTABLE drive exportability.
            aes: AesCapabilities {
                supports_sensitive_attribute: false,
                key_wrap_pad_is_rfc5649: false,
                gcm: AesGcmCapabilities {
                    allows_caller_iv_in_fips: false,
                    // Luna exports the PKCS#11 3.0 message API but C_MessageEncryptInit fails
                    // for AES-GCM.
                    supports_message: false,
                    ..AesGcmCapabilities::default()
                },
            },
            rsa: RsaCapabilities {
                supports_sensitive_attribute: false,
                ..RsaCapabilities::default()
            },
            ec: EcCapabilities {
                supports_sensitive_attribute: false,
                ..EcCapabilities::default()
            },
            ..Default::default()
        }
    }
}

/// Thales Luna HSM backend type.
///
/// Luna is fully supported by the `BaseHsm<T>` generic implementation.
/// All cryptographic operations (symmetric, asymmetric, lattice-based) are
/// delegated to the Luna PKCS#11 library and hardware.
///
/// # Features
/// - FIPS 140-3 Level 3 certified
/// - Network HSM (remote hardware via NTLS)
/// - AES, RSA, EC, ML-KEM, ML-DSA, SLH-DSA support
/// - Multi-user access control via partition PINs
/// - Redundant HSM failover (primary + secondary appliance)
/// - Real-time cryptoki operation logging
pub type Luna = cosmian_kms_base_hsm::BaseHsm<LunaCapabilityProvider>;

#[cfg(test)]
#[cfg(feature = "luna")]
mod luna_integration_tests {
    use super::*;

    /// Test that Luna PKCS#11 library path is correctly defined
    #[test]
    fn test_luna_library_path_defined() {
        assert!(
            !LUNA_PKCS11_LIB.is_empty(),
            "Luna library path must be defined"
        );
        assert!(
            LUNA_PKCS11_LIB.contains("Cryptoki"),
            "Path should reference Cryptoki library"
        );
    }

    /// Test that Luna capability provider is correctly configured
    #[test]
    fn test_luna_capabilities() {
        let caps = LunaCapabilityProvider::capabilities();
        assert_eq!(
            caps.find_max_object_count, 256,
            "Luna should support 256 object enumeration"
        );
        assert_eq!(
            caps.max_cbc_data_size, None,
            "Luna should not impose CBC data size limits"
        );
    }
}
