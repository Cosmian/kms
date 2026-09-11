use std::ptr;

use cosmian_kms_interfaces::EcCurve;
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CKA_DERIVE, CKA_EC_PARAMS,
    CKA_EXTRACTABLE, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN,
    CKA_TOKEN, CKA_VERIFY, CKK_EC, CKM_EC_KEY_PAIR_GEN,
};
#[cfg(feature = "non-fips")]
use pkcs11_sys::{
    CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
};

use crate::{HError, HResult, hsm_call, session::Session};

/// PKCS#11 `CKA_EC_PARAMS` value for each curve supported for HSM-delegated EC key generation.
/// FIPS-approved NIST prime curves always use the DER-encoded `ASN.1 OBJECT IDENTIFIER`.
/// Edwards/Montgomery curves (`Ed25519`/`Ed448`/`X25519`, gated behind the `non-fips` feature,
/// mirroring `crate::crypto::elliptic_curves::sign`, issue #1157) use the DER-encoded
/// `PrintableString` curve name instead (OASIS Cryptoki v3.0 §2.3.7/§2.3.8, Table 8): the OID
/// form is also spec-permitted, but the `PrintableString` form was empirically verified to be
/// the one actually required by `SoftHSM2` 2.6.1's `CKM_EC_EDWARDS_KEY_PAIR_GEN` (`pkcs11-tool
/// --keypairgen --key-type EC:edwards25519` produces `EC_PARAMS: 130c656477617264733235353139`,
/// i.e. tag `0x13` = `PrintableString`, not tag `0x06` = `OBJECT IDENTIFIER`).
#[must_use]
pub(crate) const fn curve_der_oid(curve: EcCurve) -> &'static [u8] {
    match curve {
        // secp224r1 (1.3.132.0.33)
        EcCurve::P224 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21],
        // prime256v1 / secp256r1 (1.2.840.10045.3.1.7)
        EcCurve::P256 => &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // secp384r1 (1.3.132.0.34)
        EcCurve::P384 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
        // secp521r1 (1.3.132.0.35)
        EcCurve::P521 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],
        // PrintableString "edwards25519"
        #[cfg(feature = "non-fips")]
        EcCurve::Ed25519 => &[
            0x13, 0x0C, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
        ],
        // PrintableString "edwards448"
        #[cfg(feature = "non-fips")]
        EcCurve::Ed448 => &[
            0x13, 0x0A, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38,
        ],
        // PrintableString "curve25519"
        #[cfg(feature = "non-fips")]
        EcCurve::X25519 => &[
            0x13, 0x0A, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
        ],
    }
}

/// Some PKCS#11 tokens store Edwards/Montgomery `CKA_EC_PARAMS` as a DER `OBJECT IDENTIFIER`
/// instead of the printable-string form used during key generation on `SoftHSM2`.
#[cfg(feature = "non-fips")]
#[must_use]
const fn curve_der_named_curve_oid(curve: EcCurve) -> Option<&'static [u8]> {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => None,
        // id-X25519 (1.3.101.110)
        EcCurve::X25519 => Some(&[0x06, 0x03, 0x2B, 0x65, 0x6E]),
        // id-Ed25519 (1.3.101.112)
        EcCurve::Ed25519 => Some(&[0x06, 0x03, 0x2B, 0x65, 0x70]),
        // id-Ed448 (1.3.101.113)
        EcCurve::Ed448 => Some(&[0x06, 0x03, 0x2B, 0x65, 0x71]),
    }
}

/// The `CK_MECHANISM_TYPE` used by `C_GenerateKeyPair` to create a key pair on `curve`.
/// FIPS-approved NIST prime curves use the generic `CKM_EC_KEY_PAIR_GEN`; Edwards curves
/// (`Ed25519`/`Ed448`) use `CKM_EC_EDWARDS_KEY_PAIR_GEN`; the Montgomery curve (`X25519`) uses
/// `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` (PKCS#11 v3.0 §2.3.7/§2.3.8, issue #1157).
#[must_use]
pub(crate) const fn curve_key_pair_gen_mechanism(curve: EcCurve) -> CK_MECHANISM_TYPE {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => CKM_EC_KEY_PAIR_GEN,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed25519 | EcCurve::Ed448 => CKM_EC_EDWARDS_KEY_PAIR_GEN,
        #[cfg(feature = "non-fips")]
        EcCurve::X25519 => CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    }
}

/// The `CKA_KEY_TYPE` value the generated key pair's objects must carry. FIPS-approved NIST
/// prime curves use the generic `CKK_EC`; Edwards curves use `CKK_EC_EDWARDS`; the Montgomery
/// curve uses `CKK_EC_MONTGOMERY` — mismatching this against the key-pair-gen mechanism causes
/// `CKR_TEMPLATE_INCONSISTENT` on at least `SoftHSM2` (empirically verified, issue #1157).
#[must_use]
pub(crate) const fn curve_key_type(curve: EcCurve) -> CK_KEY_TYPE {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => CKK_EC,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed25519 | EcCurve::Ed448 => CKK_EC_EDWARDS,
        #[cfg(feature = "non-fips")]
        EcCurve::X25519 => CKK_EC_MONTGOMERY,
    }
}

/// Recover the `EcCurve` matching a DER-encoded `CKA_EC_PARAMS` value read back from the HSM.
pub(crate) fn curve_from_der_oid(oid: &[u8]) -> HResult<EcCurve> {
    #[cfg(not(feature = "non-fips"))]
    let curves = [EcCurve::P224, EcCurve::P256, EcCurve::P384, EcCurve::P521];
    #[cfg(feature = "non-fips")]
    let curves = [
        EcCurve::P224,
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::Ed25519,
        EcCurve::Ed448,
        EcCurve::X25519,
    ];
    for curve in curves {
        if curve_der_oid(curve) == oid {
            return Ok(curve);
        }
        #[cfg(feature = "non-fips")]
        if curve_der_named_curve_oid(curve).is_some_and(|candidate| candidate == oid) {
            return Ok(curve);
        }
    }
    Err(HError::Default(format!(
        "Unsupported EC curve OID: {oid:02x?}"
    )))
}

/// The curve's field element size, in bytes (used to size the `CKA_VALUE` private scalar and
/// to split the raw `r || s` ECDSA signature). Not meaningful for `EdDSA` signatures, which are
/// always `2 * curve_byte_size` for the Edwards curves below (64 bytes for Ed25519, 114 bytes
/// for Ed448) and are sized directly by `Session::sign`.
#[must_use]
pub(crate) const fn curve_byte_size(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P224 => 28,
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        // 521 bits -> ceil(521 / 8) = 66 bytes
        EcCurve::P521 => 66,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed25519 | EcCurve::X25519 => 32,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed448 => 57,
    }
}

/// `true` for the Montgomery curve (`X25519`), which is used only for ECDH key agreement
/// (`CKA_DERIVE`) and does not support `CKA_SIGN`/`CKA_VERIFY`, unlike every other curve here
/// (issue #1157). Always `false` in FIPS-only builds, where `EcCurve::X25519` does not exist.
#[must_use]
pub(crate) const fn curve_is_montgomery(curve: EcCurve) -> bool {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => false,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed25519 | EcCurve::Ed448 => false,
        #[cfg(feature = "non-fips")]
        EcCurve::X25519 => true,
    }
}

impl Session {
    /// Generate an EC key pair and return the private and public key handles in this order.
    ///
    /// FIPS-approved NIST prime curves (P-224/P-256/P-384/P-521) are always supported; the
    /// Edwards curves (`Ed25519`/`Ed448`, for `EdDSA` signing) and the Montgomery curve
    /// (`X25519`, for ECDH key agreement) require the `non-fips` feature (issue #1157).
    ///
    /// If exportable is set to `false`, the `sensitive` flag is set to true, and the private
    /// key will not be exportable.
    /// # Arguments
    /// * `sk_id` - The ID of the private key
    /// * `pk_id` - The ID of the public key
    /// * `curve` - The NIST curve to use
    /// * `sensitive` - If the private key is sensitive
    /// # Returns
    /// * `Ok((HsmId, HsmId))` - The private and public key handles
    pub fn generate_ec_key_pair(
        &self,
        sk_id: &[u8],
        pk_id: &[u8],
        curve: EcCurve,
        sensitive: bool,
    ) -> HResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let ec_params = curve_der_oid(curve);
        let key_type = curve_key_type(curve);
        let sensitive = if sensitive { CK_TRUE } else { CK_FALSE };
        let extractable = if sensitive == CK_TRUE {
            CK_FALSE
        } else {
            CK_TRUE
        };
        // Montgomery curves (X25519) are derive-only: CKA_DERIVE replaces CKA_SIGN/CKA_VERIFY.
        let is_montgomery = curve_is_montgomery(curve);
        let usage_attribute_type = if is_montgomery {
            CKA_DERIVE
        } else {
            CKA_VERIFY
        };
        let priv_usage_attribute_type = if is_montgomery { CKA_DERIVE } else { CKA_SIGN };

        let mut pub_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&key_type)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: ec_params.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(ec_params.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(pk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID,
                pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(pk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: usage_attribute_type,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
        ];
        // AES/RSA-style wrap/encrypt flags do not apply to EC keys — only sign/verify (or,
        // for the Montgomery curve X25519, derive) are set (matching PKCS#11's CKA_SIGN/
        // CKA_VERIFY/CKA_DERIVE convention for EC keys).

        let mut priv_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&key_type)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: sk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(sk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID,
                pValue: sk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(sk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: priv_usage_attribute_type,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: (&raw const sensitive).cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: std::ptr::from_ref(&extractable)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
        ];
        // CKA_ENCRYPT/CKA_DECRYPT/CKA_WRAP/CKA_UNWRAP are intentionally omitted for EC keys —
        // ECDSA private keys are used only for CKA_SIGN, matching the KMIP EC private key usage
        // mask set by the software EC key generation path.

        let mut mechanism = CK_MECHANISM {
            mechanism: curve_key_pair_gen_mechanism(curve),
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut pub_key_handle = CK_OBJECT_HANDLE::default();
        let mut priv_key_handle = CK_OBJECT_HANDLE::default();
        let p_mechanism: CK_MECHANISM_PTR = &raw mut mechanism;

        hsm_call!(
            self.hsm(),
            "Failed generating EC key pair",
            C_GenerateKeyPair,
            self.session_handle(),
            p_mechanism,
            pub_key_template.as_mut_ptr(),
            CK_ULONG::try_from(pub_key_template.len())?,
            priv_key_template.as_mut_ptr(),
            CK_ULONG::try_from(priv_key_template.len())?,
            &raw mut pub_key_handle,
            &raw mut priv_key_handle
        );

        self.object_handles_cache()
            .insert(sk_id.to_vec(), priv_key_handle)?;
        self.object_handles_cache()
            .insert(pk_id.to_vec(), pub_key_handle)?;

        Ok((priv_key_handle, pub_key_handle))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use cosmian_kms_interfaces::EcCurve;
    use pkcs11_sys::{CKK_EC, CKM_EC_KEY_PAIR_GEN};

    use super::{curve_der_oid, curve_from_der_oid, curve_key_pair_gen_mechanism, curve_key_type};

    /// `curve_from_der_oid` must recover the exact curve that `curve_der_oid` encoded, for
    /// every FIPS-approved NIST prime curve — a pure round-trip test requiring no HSM
    /// connection (no simulator can help here; this is HSM-independent parameter logic).
    #[test]
    fn nist_curve_oid_round_trips() {
        for curve in [EcCurve::P224, EcCurve::P256, EcCurve::P384, EcCurve::P521] {
            let oid = curve_der_oid(curve);
            assert_eq!(
                curve_from_der_oid(oid).expect("must recognize a curve it just encoded"),
                curve
            );
            assert_eq!(curve_key_pair_gen_mechanism(curve), CKM_EC_KEY_PAIR_GEN);
            assert_eq!(curve_key_type(curve), CKK_EC);
        }
    }

    #[test]
    fn unsupported_oid_is_rejected() {
        // secp256k1 (1.3.132.0.10) is intentionally not supported for HSM delegation.
        let secp256k1_oid = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
        curve_from_der_oid(&secp256k1_oid).unwrap_err();
    }
}

/// Mocked/parameter-only coverage for HSM-delegated `EdDSA`/X25519 key generation (issue #1157):
/// neither `SoftHSM2` 2.6.1 nor the Utimaco `CryptoServer` simulator expose the Montgomery
/// (X25519) key-pair-gen mechanism, so this suite cannot be exercised end-to-end against any
/// available simulator; `SoftHSM2` *does* support `EdDSA`/`Ed25519`/`Ed448`, which is covered
/// live by `tests_shared::eddsa_sign_all_curves` instead. These tests only assert the pure
/// PKCS#11 parameter-encoding logic (`CKA_EC_PARAMS`, `CKA_KEY_TYPE`, mechanism selection).
#[cfg(all(test, feature = "non-fips"))]
mod non_fips_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use cosmian_kms_interfaces::EcCurve;
    use pkcs11_sys::{
        CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKM_EC_EDWARDS_KEY_PAIR_GEN,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    };

    use super::{
        curve_der_oid, curve_from_der_oid, curve_is_montgomery, curve_key_pair_gen_mechanism,
        curve_key_type,
    };

    #[test]
    fn edwards_and_montgomery_curve_params_round_trip() {
        for curve in [EcCurve::Ed25519, EcCurve::Ed448, EcCurve::X25519] {
            let oid = curve_der_oid(curve);
            assert_eq!(
                curve_from_der_oid(oid).expect("must recognize a curve it just encoded"),
                curve
            );
        }
    }

    #[test]
    fn edwards_and_montgomery_named_curve_oids_round_trip() {
        for (curve, oid) in [
            (EcCurve::Ed25519, [0x06, 0x03, 0x2B, 0x65, 0x70]),
            (EcCurve::Ed448, [0x06, 0x03, 0x2B, 0x65, 0x71]),
            (EcCurve::X25519, [0x06, 0x03, 0x2B, 0x65, 0x6E]),
        ] {
            assert_eq!(
                curve_from_der_oid(&oid).expect("must accept named-curve OID form"),
                curve
            );
        }
    }

    #[test]
    fn edwards_curves_use_edwards_key_type_and_mechanism() {
        for curve in [EcCurve::Ed25519, EcCurve::Ed448] {
            assert_eq!(curve_key_type(curve), CKK_EC_EDWARDS);
            assert_eq!(
                curve_key_pair_gen_mechanism(curve),
                CKM_EC_EDWARDS_KEY_PAIR_GEN
            );
            assert!(!curve_is_montgomery(curve));
        }
    }

    #[test]
    fn x25519_uses_montgomery_key_type_mechanism_and_is_derive_only() {
        assert_eq!(curve_key_type(EcCurve::X25519), CKK_EC_MONTGOMERY);
        assert_eq!(
            curve_key_pair_gen_mechanism(EcCurve::X25519),
            CKM_EC_MONTGOMERY_KEY_PAIR_GEN
        );
        assert!(curve_is_montgomery(EcCurve::X25519));
    }

    #[test]
    fn curve_param_encodings_use_printable_string_not_oid() {
        // SoftHSM2 2.6.1 was empirically verified (pkcs11-tool --keypairgen --key-type
        // EC:edwards25519) to require the PrintableString curve-name encoding, not the DER
        // OID, for CKA_EC_PARAMS on Edwards/Montgomery curves; see curve_der_oid's doc comment.
        for curve in [EcCurve::Ed25519, EcCurve::Ed448, EcCurve::X25519] {
            let oid = curve_der_oid(curve);
            assert_eq!(
                oid.first().copied(),
                Some(0x13),
                "expected PrintableString DER tag (0x13) for {curve:?}"
            );
        }
    }
}
