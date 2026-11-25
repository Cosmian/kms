use cosmian_logger::info;

use crate::{error::KmsError, result::KResult};

pub(crate) fn get_hsm_password() -> KResult<String> {
    let user_password = option_env!("HSM_USER_PASSWORD")
        .ok_or_else(|| {
            KmsError::Default(
                "The user password for the HSM is not set. Please set the HSM_USER_PASSWORD \
                 environment variable"
                    .to_owned(),
            )
        })?
        .to_owned();
    Ok(user_password)
}

pub(crate) fn get_hsm_slot_id() -> KResult<usize> {
    let slot_id = option_env!("HSM_SLOT_ID")
        .ok_or_else(|| {
            KmsError::Default(
                "The slot id for the HSM was not provided. Please set the HSM_SLOT_ID environment \
                 variable"
                    .to_owned(),
            )
        })?
        .to_owned();
    slot_id.parse().map_err(|_e| {
        KmsError::Default(format!(
            "The HSM slot id '{slot_id}' could not be parsed. Please make sure theHSM_SLOT_ID \
             environment variable is set to a valid slot id."
        ))
    })
}

pub(crate) fn get_hsm_model() -> Option<String> {
    let model = option_env!("HSM_MODEL");
    model.map_or_else(
        || {
            info!(
                "No HSM model provided via environment variable 'HSM_MODEL'. Defaulting to utimaco"
            );
            None
        },
        |model| Some(model.to_owned()),
    )
}

/// Whether the token stores `CKA_START_DATE` / `CKA_END_DATE` on keys (HSM key rotation
/// scheduling). `Some` for the models whose capability profile is known, `None` for the
/// profile that has not been measured (`kryoptic`): the test then follows what the token does.
pub(crate) fn hsm_key_dates_support() -> Option<bool> {
    match get_hsm_model().as_deref() {
        Some(
            "softhsm2" | "other" | "crypt2pay" | "idemia_sphere" | "aws_cloudhsm"
            | "azure_cloud_hsm" | "gcp_cloud_hsm",
        ) => Some(false),
        Some("kryoptic") => None,
        _ => Some(true),
    }
}

/// A FIPS build only lets a token seal AES-GCM when the token generates the IV itself
/// (FIPS 140-3 IG C.H); `SoftHSM2` cannot, so the server refuses instead of sending its own IV.
/// The Idemia simulator in `SECURITY_LEVEL=FIPS` forwards `CKM_AES_GCM` to `SoftHSM2` and does not
/// write an IV either, and a generic `hsm_model = "other"` library is assumed not to. These three
/// are taken to generate the IV only when the build environment sets `HSM_GENERATES_GCM_IV`,
/// i.e. when the PKCS#11 library is fronted by the IV shim
/// (`.mise/scripts/test/hsm/pkcs11_fips_iv_shim.c`). Kryoptic generates it through the PKCS#11 v3
/// message API, so it encrypts as usual, like the other HSMs.
#[cfg(not(feature = "non-fips"))]
pub(crate) fn hsm_cannot_generate_gcm_iv() -> bool {
    match get_hsm_model().as_deref() {
        Some("softhsm2" | "idemia_sphere" | "other") => {
            option_env!("HSM_GENERATES_GCM_IV").is_none()
        }
        _ => false,
    }
}

/// See the FIPS variant: a non-FIPS build encrypts with a KMS-chosen IV on every token.
#[cfg(feature = "non-fips")]
pub(crate) const fn hsm_cannot_generate_gcm_iv() -> bool {
    false
}

/// The Idemia HSM Simulator does not offer `CKM_AES_KEY_WRAP_PAD` (its mechanism list stops at
/// `CKM_AES_KEY_WRAP`), so the server refuses AES-KWP on its slots.
pub(crate) fn hsm_lacks_aes_key_wrap_pad() -> bool {
    get_hsm_model().as_deref() == Some("idemia_sphere")
}

/// The Idemia simulator in `SECURITY_LEVEL=FIPS` (the one a FIPS build is tested against) offers
/// no `CKM_AES_KEY_WRAP` either: AES-KW is not a mechanism it advertises as approved, so the
/// server refuses AES-KW on its slots. Its non-FIPS profile (the `non-fips` build) offers it.
#[cfg(not(feature = "non-fips"))]
pub(crate) fn hsm_lacks_aes_key_wrap() -> bool {
    get_hsm_model().as_deref() == Some("idemia_sphere")
}

/// See the FIPS variant: the non-FIPS simulator profile offers AES-KW.
#[cfg(feature = "non-fips")]
pub(crate) const fn hsm_lacks_aes_key_wrap() -> bool {
    false
}

/// The Idemia simulator in `SECURITY_LEVEL=FIPS` lists raw `CKM_RSA_PKCS` and `CKM_ECDSA` but
/// rejects them at use (`FIPS REJECTED: ... not permitted in FIPS mode`): the KMS signs a
/// `DigestInfo` / digest through them (RSA and EC sub-CA), so those tests fail there. Its non-FIPS
/// profile accepts both.
#[cfg(not(feature = "non-fips"))]
pub(crate) fn hsm_rejects_raw_signing_mechanisms() -> bool {
    get_hsm_model().as_deref() == Some("idemia_sphere")
}

/// See the FIPS variant: the non-FIPS simulator profile accepts the raw signing mechanisms.
#[cfg(feature = "non-fips")]
pub(crate) const fn hsm_rejects_raw_signing_mechanisms() -> bool {
    false
}

/// Checks the refusal of an AES-GCM encryption inside a token that cannot generate the IV.
pub(crate) fn assert_gcm_encrypt_refused(result: KResult<Vec<u8>>) {
    let error = result.expect_err("AES-GCM without a token-generated IV must be refused in FIPS");
    assert!(
        error
            .to_string()
            .contains("needs an IV generated inside the HSM"),
        "{error}"
    );
}
