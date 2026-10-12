//! HSM-resident `EdDSA` (Ed25519/Ed448) keypair creation and KMIP Sign/SignatureVerify
//! reachability (issue #1182).
use std::sync::Arc;

use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_operations::{Operation, Sign, SignatureVerify},
    kmip_types::{RecommendedCurve, UniqueIdentifier, ValidityIndicator},
    requests::create_ec_key_pair_request,
};
use cosmian_logger::{info, warn};
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::{
        hsm::{EMPTY_TAGS, hsm_clap_config, send_message},
        test_utils::get_tmp_sqlite_path,
    },
};

const ADMIN: &str = "owner.client@acme.com";
const DATA: &[u8] = b"HSM EdDSA KMIP reachability test data";

async fn create_sign_verify(kms: &Arc<KMS>, slot: usize, curve: RecommendedCurve) -> KResult<()> {
    let sk_uid = as_hsm_uid!(slot, Uuid::new_v4());
    let create_request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(sk_uid.clone())),
        EMPTY_TAGS,
        curve,
        false,
        None,
    )?;
    let response = send_message(
        kms.clone(),
        ADMIN,
        vec![Operation::CreateKeyPair(Box::new(create_request))],
    )
    .await?;
    let Operation::CreateKeyPairResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError(
            "invalid CreateKeyPair response".to_owned(),
        ));
    };
    assert_eq!(
        create_response.private_key_unique_identifier,
        UniqueIdentifier::TextString(sk_uid.clone())
    );
    let pk_uid = create_response.public_key_unique_identifier.clone();

    // Capability-probe like the HSM-layer test (`base_hsm::tests_shared`): some PKCS#11 libraries
    // (e.g. Kryoptic builds without PKCS#11 v3.0 `CKM_EDDSA`, mechanism 4183) cannot sign EdDSA.
    // The CreateKeyPair reachability above is still asserted; only the Sign/Verify leg is skipped.
    let sign_result = kms
        .sign(
            Sign {
                unique_identifier: Some(UniqueIdentifier::TextString(sk_uid)),
                data: Some(DATA.to_vec().into()),
                ..Default::default()
            },
            &UserId::from(ADMIN),
        )
        .await;
    let sign_response = match sign_result {
        Ok(response) => response,
        Err(error) if error.to_string().contains("does not support mechanism") => {
            warn!(
                "HSM EdDSA: {curve:?} Sign unavailable on this PKCS#11 library, skipping: {error}"
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let signature = sign_response
        .signature_data
        .ok_or_else(|| KmsError::ServerError("missing signature_data".to_owned()))?;

    let verify_response = kms
        .signature_verify(
            SignatureVerify {
                unique_identifier: Some(pk_uid.clone()),
                data: Some(DATA.to_vec()),
                signature_data: Some(signature.clone()),
                ..Default::default()
            },
            &UserId::from(ADMIN),
        )
        .await?;
    assert_eq!(
        verify_response.validity_indicator,
        Some(ValidityIndicator::Valid),
        "{curve:?}: genuine signature must verify"
    );

    let mut tampered = signature;
    if let Some(last) = tampered.last_mut() {
        *last ^= 0xFF;
    }
    let tampered_verify = kms
        .signature_verify(
            SignatureVerify {
                unique_identifier: Some(pk_uid),
                data: Some(DATA.to_vec()),
                signature_data: Some(tampered),
                ..Default::default()
            },
            &UserId::from(ADMIN),
        )
        .await?;
    assert_eq!(
        tampered_verify.validity_indicator,
        Some(ValidityIndicator::Invalid),
        "{curve:?}: tampered signature must not verify"
    );
    Ok(())
}

/// Issue #1182: HSM-resident Ed25519 and Ed448 keypairs created via KMIP `CreateKeyPair`
/// must be usable through KMIP `Sign`/`SignatureVerify`.
pub(super) async fn test_hsm_eddsa_sign() -> KResult<()> {
    let sqlite_path = get_tmp_sqlite_path();
    let mut clap_config = hsm_clap_config(ADMIN, None)?;
    clap_config.db.sqlite_path = sqlite_path;
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    info!("HSM EdDSA: Ed25519 create+sign+verify");
    create_sign_verify(&kms, slot, RecommendedCurve::CURVEED25519).await?;
    info!("HSM EdDSA: Ed448 create+sign+verify");
    create_sign_verify(&kms, slot, RecommendedCurve::CURVEED448).await?;
    Ok(())
}
