//! Tests for the KMIP 2.1 §6.1.44 `Revoke` operation state-transition contract.
//!
//! For every [`RevocationReasonCode`] the server MUST write the correct [`State`]
//! when revoking an `Active` key:
//!
//! | Reason code            | Active → |
//! |------------------------|----------|
//! | `Unspecified`          | `Deactivated` |
//! | `KeyCompromise`        | `Compromised`  |
//! | `CACompromise`         | `Compromised`  |
//! | `AffiliationChanged`   | `Deactivated` |
//! | `Superseded`           | `Deactivated` |
//! | `CessationOfOperation` | `Deactivated` |
//! | `PrivilegeWithdrawn`   | `Deactivated` |
//!
//! KMIP §6.1.44 transition \#8 (Deactivated → Compromised) is also tested:
//!
//! | Reason code            | Deactivated → |
//! |------------------------|----------------|
//! | `KeyCompromise`        | `Compromised` (transition \#8) |
//! | `CACompromise`         | `Compromised` (transition \#8) |
//! | `Unspecified`          | `Deactivated` (no-op success) |
//! | `CessationOfOperation` | `Deactivated` (no-op success) |
//!
//! Additional coverage:
//! - AKLC-M-2-21: Revoke on an already-`Destroyed` key succeeds without changing state.
//! - EC key-pair cascade: `cascade=true` propagates the revocation to the paired key;
//!   `cascade=false` does not.
//! - Unknown UID returns `Object_Not_Found`.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, RevocationReason, RevocationReasonCode, State},
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_operations::{
            CreateKeyPairResponse, CreateResponse, Destroy, DestroyResponse, GetAttributes,
            GetAttributesResponse, Revoke, RevokeResponse,
        },
        kmip_types::{
            AttributeReference, CryptographicAlgorithm, RecommendedCurve, Tag, UniqueIdentifier,
        },
        requests::{create_ec_key_pair_request, symmetric_key_create_request},
    },
};

use crate::{result::KResult, tests::test_utils};

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Create an AES-256 symmetric key and return its UID.
async fn create_aes_key<S, B>(app: &S) -> KResult<String>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let resp: CreateResponse = test_utils::post_2_1(app, req).await?;
    Ok(resp.unique_identifier.to_string())
}

/// Create an EC P-256 key pair and return `(private_uid, public_uid)`.
async fn create_ec_pair<S, B>(app: &S) -> KResult<(String, String)>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let resp: CreateKeyPairResponse = test_utils::post_2_1(app, req).await?;
    Ok((
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    ))
}

/// Query the `State` attribute of an object via KMIP `GetAttributes`.
async fn get_state<S, B>(app: &S, uid: &str) -> KResult<Option<State>>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let resp: GetAttributesResponse = test_utils::post_2_1(
        app,
        GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_reference: Some(vec![AttributeReference::Standard(Tag::State)]),
        },
    )
    .await?;
    Ok(resp.attributes.state)
}

/// Send a `Revoke` request with the given `reason_code` and `cascade` flag.
/// Returns the parsed `RevokeResponse` on success, or a `KmsError` on failure.
async fn revoke<S, B>(
    app: &S,
    uid: &str,
    reason_code: RevocationReasonCode,
    cascade: bool,
) -> KResult<RevokeResponse>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    test_utils::post_2_1(
        app,
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            revocation_reason: RevocationReason {
                revocation_reason_code: reason_code,
                revocation_message: Some("revoke_tests harness".to_owned()),
            },
            compromise_occurrence_date: None,
            cascade,
        },
    )
    .await
}

/// Transition a key to `Destroyed` state (Revoke → Destroy with `remove=false`).
///
/// Using `remove=false` keeps the metadata so the key can still be looked up
/// and its state can be verified (or a subsequent Revoke can be tested).
async fn destroy_key<S, B>(app: &S, uid: &str) -> KResult<DestroyResponse>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    // KMIP §6.1.17 requires Deactivated/Compromised state before Destroy.
    revoke(app, uid, RevocationReasonCode::CessationOfOperation, false).await?;
    test_utils::post_2_1(
        app,
        Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            remove: false,
            cascade: false,
            expected_object_type: None,
        },
    )
    .await
}

// ── Section A: Active → correct state for each RevocationReasonCode ───────────

/// KMIP §6.1.44: `Active + Unspecified` → `Deactivated`.
#[tokio::test]
async fn test_active_unspecified_yields_deactivated() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(&app, &uid, RevocationReasonCode::Unspecified, false).await?;

    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));
    Ok(())
}

/// KMIP §6.1.44: `Active + KeyCompromise` → `Compromised`.
#[tokio::test]
async fn test_active_key_compromise_yields_compromised() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(&app, &uid, RevocationReasonCode::KeyCompromise, false).await?;

    assert_eq!(get_state(&app, &uid).await?, Some(State::Compromised));
    Ok(())
}

/// KMIP §6.1.44: `Active + CACompromise` → `Compromised`.
#[tokio::test]
async fn test_active_ca_compromise_yields_compromised() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(&app, &uid, RevocationReasonCode::CACompromise, false).await?;

    assert_eq!(get_state(&app, &uid).await?, Some(State::Compromised));
    Ok(())
}

/// KMIP §6.1.44: `Active + AffiliationChanged` → `Deactivated`.
#[tokio::test]
async fn test_active_affiliation_changed_yields_deactivated() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(&app, &uid, RevocationReasonCode::AffiliationChanged, false).await?;

    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));
    Ok(())
}

/// KMIP §6.1.44: `Active + Superseded` → `Deactivated`.
#[tokio::test]
async fn test_active_superseded_yields_deactivated() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(&app, &uid, RevocationReasonCode::Superseded, false).await?;

    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));
    Ok(())
}

/// KMIP §6.1.44: `Active + CessationOfOperation` → `Deactivated`.
#[tokio::test]
async fn test_active_cessation_yields_deactivated() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(
        &app,
        &uid,
        RevocationReasonCode::CessationOfOperation,
        false,
    )
    .await?;

    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));
    Ok(())
}

/// KMIP §6.1.44: `Active + PrivilegeWithdrawn` → `Deactivated`.
#[tokio::test]
async fn test_active_privilege_withdrawn_yields_deactivated() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(&app, &uid, RevocationReasonCode::PrivilegeWithdrawn, false).await?;

    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));
    Ok(())
}

// ── Section B: Transition #8 — Deactivated → Compromised (or no-op) ──────────

/// KMIP §6.1.44 transition \#8: `Deactivated + KeyCompromise` → `Compromised`.
#[tokio::test]
async fn test_deactivated_key_compromise_yields_compromised() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    // Transition Active → Deactivated first.
    revoke(
        &app,
        &uid,
        RevocationReasonCode::CessationOfOperation,
        false,
    )
    .await?;
    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));

    // Transition #8: Deactivated → Compromised.
    revoke(&app, &uid, RevocationReasonCode::KeyCompromise, false).await?;
    assert_eq!(
        get_state(&app, &uid).await?,
        Some(State::Compromised),
        "Deactivated + KeyCompromise MUST yield Compromised (KMIP §6.1.44 transition #8)"
    );
    Ok(())
}

/// KMIP §6.1.44 transition \#8: `Deactivated + CACompromise` → `Compromised`.
#[tokio::test]
async fn test_deactivated_ca_compromise_yields_compromised() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(
        &app,
        &uid,
        RevocationReasonCode::CessationOfOperation,
        false,
    )
    .await?;
    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));

    revoke(&app, &uid, RevocationReasonCode::CACompromise, false).await?;
    assert_eq!(
        get_state(&app, &uid).await?,
        Some(State::Compromised),
        "Deactivated + CACompromise MUST yield Compromised (KMIP §6.1.44 transition #8)"
    );
    Ok(())
}

/// Asserts that a Revoke with `reason_code` fails with `Wrong_Key_Lifecycle_State` and
/// leaves the object in `state`.
async fn assert_revoke_refused<S, B>(
    app: &S,
    uid: &str,
    reason_code: RevocationReasonCode,
    state: State,
) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let error = revoke(app, uid, reason_code, false)
        .await
        .err()
        .map(|e| e.to_string());
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.contains(&ErrorReason::Wrong_Key_Lifecycle_State.to_string())),
        "Revoke with {reason_code:?} on a {state:?} object must fail with \
         Wrong_Key_Lifecycle_State, got: {error:?}"
    );
    assert_eq!(get_state(app, uid).await?, Some(state));
    Ok(())
}

/// KMIP 2.1 §4.57: a non-compromise reason only moves Active to Deactivated, so revoking a
/// Deactivated object with `Unspecified` is `Wrong_Key_Lifecycle_State` and keeps it Deactivated.
#[tokio::test]
async fn test_deactivated_unspecified_is_refused() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(
        &app,
        &uid,
        RevocationReasonCode::CessationOfOperation,
        false,
    )
    .await?;
    assert_eq!(get_state(&app, &uid).await?, Some(State::Deactivated));

    assert_revoke_refused(
        &app,
        &uid,
        RevocationReasonCode::Unspecified,
        State::Deactivated,
    )
    .await
}

/// KMIP 2.1 §4.57: `Deactivated + Superseded` is `Wrong_Key_Lifecycle_State`.
#[tokio::test]
async fn test_deactivated_superseded_is_refused() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    revoke(
        &app,
        &uid,
        RevocationReasonCode::CessationOfOperation,
        false,
    )
    .await?;
    assert_revoke_refused(
        &app,
        &uid,
        RevocationReasonCode::Superseded,
        State::Deactivated,
    )
    .await
}

// ── Section C: Destroyed keys ────────────────────────────────────────────────

/// KMIP 2.1 §4.57: only a compromise moves a Destroyed object (to Destroyed Compromised,
/// as in AKLC-M-2-21); a non-compromise reason is `Wrong_Key_Lifecycle_State`.
#[tokio::test]
async fn test_revoke_on_destroyed_key_non_compromise_is_refused() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    // Bring the key to Destroyed state (Revoke → Destroy with metadata kept).
    destroy_key(&app, &uid).await?;
    assert_eq!(get_state(&app, &uid).await?, Some(State::Destroyed));

    assert_revoke_refused(
        &app,
        &uid,
        RevocationReasonCode::CessationOfOperation,
        State::Destroyed,
    )
    .await?;

    // A compromise is accepted and moves it to Destroyed Compromised.
    revoke(&app, &uid, RevocationReasonCode::KeyCompromise, false).await?;
    assert_eq!(
        get_state(&app, &uid).await?,
        Some(State::Destroyed_Compromised)
    );
    Ok(())
}

/// KMIP 2.1 §4.57: a Destroyed Compromised object accepts no further revocation.
#[tokio::test]
async fn test_revoke_on_destroyed_compromised_key_is_refused() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let uid = create_aes_key(&app).await?;

    // Bring to Compromised then Destroy → Destroyed_Compromised.
    revoke(&app, &uid, RevocationReasonCode::KeyCompromise, false).await?;
    assert_eq!(get_state(&app, &uid).await?, Some(State::Compromised));
    test_utils::post_2_1::<_, _, DestroyResponse, _>(
        &app,
        Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            remove: false,
            cascade: false,
            expected_object_type: None,
        },
    )
    .await?;
    assert_eq!(
        get_state(&app, &uid).await?,
        Some(State::Destroyed_Compromised)
    );

    assert_revoke_refused(
        &app,
        &uid,
        RevocationReasonCode::CessationOfOperation,
        State::Destroyed_Compromised,
    )
    .await
}

// ── Section D: EC key-pair cascade ───────────────────────────────────────────

/// `cascade=true`: revoking the private key MUST also revoke the linked public key.
#[tokio::test]
async fn test_ec_pair_revoke_private_cascade_true_revokes_public() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let (priv_uid, pub_uid) = create_ec_pair(&app).await?;

    revoke(
        &app,
        &priv_uid,
        RevocationReasonCode::CessationOfOperation,
        true,
    )
    .await?;

    assert_eq!(
        get_state(&app, &priv_uid).await?,
        Some(State::Deactivated),
        "Private key MUST be Deactivated after Revoke"
    );
    assert_eq!(
        get_state(&app, &pub_uid).await?,
        Some(State::Deactivated),
        "Public key MUST be Deactivated when cascade=true"
    );
    Ok(())
}

/// `cascade=false`: revoking the private key MUST NOT touch the linked public key.
#[tokio::test]
async fn test_ec_pair_revoke_private_cascade_false_leaves_public_active() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let (priv_uid, pub_uid) = create_ec_pair(&app).await?;

    revoke(
        &app,
        &priv_uid,
        RevocationReasonCode::CessationOfOperation,
        false,
    )
    .await?;

    assert_eq!(get_state(&app, &priv_uid).await?, Some(State::Deactivated));
    assert_eq!(
        get_state(&app, &pub_uid).await?,
        Some(State::Active),
        "Public key MUST remain Active when cascade=false"
    );
    Ok(())
}

/// `cascade=true` with `KeyCompromise`: both private AND public MUST become `Compromised`.
#[tokio::test]
async fn test_ec_pair_key_compromise_cascade_true_compromises_both() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let (priv_uid, pub_uid) = create_ec_pair(&app).await?;

    revoke(&app, &priv_uid, RevocationReasonCode::KeyCompromise, true).await?;

    assert_eq!(
        get_state(&app, &priv_uid).await?,
        Some(State::Compromised),
        "Private key MUST be Compromised after KeyCompromise Revoke"
    );
    assert_eq!(
        get_state(&app, &pub_uid).await?,
        Some(State::Compromised),
        "Public key MUST also be Compromised when cascade=true + KeyCompromise"
    );
    Ok(())
}

/// `cascade=true` via public key: revoking the public key MUST also revoke the private key.
#[tokio::test]
async fn test_ec_pair_revoke_public_cascade_true_revokes_private() -> KResult<()> {
    let app = test_utils::setup_app(None).await;
    let (priv_uid, pub_uid) = create_ec_pair(&app).await?;

    revoke(
        &app,
        &pub_uid,
        RevocationReasonCode::CessationOfOperation,
        true,
    )
    .await?;

    assert_eq!(
        get_state(&app, &pub_uid).await?,
        Some(State::Deactivated),
        "Public key MUST be Deactivated after Revoke"
    );
    assert_eq!(
        get_state(&app, &priv_uid).await?,
        Some(State::Deactivated),
        "Private key MUST be Deactivated when cascade=true (from public)"
    );
    Ok(())
}

// ── Section E: Error cases ────────────────────────────────────────────────────

/// KMIP §6.1.44: Revoking a non-existent UID MUST return `Object_Not_Found`.
#[tokio::test]
async fn test_revoke_unknown_uid_returns_object_not_found() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    let result = revoke(
        &app,
        "non-existent-uid-00000000",
        RevocationReasonCode::Unspecified,
        false,
    )
    .await;

    assert!(
        result.is_err(),
        "Revoke on unknown UID MUST fail with Object_Not_Found"
    );
    // The error message MUST contain the Object_Not_Found reason.
    let err_str = result.unwrap_err().to_string();
    let expected = ErrorReason::Object_Not_Found.to_string();
    assert!(
        err_str.contains(&expected),
        "Expected Object_Not_Found in error, got: {err_str}"
    );
    Ok(())
}
