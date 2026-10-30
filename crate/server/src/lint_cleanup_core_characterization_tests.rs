//! Characterization tests pinning BASE behavior of `core/**`, `lib.rs`, `start_kms_server.rs`, `openssl_providers.rs`.

use std::sync::Arc;

use cosmian_kms_interfaces::HsmStore;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, RevocationReason, RevocationReasonCode, State},
        kmip_2_1::{
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_data_structures::{KeyValue, KeyWrappingSpecification},
            kmip_operations::{Destroy, Revoke},
            kmip_types::{
                CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation, RecommendedCurve,
                UniqueIdentifier, WrappingMethod,
            },
            requests::{create_ec_key_pair_request, symmetric_key_create_request},
        },
    },
    cosmian_kms_crypto::crypto::wrap::unwrap_key_block,
};
use time::OffsetDateTime;

use crate::{
    core::{
        KMS,
        certificate::validate_crl_url,
        wrapping::{unwrap_object, wrap_object},
    },
    error::KmsError,
    middlewares::UserId,
    start_kms_server::prepare_kms_server,
    tests::test_utils::{https_clap_config, test_kms},
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn reason(code: RevocationReasonCode, message: Option<&str>) -> RevocationReason {
    RevocationReason {
        revocation_reason_code: code,
        revocation_message: message.map(str::to_owned),
    }
}

fn compromise_date() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
}

async fn create_aes_key(kms: &KMS, user: &UserId, tags: &[&str]) -> String {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        tags,
        false,
        None,
    )
    .unwrap();
    kms.create(request, user)
        .await
        .unwrap()
        .unique_identifier
        .to_string()
}

/// Returns `(private_key_uid, public_key_uid)` of a new EC P-256 key pair.
async fn create_ec_pair(kms: &KMS, user: &UserId) -> (String, String) {
    let request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )
    .unwrap();
    let response = kms.create_key_pair(request, user).await.unwrap();
    (
        response.private_key_unique_identifier.to_string(),
        response.public_key_unique_identifier.to_string(),
    )
}

async fn revoke(
    kms: &KMS,
    user: &UserId,
    uid: &str,
    reason: RevocationReason,
    compromise_occurrence_date: Option<OffsetDateTime>,
    cascade: bool,
) -> Result<UniqueIdentifier, KmsError> {
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            revocation_reason: reason,
            compromise_occurrence_date,
            cascade,
        },
        user,
    )
    .await
    .map(|response| response.unique_identifier)
}

/// Observable revocation state of an object, both as stored in the "external" attributes
/// and in the attributes embedded in the object itself.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    state: State,
    external_reason: Option<RevocationReason>,
    embedded_reason: Option<RevocationReason>,
    external_compromise_date: Option<OffsetDateTime>,
    embedded_compromise_date: Option<OffsetDateTime>,
    external_deactivation_date: bool,
    embedded_deactivation_date: bool,
}

async fn snapshot(kms: &KMS, uid: &str) -> Snapshot {
    let owm = kms.database.retrieve_object(uid).await.unwrap().unwrap();
    let embedded = owm.object().attributes().ok();
    Snapshot {
        state: owm.state(),
        external_reason: owm.attributes().revocation_reason.clone(),
        embedded_reason: embedded.and_then(|a| a.revocation_reason.clone()),
        external_compromise_date: owm.attributes().compromise_occurrence_date,
        embedded_compromise_date: embedded.and_then(|a| a.compromise_occurrence_date),
        external_deactivation_date: owm.attributes().deactivation_date.is_some(),
        embedded_deactivation_date: embedded.is_some_and(|a| a.deactivation_date.is_some()),
    }
}

async fn state_of(kms: &KMS, uid: &str) -> State {
    kms.database
        .retrieve_object(uid)
        .await
        .unwrap()
        .unwrap()
        .state()
}

// ── revoke: reason code -> state, persisted attributes ───────────────────────

#[tokio::test]
async fn characterization_revoke_state_for_each_reason_code() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_revoke_reason");
    let cases = [
        (RevocationReasonCode::Unspecified, State::Deactivated),
        (RevocationReasonCode::KeyCompromise, State::Compromised),
        (RevocationReasonCode::CACompromise, State::Compromised),
        (RevocationReasonCode::AffiliationChanged, State::Deactivated),
        (RevocationReasonCode::Superseded, State::Deactivated),
        (
            RevocationReasonCode::CessationOfOperation,
            State::Deactivated,
        ),
        (RevocationReasonCode::PrivilegeWithdrawn, State::Deactivated),
        (RevocationReasonCode::CertificateHold, State::Deactivated),
        (RevocationReasonCode::RemoveFromCRL, State::Deactivated),
        (RevocationReasonCode::AaCompromise, State::Deactivated),
    ];
    for (code, expected_state) in cases {
        let uid = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
        assert_eq!(state_of(&kms, &uid).await, State::Active);
        // A compromise occurrence date is only accepted with a compromise reason.
        let compromised = expected_state == State::Compromised;
        let date = compromised.then(compromise_date);
        let returned = revoke(
            &kms,
            &user,
            &uid,
            reason(code, Some("characterization")),
            date,
            false,
        )
        .await
        .unwrap();
        assert_eq!(returned, UniqueIdentifier::TextString(uid.clone()));
        let expected_reason = Some(reason(code, Some("characterization")));
        assert_eq!(
            snapshot(&kms, &uid).await,
            Snapshot {
                state: expected_state,
                external_reason: expected_reason.clone(),
                embedded_reason: expected_reason,
                external_compromise_date: date,
                embedded_compromise_date: date,
                external_deactivation_date: !compromised,
                embedded_deactivation_date: !compromised,
            },
            "reason code {code:?}"
        );
    }
}

#[tokio::test]
async fn characterization_revoke_without_compromise_date_leaves_it_unset() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_revoke_no_date");
    let uid = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    revoke(
        &kms,
        &user,
        &uid,
        reason(RevocationReasonCode::Superseded, None),
        None,
        false,
    )
    .await
    .unwrap();
    let snap = snapshot(&kms, &uid).await;
    assert_eq!(snap.state, State::Deactivated);
    assert_eq!(snap.external_compromise_date, None);
    assert_eq!(snap.embedded_compromise_date, None);
    assert_eq!(
        snap.external_reason,
        Some(reason(RevocationReasonCode::Superseded, None))
    );
}

#[tokio::test]
async fn characterization_revoke_state_transitions_of_already_revoked_keys() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_revoke_transitions");
    let uid = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;

    revoke(
        &kms,
        &user,
        &uid,
        reason(RevocationReasonCode::Unspecified, Some("first")),
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(state_of(&kms, &uid).await, State::Deactivated);

    // Deactivated + non-compromise reason: no-op success, first reason is kept.
    revoke(
        &kms,
        &user,
        &uid,
        reason(RevocationReasonCode::Superseded, Some("second")),
        None,
        false,
    )
    .await
    .unwrap();
    let snap = snapshot(&kms, &uid).await;
    assert_eq!(snap.state, State::Deactivated);
    assert_eq!(
        snap.external_reason,
        Some(reason(RevocationReasonCode::Unspecified, Some("first")))
    );

    // Deactivated + compromise reason: transition to Compromised, reason replaced.
    revoke(
        &kms,
        &user,
        &uid,
        reason(RevocationReasonCode::KeyCompromise, Some("third")),
        Some(compromise_date()),
        false,
    )
    .await
    .unwrap();
    let snap = snapshot(&kms, &uid).await;
    assert_eq!(snap.state, State::Compromised);
    assert_eq!(
        snap.external_reason,
        Some(reason(RevocationReasonCode::KeyCompromise, Some("third")))
    );
    assert_eq!(snap.external_compromise_date, Some(compromise_date()));

    // Compromised keys cannot be revoked again.
    let err = revoke(
        &kms,
        &user,
        &uid,
        reason(RevocationReasonCode::KeyCompromise, None),
        None,
        false,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Wrong_Key_Lifecycle_State, _)
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn characterization_revoke_destroyed_key_with_compromise_becomes_destroyed_compromised() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_revoke_destroyed");
    let uid = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    revoke(
        &kms,
        &user,
        &uid,
        reason(RevocationReasonCode::CessationOfOperation, None),
        None,
        false,
    )
    .await
    .unwrap();
    kms.destroy(
        Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            remove: false,
            cascade: false,
            expected_object_type: None,
        },
        &user,
    )
    .await
    .unwrap();
    assert_eq!(state_of(&kms, &uid).await, State::Destroyed);
    revoke(
        &kms,
        &user,
        &uid,
        reason(RevocationReasonCode::KeyCompromise, None),
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(state_of(&kms, &uid).await, State::Destroyed_Compromised);
}

#[tokio::test]
async fn characterization_revoke_unknown_and_foreign_keys_are_not_found() {
    let kms = test_kms().await.unwrap();
    let owner = UserId::from("char_revoke_owner");
    let other = UserId::from("char_revoke_other");
    let err = revoke(
        &kms,
        &owner,
        "characterization-unknown-uid",
        reason(RevocationReasonCode::Unspecified, None),
        None,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "Object_Not_Found: characterization-unknown-uid"
    );

    let uid = create_aes_key(&kms, &owner, EMPTY_TAGS.as_slice()).await;
    let err = revoke(
        &kms,
        &other,
        &uid,
        reason(RevocationReasonCode::Unspecified, None),
        None,
        false,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, KmsError::Kmip21Error(ErrorReason::Object_Not_Found, _)),
        "{err:?}"
    );
    assert_eq!(state_of(&kms, &uid).await, State::Active);
}

#[tokio::test]
async fn characterization_revoke_by_tags_revokes_every_tagged_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_revoke_tags");
    let tag = "characterization_revoke_tag";
    let first = create_aes_key(&kms, &user, &[tag]).await;
    let second = create_aes_key(&kms, &user, &[tag]).await;
    let untagged = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    revoke(
        &kms,
        &user,
        &format!("[\"{tag}\"]"),
        reason(RevocationReasonCode::KeyCompromise, None),
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(state_of(&kms, &first).await, State::Compromised);
    assert_eq!(state_of(&kms, &second).await, State::Compromised);
    assert_eq!(state_of(&kms, &untagged).await, State::Active);
}

// ── revoke: linked key cascade ───────────────────────────────────────────────

#[tokio::test]
async fn characterization_revoke_private_key_without_cascade_keeps_public_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_cascade_off");
    let (sk, pk) = create_ec_pair(&kms, &user).await;
    revoke(
        &kms,
        &user,
        &sk,
        reason(RevocationReasonCode::Unspecified, None),
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(state_of(&kms, &sk).await, State::Deactivated);
    assert_eq!(state_of(&kms, &pk).await, State::Active);
}

#[tokio::test]
async fn characterization_revoke_private_key_with_cascade_revokes_public_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_cascade_private");
    let (sk, pk) = create_ec_pair(&kms, &user).await;
    revoke(
        &kms,
        &user,
        &sk,
        reason(RevocationReasonCode::KeyCompromise, Some("cascade")),
        Some(compromise_date()),
        true,
    )
    .await
    .unwrap();
    for uid in [&sk, &pk] {
        let snap = snapshot(&kms, uid).await;
        assert_eq!(snap.state, State::Compromised, "{uid}");
        assert_eq!(
            snap.external_reason,
            Some(reason(RevocationReasonCode::KeyCompromise, Some("cascade")))
        );
        assert_eq!(snap.external_compromise_date, Some(compromise_date()));
        assert!(!snap.external_deactivation_date);
    }
}

#[tokio::test]
async fn characterization_revoke_public_key_with_cascade_revokes_private_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_cascade_public");
    let (sk, pk) = create_ec_pair(&kms, &user).await;
    revoke(
        &kms,
        &user,
        &pk,
        reason(RevocationReasonCode::Superseded, None),
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(state_of(&kms, &sk).await, State::Deactivated);
    assert_eq!(state_of(&kms, &pk).await, State::Deactivated);
}

#[tokio::test]
async fn characterization_revoke_public_key_without_cascade_keeps_private_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_cascade_public_off");
    let (sk, pk) = create_ec_pair(&kms, &user).await;
    revoke(
        &kms,
        &user,
        &pk,
        reason(RevocationReasonCode::Superseded, None),
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(state_of(&kms, &sk).await, State::Active);
    assert_eq!(state_of(&kms, &pk).await, State::Deactivated);
}

// ── revoke: HSM-prefixed identifiers ─────────────────────────────────────────

mod hsm_stub {
    use std::collections::HashSet;

    use async_trait::async_trait;
    use cosmian_kms_interfaces::{
        CryptoAlgorithm, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeyPairIds,
        HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, InterfaceError, InterfaceResult,
        KeyMetadata, KeyType, SigningAlgorithm, SigningKeyMetadata,
    };
    use zeroize::Zeroizing;

    /// An `HSM` whose every operation is "not supported": only the routing/ownership
    /// logic of `HsmStore` and the revoke handler is exercised.
    pub(super) struct StubHsm;

    fn stub<T>() -> InterfaceResult<T> {
        Err(InterfaceError::NotSupported("stub".to_owned()))
    }

    #[async_trait]
    impl HSM for StubHsm {
        async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>> {
            stub()
        }

        async fn get_supported_algorithms(
            &self,
            _slot_id: usize,
        ) -> InterfaceResult<Vec<CryptoAlgorithm>> {
            stub()
        }

        async fn create_key<'a>(
            &'a self,
            _slot_id: usize,
            _id: &'a [u8],
            _algorithm: HsmKeyAlgorithm,
            _key_length_in_bits: usize,
            _sensitive: bool,
            _tags: &'a HashSet<String>,
        ) -> InterfaceResult<()> {
            stub()
        }

        async fn create_keypair<'a>(
            &'a self,
            _slot_id: usize,
            _ids: HsmKeyPairIds<'a>,
            _algorithm: HsmKeypairAlgorithm,
            _key_length_in_bits: usize,
            _sensitive: bool,
            _tags: &'a HashSet<String>,
        ) -> InterfaceResult<()> {
            stub()
        }

        async fn export(
            &self,
            _slot_id: usize,
            _object_id: &[u8],
        ) -> InterfaceResult<Option<HsmObject>> {
            stub()
        }

        async fn delete(&self, _slot_id: usize, _object_id: &[u8]) -> InterfaceResult<()> {
            stub()
        }

        async fn find(
            &self,
            _slot_id: usize,
            _object_filter: HsmObjectFilter,
        ) -> InterfaceResult<Vec<Vec<u8>>> {
            stub()
        }

        async fn encrypt<'a>(
            &'a self,
            _slot_id: usize,
            _key_id: &'a [u8],
            _algorithm: CryptoAlgorithm,
            _data: &'a [u8],
            _iv_counter_nonce: &'a [u8],
        ) -> InterfaceResult<EncryptedContent> {
            stub()
        }

        async fn decrypt(
            &self,
            _slot_id: usize,
            _key_id: &[u8],
            _algorithm: CryptoAlgorithm,
            _data: &[u8],
        ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
            stub()
        }

        async fn get_key_type(
            &self,
            _slot_id: usize,
            _key_id: &[u8],
        ) -> InterfaceResult<Option<KeyType>> {
            stub()
        }

        async fn get_key_metadata(
            &self,
            _slot_id: usize,
            _key_id: &[u8],
        ) -> InterfaceResult<Option<KeyMetadata>> {
            stub()
        }

        async fn sign_with_metadata(
            &self,
            _slot_id: usize,
            _key_id: &[u8],
            _resolve_algorithm: Box<
                dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                    + Send
                    + Sync
                    + 'static,
            >,
            _data: &[u8],
        ) -> InterfaceResult<Vec<u8>> {
            stub()
        }

        async fn verify_with_metadata(
            &self,
            _slot_id: usize,
            _key_id: &[u8],
            _resolve_algorithm: Box<
                dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                    + Send
                    + Sync
                    + 'static,
            >,
            _data: &[u8],
            _signature: &[u8],
        ) -> InterfaceResult<bool> {
            stub()
        }

        async fn generate_random(&self, _slot_id: usize, _len: usize) -> InterfaceResult<Vec<u8>> {
            stub()
        }

        async fn seed_random(&self, _slot_id: usize, _seed: &[u8]) -> InterfaceResult<()> {
            stub()
        }

        async fn set_key_dates(
            &self,
            _slot_id: usize,
            _key_id: &[u8],
            _start_date: Option<time::Date>,
            _end_date: Option<time::Date>,
        ) -> InterfaceResult<()> {
            stub()
        }

        async fn set_key_label(
            &self,
            _slot_id: usize,
            _key_id: &[u8],
            _label: &str,
        ) -> InterfaceResult<()> {
            stub()
        }

        fn hsm_lib(&self) -> Option<&dyn std::any::Any> {
            None
        }
    }
}

#[tokio::test]
async fn characterization_revoke_hsm_prefixed_uid_admin_is_not_supported() {
    let kms = test_kms().await.unwrap();
    let admin = UserId::from("char_hsm_admin");
    let store = HsmStore::new(
        Arc::new(hsm_stub::StubHsm),
        &["char_hsm_admin".to_owned()],
        VENDOR_ID_COSMIAN,
        "hsm",
    );
    kms.database
        .register_objects_store("hsm", Arc::new(store))
        .await;
    // HSM objects cannot change state: the admin owns them, the state update is rejected.
    for code in [
        RevocationReasonCode::KeyCompromise,
        RevocationReasonCode::Unspecified,
    ] {
        let err = revoke(
            &kms,
            &admin,
            "hsm::0::characterization-key",
            reason(code, None),
            None,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Not Supported: Objects with prefix 'hsm' cannot be revoked. Destroy them directly.",
            "{code:?}"
        );
    }
}

#[tokio::test]
async fn characterization_revoke_hsm_prefixed_uid_non_admin_is_not_found() {
    let kms = test_kms().await.unwrap();
    let other = UserId::from("char_hsm_other");
    let store = HsmStore::new(
        Arc::new(hsm_stub::StubHsm),
        &["char_hsm_admin".to_owned()],
        VENDOR_ID_COSMIAN,
        "hsm",
    );
    kms.database
        .register_objects_store("hsm", Arc::new(store))
        .await;
    let err = revoke(
        &kms,
        &other,
        "hsm::0::characterization-key",
        reason(RevocationReasonCode::KeyCompromise, None),
        None,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "Object_Not_Found: hsm::0::characterization-key"
    );
}
// ── permissions ──────────────────────────────────────────────────────────────

#[test]
fn characterization_reject_protection_storage_masks() {
    KMS::reject_protection_storage_masks(false).unwrap();
    let err = KMS::reject_protection_storage_masks(true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "This KMIP server does not yet support protection masks"
    );
}

// ── CRL distribution point URL validation ────────────────────────────────────

#[test]
fn characterization_validate_crl_url_accepts_public_hosts() {
    for url in [
        "https://kacls.example.com/v1",
        "http://crl.example.com/ca.crl",
        "https://local",
        "https://notlocal",
        "https://foo.localhost",
        "https://foo.local.example.com",
        "https://internal.example.com",
        "https://8.8.8.8/crl",
        "https://[2001:db8::1]/crl",
    ] {
        validate_crl_url(url).unwrap();
    }
}

#[test]
fn characterization_validate_crl_url_rejects_internal_hostnames() {
    for url in [
        "https://localhost",
        "https://LOCALHOST/crl",
        "https://foo.local",
        "https://foo.LOCAL",
        "https://svc.cluster.local",
        "https://x.local:8443/crl",
        "https://a.b.internal",
        "https://FOO.INTERNAL/crl",
        "https://metadata.google.internal",
    ] {
        let err = validate_crl_url(url).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Certificate error: CRL Distribution Point URL must not target internal or cloud-metadata hostnames",
            "{url}"
        );
    }
}

#[test]
fn characterization_validate_crl_url_rejects_private_addresses() {
    for url in [
        "http://127.0.0.1:8765/crl",
        "http://10.0.0.1/crl",
        "http://172.16.0.1/crl",
        "http://192.168.1.1/crl",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/crl",
        "http://[::1]/crl",
        "http://[::]/crl",
        "http://[fc00::1]/crl",
        "http://[fe80::1]/crl",
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:10.0.0.1]/",
    ] {
        let err = validate_crl_url(url).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Certificate error: CRL Distribution Point URL must not target private, loopback, or link-local addresses",
            "{url}"
        );
    }
}

#[test]
fn characterization_validate_crl_url_rejects_bad_scheme_and_syntax() {
    let scheme =
        "Certificate error: CRL Distribution Point URL must use http or https scheme, got: ";
    assert_eq!(
        validate_crl_url("ftp://example.com/crl")
            .unwrap_err()
            .to_string(),
        format!("{scheme}ftp")
    );
    assert_eq!(
        validate_crl_url("file:///etc/passwd")
            .unwrap_err()
            .to_string(),
        format!("{scheme}file")
    );
    assert_eq!(
        validate_crl_url("mailto:a@b.c").unwrap_err().to_string(),
        format!("{scheme}mailto")
    );
    assert_eq!(
        validate_crl_url("not a url").unwrap_err().to_string(),
        "Certificate error: Invalid CRL Distribution Point URL: relative URL without a base"
    );
}

// ── wrapping: wrapping key that is itself wrapped ────────────────────────────

async fn create_wrapped_aes_key(kms: &KMS, user: &UserId, wrapping_key_id: &str) -> String {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        Some(&wrapping_key_id.to_owned()),
    )
    .unwrap();
    kms.create(request, user)
        .await
        .unwrap()
        .unique_identifier
        .to_string()
}

fn wrapping_spec(wrapping_key_id: &str) -> KeyWrappingSpecification {
    KeyWrappingSpecification {
        wrapping_method: WrappingMethod::Encrypt,
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_id.to_owned()),
            cryptographic_parameters: None,
        }),
        encoding_option: Some(EncodingOption::NoEncoding),
        ..KeyWrappingSpecification::default()
    }
}

#[tokio::test]
async fn characterization_wrap_object_with_wrapping_key_that_is_itself_wrapped() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_wrap_chain");

    // root key W (plain) -> K1 (wrapped by W) -> wrap an arbitrary key with K1
    let root = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    let wrapping = create_wrapped_aes_key(&kms, &user, &root).await;
    let stored = kms
        .database
        .retrieve_object(&wrapping)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.object().is_wrapped());

    // a key with known bytes to wrap
    let target_uid = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    let target = kms
        .database
        .retrieve_object(&target_uid)
        .await
        .unwrap()
        .unwrap();
    let plain_bytes = target
        .object()
        .key_block()
        .unwrap()
        .key_bytes()
        .unwrap()
        .to_vec();
    assert_eq!(plain_bytes.len(), 32);

    let mut object = target.object().clone();
    wrap_object(&mut object, &wrapping_spec(&wrapping), &kms, &user)
        .await
        .unwrap();
    assert!(object.is_wrapped());
    let key_block = object.key_block().unwrap();
    let wrapping_data = key_block.key_wrapping_data.as_ref().unwrap();
    assert_eq!(
        wrapping_data
            .encryption_key_information
            .as_ref()
            .unwrap()
            .unique_identifier,
        UniqueIdentifier::TextString(wrapping.clone())
    );
    assert_eq!(
        wrapping_data.encoding_option,
        Some(EncodingOption::NoEncoding)
    );

    // RFC 3394 AES key wrap of 32 bytes => 40 bytes
    assert!(matches!(
        key_block.key_value.as_ref(),
        Some(KeyValue::ByteString(wrapped_bytes)) if wrapped_bytes.len() == 40
    ));

    // the wrapped bytes decrypt (with the plain version of K1) back to the original key
    let mut plain_wrapping = stored.object().clone();
    unwrap_object(&mut plain_wrapping, &kms, &user)
        .await
        .unwrap();
    assert!(!plain_wrapping.is_wrapped());
    // the unwrapped wrapping key is a key-value structure WITHOUT embedded attributes: this is
    // the situation in which `wrap_using_kms` re-attaches the database attributes.
    assert!(matches!(
        plain_wrapping.key_block().unwrap().key_value.as_ref(),
        Some(KeyValue::Structure {
            attributes: None,
            ..
        })
    ));
    // re-attach the database attributes, as `wrap_using_kms` does, so that the crypto layer can
    // check the usage mask
    if let Some(KeyValue::Structure { attributes, .. }) =
        &mut plain_wrapping.key_block_mut().unwrap().key_value
    {
        *attributes = Some(stored.attributes().clone());
    }
    let mut wrapped_block = key_block.clone();
    unwrap_key_block(&mut wrapped_block, &plain_wrapping).unwrap();
    assert_eq!(wrapped_block.key_bytes().unwrap().to_vec(), plain_bytes);
}

#[tokio::test]
async fn characterization_wrap_object_inactive_wrapping_key_is_rejected() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("char_wrap_inactive");
    let wrapping = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    revoke(
        &kms,
        &user,
        &wrapping,
        reason(RevocationReasonCode::Unspecified, None),
        None,
        false,
    )
    .await
    .unwrap();
    let target_uid = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    let mut object = kms
        .database
        .retrieve_object(&target_uid)
        .await
        .unwrap()
        .unwrap()
        .object()
        .clone();
    let err = wrap_object(&mut object, &wrapping_spec(&wrapping), &kms, &user)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("Not Supported: The wrapping key {wrapping} is not active")
    );
    assert!(!object.is_wrapped());
}

// ── KMS::instantiate: unwrapped cache parameters ─────────────────────────────

async fn unwrapped_cache_holds_wrapped_key(disable_unwrapped_cache: bool) -> bool {
    let mut conf = https_clap_config();
    conf.db.disable_unwrapped_cache = disable_unwrapped_cache;
    let kms = crate::tests::test_utils::test_kms_with_config(conf)
        .await
        .unwrap();
    let user = UserId::from("char_cache_params");
    let root = create_aes_key(&kms, &user, EMPTY_TAGS.as_slice()).await;
    let wrapped = create_wrapped_aes_key(&kms, &user, &root).await;
    let stored = kms
        .database
        .retrieve_object(&wrapped)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.object().is_wrapped());
    let from_cache = kms
        .database
        .unwrapped_cache()
        .peek(&wrapped, stored.object())
        .await
        .unwrap();
    // `get_unwrapped` must succeed whatever the cache configuration is.
    let unwrapped = Box::pin(kms.get_unwrapped(&wrapped, stored.object(), &user))
        .await
        .unwrap();
    assert!(!unwrapped.is_wrapped());
    if let Some(cached) = &from_cache {
        assert_eq!(cached, &unwrapped);
    }
    from_cache.is_some()
}

#[tokio::test]
async fn characterization_instantiate_unwrapped_cache_enabled_by_default() {
    assert!(Box::pin(unwrapped_cache_holds_wrapped_key(false)).await);
}

#[tokio::test]
async fn characterization_instantiate_unwrapped_cache_can_be_disabled() {
    assert!(!Box::pin(unwrapped_cache_holds_wrapped_key(true)).await);
}

// ── OpenSSL provider diagnostics ─────────────────────────────────────────────

#[test]
fn characterization_safe_openssl_version_info_reports_bundled_openssl() {
    let (version, built_on, number) = crate::openssl_providers::safe_openssl_version_info();
    // The linked OpenSSL depends on the build flavour and platform (3.6.2 locally, the 3.1.2 FIPS
    // build on some CI runners): only the OpenSSL 3 family is pinned.
    assert!(version.starts_with("OpenSSL 3."), "{version}");
    assert!(built_on.starts_with("OPENSSLDIR: \""), "{built_on}");
    assert_eq!(number >> 28, 3, "{number:#x}");
}

#[test]
fn characterization_cpu_features_info_prefix() {
    let info = crate::openssl_providers::cpu_features_info();
    assert!(info.starts_with("OpenSSL CPU features ("), "{info}");
}

// ── Covercrypt: revocation of user decryption keys (non-fips) ────────────────

#[cfg(feature = "non-fips")]
mod covercrypt_revoke {
    use std::collections::HashSet;

    use cosmian_kms_client_utils::cover_crypt_utils::{
        build_create_covercrypt_master_keypair_request, build_create_covercrypt_usk_request,
    };
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReasonCode, State},
        kmip_2_1::extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    };

    use super::{compromise_date, reason, revoke, snapshot, state_of};
    use crate::{
        core::{KMS, cover_crypt::revoke_user_decryption_keys},
        middlewares::UserId,
        tests::test_utils::test_kms,
    };

    const ACCESS_STRUCTURE: &str = r#"{"Security Level::<":["Protected","Confidential","Top Secret::+"],"Department":["RnD","HR","MKG","FIN"]}"#;

    struct Fixture {
        msk: String,
        mpk: String,
        usks: Vec<String>,
    }

    async fn fixture(kms: &KMS, user: &UserId) -> Fixture {
        let request = build_create_covercrypt_master_keypair_request(
            VENDOR_ID_COSMIAN,
            ACCESS_STRUCTURE,
            EMPTY_TAGS,
            false,
            None,
        )
        .unwrap();
        let pair = kms.create_key_pair(request, user).await.unwrap();
        let msk = pair.private_key_unique_identifier.to_string();
        let mpk = pair.public_key_unique_identifier.to_string();
        let mut usks = Vec::new();
        for policy in [
            "Department::MKG && Security Level::Top Secret",
            "Department::FIN && Security Level::Confidential",
            "Department::HR && Security Level::Protected",
        ] {
            let request = build_create_covercrypt_usk_request(
                VENDOR_ID_COSMIAN,
                policy,
                &msk,
                EMPTY_TAGS,
                false,
                None,
            )
            .unwrap();
            usks.push(
                kms.create(request, user)
                    .await
                    .unwrap()
                    .unique_identifier
                    .to_string(),
            );
        }
        Fixture { msk, mpk, usks }
    }

    #[tokio::test]
    async fn characterization_revoke_master_secret_key_revokes_user_decryption_keys() {
        let kms = test_kms().await.unwrap();
        let user = UserId::from("char_cc_revoke");
        let fx = fixture(&kms, &user).await;
        revoke(
            &kms,
            &user,
            &fx.msk,
            reason(RevocationReasonCode::Superseded, Some("cc")),
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(state_of(&kms, &fx.msk).await, State::Deactivated);
        for usk in &fx.usks {
            let snap = snapshot(&kms, usk).await;
            assert_eq!(snap.state, State::Deactivated, "{usk}");
            assert_eq!(
                snap.external_reason,
                Some(reason(RevocationReasonCode::Superseded, Some("cc")))
            );
        }
        // no cascade: the master public key is untouched
        assert_eq!(state_of(&kms, &fx.mpk).await, State::Active);
    }

    #[tokio::test]
    async fn characterization_revoke_master_secret_key_with_compromise_and_cascade() {
        let kms = test_kms().await.unwrap();
        let user = UserId::from("char_cc_compromise");
        let fx = fixture(&kms, &user).await;
        revoke(
            &kms,
            &user,
            &fx.msk,
            reason(RevocationReasonCode::KeyCompromise, Some("cc compromise")),
            Some(compromise_date()),
            true,
        )
        .await
        .unwrap();
        let mut all = fx.usks.clone();
        all.push(fx.msk.clone());
        all.push(fx.mpk.clone());
        for uid in &all {
            let snap = snapshot(&kms, uid).await;
            assert_eq!(snap.state, State::Compromised, "{uid}");
            assert_eq!(
                snap.external_reason,
                Some(reason(
                    RevocationReasonCode::KeyCompromise,
                    Some("cc compromise")
                )),
                "{uid}"
            );
            assert_eq!(
                snap.external_compromise_date,
                Some(compromise_date()),
                "{uid}"
            );
        }
    }

    #[tokio::test]
    async fn characterization_revoke_user_decryption_keys_honours_ids_to_skip() {
        let kms = test_kms().await.unwrap();
        let user = UserId::from("char_cc_skip");
        let fx = fixture(&kms, &user).await;
        let skipped = fx.usks.first().unwrap().clone();
        revoke_user_decryption_keys(
            &fx.msk,
            reason(RevocationReasonCode::KeyCompromise, Some("skip")),
            Some(compromise_date()),
            &kms,
            &user,
            HashSet::from([skipped.clone()]),
        )
        .await
        .unwrap();
        assert_eq!(state_of(&kms, &skipped).await, State::Active);
        for usk in fx.usks.iter().filter(|usk| **usk != skipped) {
            let snap = snapshot(&kms, usk).await;
            assert_eq!(snap.state, State::Compromised, "{usk}");
            assert_eq!(
                snap.external_reason,
                Some(reason(RevocationReasonCode::KeyCompromise, Some("skip")))
            );
            assert_eq!(snap.external_compromise_date, Some(compromise_date()));
        }
        // the master keys are not touched by this helper
        assert_eq!(state_of(&kms, &fx.msk).await, State::Active);
        assert_eq!(state_of(&kms, &fx.mpk).await, State::Active);
    }

    #[tokio::test]
    async fn characterization_revoke_user_decryption_keys_only_revokes_active_keys() {
        let kms = test_kms().await.unwrap();
        let user = UserId::from("char_cc_active_only");
        let fx = fixture(&kms, &user).await;
        let first = fx.usks.first().unwrap().clone();
        revoke(
            &kms,
            &user,
            &first,
            reason(RevocationReasonCode::Unspecified, Some("already")),
            None,
            false,
        )
        .await
        .unwrap();
        revoke_user_decryption_keys(
            &fx.msk,
            reason(RevocationReasonCode::KeyCompromise, Some("later")),
            None,
            &kms,
            &user,
            HashSet::new(),
        )
        .await
        .unwrap();
        // already deactivated key is not located (only Active keys are) => reason kept
        let snap = snapshot(&kms, &first).await;
        assert_eq!(snap.state, State::Deactivated);
        assert_eq!(
            snap.external_reason,
            Some(reason(RevocationReasonCode::Unspecified, Some("already")))
        );
        for usk in fx.usks.iter().filter(|usk| **usk != first) {
            assert_eq!(state_of(&kms, usk).await, State::Compromised, "{usk}");
        }
    }
}

/// `prepare_kms_server` only builds the actix server; the Vault auth verifier is contacted per
/// request, so an unreachable URL is accepted at startup.
#[tokio::test]
async fn characterization_prepare_kms_server_with_vault_auth_verifier_url() {
    let mut config = https_clap_config();
    config.vault.vault_api_enabled = true;
    config.vault.vault_auth_verifier_url = Some("http://127.0.0.1:1".to_owned());
    let kms = crate::tests::test_utils::test_kms_with_config(config)
        .await
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let server = Box::pin(prepare_kms_server(kms, Some(listener)))
        .await
        .unwrap();
    drop(server);
}
