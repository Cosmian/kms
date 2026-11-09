//! SQL-backed symmetric key rotation (KMIP `ReKey` §6.1.46).
//!
//! This module handles `ReKey` for keys stored in the SQL database — generates fresh
//! key material, manages wrapping/unwrapping, links generations, and retires old keys.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_operations::{Create, ReKey, ReKeyResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use super::super::common::{
    RekeyOperation, ReplacementObject, RotationCandidate, reject_hsm_uid, rekey_state_error,
};
use crate::{
    core::{KMS, operations::key_ops::KeySelectionSpec, uid_utils::from_request},
    middlewares::UserId,
    result::KResult,
};

/// Implementor of [`RekeyOperation`] for KMIP `ReKey` (KMIP 2.1 §6.1.46) on SQL-backed
/// symmetric keys.
pub(in crate::core::operations::rekey) struct SqlSymmetricRekeyer {
    /// The `Offset` from the `ReKey` request — an interval added to the new key's
    /// `Initial Date` to compute its `Activation Date` (KMIP 2.1 §6.1.46 Table 305).
    pub offset: Option<i64>,
    /// Desired attributes of the replacement key (KMIP 2.1 Table 305).
    pub attributes: Option<Attributes>,
}

impl KeySelectionSpec for SqlSymmetricRekeyer {
    const KMIP_OP: KmipOperation = KmipOperation::Rekey;
    const OP_NAME: &'static str = "ReKey";

    fn accepted_states() -> &'static [State] {
        &[State::Active, State::Deactivated, State::Compromised]
    }

    fn strict_permission_check() -> bool {
        true
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        owm.object().object_type() == ObjectType::SymmetricKey
    }
}

impl RekeyOperation for SqlSymmetricRekeyer {
    type Candidates = [RotationCandidate; 1];
    type Replacements = [ReplacementObject; 1];
    type Request = ReKey;
    type Response = ReKeyResponse;

    async fn validate(
        &self,
        kms: &KMS,
        request: &ReKey,
        user: &UserId,
    ) -> KResult<[RotationCandidate; 1]> {
        KMS::reject_protection_storage_masks(request.protection_storage_masks.is_some())?;

        kms.enforce_create_permission(user).await?;

        let object_handle = from_request(request.unique_identifier.as_ref(), "ReKey")?;

        // HSM-managed keys cannot be re-keyed via the SQL pipeline: they have no KMIP
        // attribute storage and are often non-extractable (CKA_EXTRACTABLE = false).
        reject_hsm_uid(object_handle, "Re-Key")?;

        let candidates = kms
            .retrieve_eligible_keys(object_handle, ObjectType::SymmetricKey)
            .await?;

        let owm = kms
            .select_unique_key::<Self, _>(candidates, object_handle.as_str(), user, |owm| {
                // Reject requests that attempt to change crypto parameters
                owm.attributes()
                    .validate_no_crypto_param_change([request.attributes.as_ref()], "ReKey")?;
                Ok(())
            })
            .await
            .map_err(rekey_state_error)?;

        // Reject Re-Key on a retired (non-latest) member of a named keyset.
        kms.enforce_keyset_latest(owm.id(), owm.attributes(), user, "ReKey")
            .await?;

        let uid = owm.id().to_owned();
        Ok([RotationCandidate { owm, uid }])
    }

    fn generate_replacement(
        &self,
        kms: &KMS,
        _user: &UserId,
        candidates: &[RotationCandidate; 1],
    ) -> impl Future<Output = KResult<[ReplacementObject; 1]>> {
        // Key generation is synchronous CPU work: no suspension point is needed.
        std::future::ready(Self::build_replacement(kms, candidates))
    }

    fn prepare_attributes(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate; 1],
        replacements: &mut [ReplacementObject; 1],
    ) -> KResult<()> {
        let [candidate] = candidates;
        let [replacement] = replacements;

        let new_attrs = candidate
            .owm
            .attributes()
            .for_replacement(&candidate.uid, self.offset)?;

        replacement.finalize(
            &new_attrs,
            self.attributes.as_ref(),
            ObjectType::SymmetricKey,
            &candidate.uid,
            None,
            kms.vendor_id(),
        )?;

        // Preserve WrappingKeyLink if the old key was wrapped
        candidate
            .owm
            .object()
            .copy_wrapping_key_link_to(&mut replacement.attributes);

        // Set rotation metadata
        replacement
            .attributes
            .set_rotation_metadata_from(candidate.owm.attributes())?;

        // Rewrap dependants to the NEW key
        replacement.rewrap_to = Some(replacement.new_uid.clone());

        Ok(())
    }

    fn build_response(&self, replacements: &[ReplacementObject; 1]) -> ReKeyResponse {
        let [replacement] = replacements;
        ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(replacement.new_uid.clone()),
        }
    }
}

impl SqlSymmetricRekeyer {
    /// Generates the replacement key (synchronous CPU work).
    fn build_replacement(
        kms: &KMS,
        candidates: &[RotationCandidate; 1],
    ) -> KResult<[ReplacementObject; 1]> {
        let [candidate] = candidates;

        // Clean attributes for generation (removes identity, lifecycle dates, rotation metadata)
        let gen_attrs = candidate
            .owm
            .attributes()
            .clean_for_generation(kms.vendor_id());

        let create_request = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: gen_attrs,
            protection_storage_masks: None,
        };
        let (_, new_object, new_tags) = kms.create_symmetric_key_and_tags(&create_request)?;

        let new_uid = UniqueIdentifier::rotation_successor(
            candidate.owm.attributes().rotate_name.as_deref(),
            candidate.owm.attributes().rotate_generation,
        );

        Ok([ReplacementObject {
            new_uid,
            old_uid: candidate.uid.clone(),
            object: new_object,
            attributes: Attributes::default(), // filled in prepare_attributes
            tags: new_tags,
            rewrap_to: Some(candidate.uid.clone()), // placeholder, replaced in prepare_attributes
        }])
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::State,
            kmip_2_1::{
                extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
                kmip_attributes::Attributes,
                kmip_operations::{Decrypt, Encrypt, EncryptResponse, ReKey, ReKeyResponse},
                kmip_types::{
                    CryptographicAlgorithm, CryptographicParameters, LinkType, UniqueIdentifier,
                },
                requests::symmetric_key_create_request,
            },
        },
        cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
    };
    use zeroize::Zeroizing;

    use super::{RekeyOperation, ReplacementObject, RotationCandidate, SqlSymmetricRekeyer};
    use crate::{
        core::{KMS, operations::rekey::execute_rekey},
        error::KmsError,
        middlewares::UserId,
        result::KResult,
    };

    /// Rekeyer whose candidate is a snapshot taken before a concurrent write: it models a
    /// rotation that read the key, then lost the race to another writer.
    struct StaleCandidateRekeyer {
        inner: SqlSymmetricRekeyer,
        stale: ObjectWithMetadata,
        new_uid: std::sync::Mutex<Option<String>>,
        encrypt_before_finalize: bool,
        ciphertext: std::sync::Mutex<Option<EncryptResponse>>,
    }

    impl RekeyOperation for StaleCandidateRekeyer {
        type Candidates = [RotationCandidate; 1];
        type Replacements = [ReplacementObject; 1];
        type Request = ReKey;
        type Response = ReKeyResponse;

        fn validate(
            &self,
            _kms: &KMS,
            _request: &ReKey,
            _user: &UserId,
        ) -> impl Future<Output = KResult<[RotationCandidate; 1]>> {
            std::future::ready(Ok([RotationCandidate {
                owm: self.stale.clone(),
                uid: self.stale.id().to_owned(),
            }]))
        }

        async fn generate_replacement(
            &self,
            kms: &KMS,
            user: &UserId,
            candidates: &[RotationCandidate; 1],
        ) -> KResult<[ReplacementObject; 1]> {
            let replacements = self
                .inner
                .generate_replacement(kms, user, candidates)
                .await?;
            *self.new_uid.lock().expect("lock") = Some(replacements[0].new_uid.clone());
            Ok(replacements)
        }

        fn prepare_attributes(
            &self,
            kms: &KMS,
            candidates: &[RotationCandidate; 1],
            replacements: &mut [ReplacementObject; 1],
        ) -> KResult<()> {
            self.inner.prepare_attributes(kms, candidates, replacements)
        }

        async fn prepare_finalization(
            &self,
            kms: &KMS,
            user: &UserId,
            candidates: &[RotationCandidate; 1],
            replacements: &[ReplacementObject; 1],
        ) -> KResult<Vec<AtomicOperation>> {
            if self.encrypt_before_finalize {
                let [candidate] = candidates;
                let encrypted = kms
                    .encrypt(
                        Encrypt {
                            unique_identifier: Some(UniqueIdentifier::TextString(
                                candidate.uid.clone(),
                            )),
                            data: Some(Zeroizing::new(b"rotation race".to_vec())),
                            ..Encrypt::default()
                        },
                        user,
                    )
                    .await?;
                *self.ciphertext.lock().expect("ciphertext lock") = Some(encrypted);
                let mut attributes = candidate.owm.attributes().clone();
                attributes.rotate_offset = Some(42);
                kms.database
                    .atomic(
                        user,
                        &[AtomicOperation::UpdateObject((
                            candidate.uid.clone(),
                            candidate.owm.object().clone(),
                            attributes,
                            None,
                        ))],
                    )
                    .await?;
            }
            kms.default_prepare_finalization(user, candidates, replacements)
                .await
        }

        fn build_response(&self, replacements: &[ReplacementObject; 1]) -> ReKeyResponse {
            self.inner.build_response(replacements)
        }
    }

    /// A rotation whose candidate was overwritten after it was read must fail with
    /// `Conflict` from the atomic retirement, before its replacement is persisted, and leave
    /// the old key untouched and rotatable.
    ///
    /// Guards: Cosmian/kms#1006
    #[tokio::test]
    async fn rekey_with_stale_candidate_conflicts_without_orphan() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let user = UserId::from("stale_rekey_user@example.com");
        let request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )
        .map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
        let uid = kms
            .create(request, &user)
            .await?
            .unique_identifier
            .to_string();
        let rekey_request = || ReKey {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            ..ReKey::default()
        };

        let stale = kms
            .database
            .retrieve_object(&uid)
            .await?
            .expect("key must exist");
        assert!(stale.version().is_some());

        // the concurrent winner's write
        kms.database
            .atomic(
                &user,
                &[AtomicOperation::UpdateObject((
                    uid.clone(),
                    stale.object().clone(),
                    stale.attributes().clone(),
                    None,
                ))],
            )
            .await?;

        let rekeyer = StaleCandidateRekeyer {
            inner: SqlSymmetricRekeyer {
                offset: None,
                attributes: None::<Attributes>,
            },
            stale,
            new_uid: std::sync::Mutex::new(None),
            encrypt_before_finalize: false,
            ciphertext: std::sync::Mutex::new(None),
        };
        let err = execute_rekey(&rekeyer, &kms, &rekey_request(), &user)
            .await
            .expect_err("stale rotation must fail");
        assert!(matches!(err, KmsError::Conflict(_)), "{err:?}");

        let new_uid = rekeyer
            .new_uid
            .lock()
            .expect("lock")
            .clone()
            .expect("replacement was generated");
        assert!(kms.database.retrieve_object(&new_uid).await?.is_none());

        let old = kms
            .database
            .retrieve_object(&uid)
            .await?
            .expect("key must exist");
        assert!(
            old.attributes()
                .get_link(LinkType::ReplacementObjectLink)
                .is_none()
        );
        assert_eq!(old.state(), State::Active);

        kms.rekey(rekey_request(), &user).await?;
        Ok(())
    }

    /// Encryption concurrent with a failed rotation must never use a replacement
    /// that conflict cleanup can subsequently delete.
    #[tokio::test]
    async fn rotation_conflict_keeps_precommit_ciphertext_decryptable() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let user = UserId::from("publication_race@example.com");
        // A keyset name: UUIDs are never resolved as keyset references, so a UUID key would
        // not exercise the latest-generation lookup that Encrypt performs.
        let keyset = format!("publication-race-{}", uuid::Uuid::new_v4().simple());
        let request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(keyset.clone())),
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        let uid = kms
            .create(request, &user)
            .await?
            .unique_identifier
            .to_string();
        assert_eq!(uid, keyset);
        let mut original = kms.database.retrieve_object(&uid).await?.expect("source");
        original.attributes_mut().rotate_name = Some(uid.clone());
        original.attributes_mut().rotate_generation = Some(0);
        kms.database
            .update_object(&uid, original.object(), original.attributes(), None)
            .await?;
        let source = kms.database.retrieve_object(&uid).await?.expect("source");
        let rekeyer = StaleCandidateRekeyer {
            inner: SqlSymmetricRekeyer {
                offset: None,
                attributes: None,
            },
            stale: source,
            new_uid: std::sync::Mutex::new(None),
            encrypt_before_finalize: true,
            ciphertext: std::sync::Mutex::new(None),
        };
        let err = execute_rekey(
            &rekeyer,
            &kms,
            &ReKey {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                ..ReKey::default()
            },
            &user,
        )
        .await
        .expect_err("concurrent write must reject rotation");
        assert!(matches!(err, KmsError::Conflict(_)), "{err:?}");
        let encrypted = rekeyer
            .ciphertext
            .lock()
            .expect("ciphertext lock")
            .take()
            .expect("encryption completed");
        let decrypted = kms
            .decrypt(
                Decrypt {
                    unique_identifier: Some(encrypted.unique_identifier.clone()),
                    data: encrypted.data,
                    i_v_counter_nonce: encrypted.i_v_counter_nonce,
                    authenticated_encryption_tag: encrypted.authenticated_encryption_tag,
                    cryptographic_parameters: Some(CryptographicParameters::default()),
                    ..Decrypt::default()
                },
                &user,
            )
            .await?;
        assert_eq!(
            decrypted.data.as_ref().map(|data| data.as_slice()),
            Some(b"rotation race".as_slice())
        );
        // the keyset still resolves to the original key: the replacement was never published
        assert_eq!(encrypted.unique_identifier.to_string(), keyset);
        let source = kms.database.retrieve_object(&uid).await?.expect("source");
        assert_eq!(source.state(), State::Active);
        assert_eq!(source.attributes().rotate_offset, Some(42));
        assert!(
            source
                .attributes()
                .get_link(LinkType::ReplacementObjectLink)
                .is_none()
        );
        let replacement = rekeyer
            .new_uid
            .lock()
            .expect("uid lock")
            .clone()
            .expect("generated");
        assert!(kms.database.retrieve_object(&replacement).await?.is_none());
        Ok(())
    }

    /// Creates a KEK and a DEK wrapped by it, and returns `(kek_uid, dek_uid)`.
    async fn create_wrapped_dek(kms: &KMS, user: &UserId) -> KResult<(String, String)> {
        let new_key = |wrap_key_id: Option<&String>| {
            symmetric_key_create_request(
                VENDOR_ID_COSMIAN,
                None,
                256,
                CryptographicAlgorithm::AES,
                EMPTY_TAGS,
                false,
                wrap_key_id,
            )
        };
        let kek_uid = kms
            .create(new_key(None)?, user)
            .await?
            .unique_identifier
            .to_string();
        let dek_uid = kms
            .create(new_key(Some(&kek_uid))?, user)
            .await?
            .unique_identifier
            .to_string();
        let dek = kms.database.retrieve_object(&dek_uid).await?.expect("dek");
        assert_eq!(dek.object().wrapping_key_uid(), Some(kek_uid.clone()));
        Ok((kek_uid, dek_uid))
    }

    async fn encrypt_with(
        kms: &KMS,
        user: &UserId,
        uid: &str,
        data: &[u8],
    ) -> KResult<EncryptResponse> {
        kms.encrypt(
            Encrypt {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                data: Some(Zeroizing::new(data.to_vec())),
                ..Encrypt::default()
            },
            user,
        )
        .await
    }

    async fn decrypt_with(
        kms: &KMS,
        user: &UserId,
        encrypted: EncryptResponse,
    ) -> KResult<Vec<u8>> {
        let decrypted = kms
            .decrypt(
                Decrypt {
                    unique_identifier: Some(encrypted.unique_identifier),
                    data: encrypted.data,
                    i_v_counter_nonce: encrypted.i_v_counter_nonce,
                    authenticated_encryption_tag: encrypted.authenticated_encryption_tag,
                    cryptographic_parameters: Some(CryptographicParameters::default()),
                    ..Decrypt::default()
                },
                user,
            )
            .await?;
        Ok(decrypted.data.map(|data| data.to_vec()).unwrap_or_default())
    }

    /// Rotating a key wrapping other keys re-wraps them under the unpublished replacement
    /// in the same commit: afterwards the dependant is wrapped by the new key, which is
    /// Active, while the old key is retired, and data protected earlier is still readable.
    #[tokio::test]
    async fn rotating_a_wrapping_key_rewraps_dependants_atomically() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let user = UserId::from("rewrap_dependants@example.com");
        let (kek_uid, dek_uid) = create_wrapped_dek(&kms, &user).await?;
        let before = encrypt_with(&kms, &user, &dek_uid, b"before rotation").await?;

        let new_kek_uid = kms
            .rekey(
                ReKey {
                    unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
                    ..ReKey::default()
                },
                &user,
            )
            .await?
            .unique_identifier
            .to_string();

        let dek = kms.database.retrieve_object(&dek_uid).await?.expect("dek");
        assert_eq!(dek.object().wrapping_key_uid(), Some(new_kek_uid.clone()));
        let old_kek = kms
            .database
            .retrieve_object(&kek_uid)
            .await?
            .expect("old kek");
        assert_eq!(old_kek.state(), State::Deactivated);
        assert!(
            old_kek
                .attributes()
                .get_link(LinkType::ReplacementObjectLink)
                .is_some()
        );
        let new_kek = kms
            .database
            .retrieve_object(&new_kek_uid)
            .await?
            .expect("new kek");
        assert_eq!(new_kek.state(), State::Active);
        assert_eq!(
            decrypt_with(&kms, &user, before).await?,
            b"before rotation".to_vec()
        );
        let after = encrypt_with(&kms, &user, &dek_uid, b"after rotation").await?;
        assert_eq!(
            decrypt_with(&kms, &user, after).await?,
            b"after rotation".to_vec()
        );
        Ok(())
    }

    /// A rotation that loses the race leaves the dependants wrapped by the old key,
    /// unchanged and usable, and publishes neither the new key nor any re-wrapped dependant.
    #[tokio::test]
    async fn rotation_conflict_leaves_dependants_wrapped_by_old_key() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let user = UserId::from("conflict_dependants@example.com");
        let (kek_uid, dek_uid) = create_wrapped_dek(&kms, &user).await?;
        let before = encrypt_with(&kms, &user, &dek_uid, b"kept").await?;
        let stale = kms.database.retrieve_object(&kek_uid).await?.expect("kek");
        let dek_before = kms.database.retrieve_object(&dek_uid).await?.expect("dek");
        // the concurrent winner's write
        kms.database
            .atomic(
                &user,
                &[AtomicOperation::UpdateObject((
                    kek_uid.clone(),
                    stale.object().clone(),
                    stale.attributes().clone(),
                    None,
                ))],
            )
            .await?;
        let rekeyer = StaleCandidateRekeyer {
            inner: SqlSymmetricRekeyer {
                offset: None,
                attributes: None,
            },
            stale,
            new_uid: std::sync::Mutex::new(None),
            encrypt_before_finalize: false,
            ciphertext: std::sync::Mutex::new(None),
        };
        let err = execute_rekey(
            &rekeyer,
            &kms,
            &ReKey {
                unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
                ..ReKey::default()
            },
            &user,
        )
        .await
        .expect_err("stale rotation must conflict");
        assert!(matches!(err, KmsError::Conflict(_)), "{err:?}");

        let dek_after = kms.database.retrieve_object(&dek_uid).await?.expect("dek");
        assert!(
            dek_after.object() == dek_before.object(),
            "dependant was rewritten"
        );
        assert_eq!(dek_after.object().wrapping_key_uid(), Some(kek_uid.clone()));
        assert_eq!(dek_after.version(), dek_before.version());
        let replacement = rekeyer
            .new_uid
            .lock()
            .expect("uid lock")
            .clone()
            .expect("generated");
        assert!(kms.database.retrieve_object(&replacement).await?.is_none());
        assert_eq!(decrypt_with(&kms, &user, before).await?, b"kept".to_vec());
        Ok(())
    }
}
