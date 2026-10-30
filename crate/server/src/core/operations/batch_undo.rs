//! Rollback of a batch processed with the `Undo` Batch Error Continuation Option.
//!
//! KMIP 2.1 §9.6 (Table 434): when an operation of an `Undo` batch fails, the server SHALL
//! undo all the previous operations. Before running each item the server snapshots the stored
//! objects the operation may change that the requester is allowed to change; after the item
//! runs it records how it left them. After a failure it reverts the items in reverse order:
//! one atomic transaction per item deletes the objects it created and restores its snapshots,
//! and only if every one of those objects is still exactly as the item left it. Only reverted
//! items are reported `Operation Undone`; the others keep their `Success` status.

use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_operations::Operation,
            kmip_types::{CryptographicAlgorithm, LinkedObjectIdentifier, UniqueIdentifier},
        },
    },
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use cosmian_logger::{error, info, warn};

use crate::{
    core::{
        KMS,
        retrieve_object_utils::user_has_permission,
        uid_utils::{KeysetVersion, ObjectHandle, parse_keyset_identifier},
    },
    middlewares::UserId,
    result::KResult,
};

/// Maximum number of items in a batch processed with `Undo`: every item keeps a snapshot
/// of the objects it may change until the end of the message.
pub(super) const MAX_UNDO_BATCH_ITEMS: usize = 1_000;

/// Maximum number of objects snapshotted for one `Undo` batch (targets and linked objects).
pub(super) const MAX_UNDO_SNAPSHOTS: usize = 4 * MAX_UNDO_BATCH_ITEMS;

/// The stored state and attributes of an object, as an item left it.
type StoredState = (State, Attributes);

/// An object as it was before an item ran, and as the item left it.
struct Snapshot {
    before: ObjectWithMetadata,
    tags: HashSet<String>,
    after: StoredState,
}

/// What undoing one executed batch item requires.
pub(super) struct UndoRecord {
    /// Index of the item in the response
    pub(super) item_index: usize,
    /// Objects the operation may have changed
    snapshots: Vec<Snapshot>,
    /// Objects the operation created, as it left them
    created: Vec<(String, StoredState)>,
}

/// State captured before an operation runs; `None` when the operation cannot be undone.
pub(super) struct PreState(Option<Vec<(ObjectWithMetadata, HashSet<String>)>>);

/// The object an operation changes and the permission it needs on it, `None` when it only
/// creates objects, or `Err(())` when the server cannot revert it.
fn touched_object(operation: &Operation) -> Result<Option<(&UniqueIdentifier, KmipOperation)>, ()> {
    let (uid, kmip_operation) = match operation {
        // Operations that change no stored object, or only create new ones
        Operation::Create(_)
        | Operation::CreateKeyPair(_)
        | Operation::Register(_)
        | Operation::Query(_)
        | Operation::DiscoverVersions(_)
        | Operation::Locate(_)
        | Operation::Hash(_)
        | Operation::RNGRetrieve(_)
        | Operation::Validate(_)
        | Operation::Get(_)
        | Operation::GetAttributes(_)
        | Operation::GetAttributeList(_)
        | Operation::Export(_)
        | Operation::Check(_)
        | Operation::Ping(_) => return Ok(None),
        Operation::Activate(r) => (Some(&r.unique_identifier), KmipOperation::Activate),
        Operation::AddAttribute(r) => (Some(&r.unique_identifier), KmipOperation::AddAttribute),
        Operation::MACVerify(r) => (Some(&r.unique_identifier), KmipOperation::MAC),
        Operation::Import(r) => (Some(&r.unique_identifier), KmipOperation::Import),
        Operation::DeriveKey(r) => match r.object_unique_identifier.as_slice() {
            [] => return Ok(None),
            [base] => (Some(base), KmipOperation::DeriveKey),
            _ => return Err(()),
        },
        // Removing the object also drops its access grants, which cannot be restored
        Operation::Destroy(r) if r.remove => return Err(()),
        Operation::Destroy(r) => (r.unique_identifier.as_ref(), KmipOperation::Destroy),
        Operation::Revoke(r) => (r.unique_identifier.as_ref(), KmipOperation::Revoke),
        Operation::SetAttribute(r) => (r.unique_identifier.as_ref(), KmipOperation::SetAttribute),
        Operation::ModifyAttribute(r) => {
            (r.unique_identifier.as_ref(), KmipOperation::ModifyAttribute)
        }
        Operation::DeleteAttribute(r) => {
            (r.unique_identifier.as_ref(), KmipOperation::DeleteAttribute)
        }
        Operation::ReKey(r) => (r.unique_identifier.as_ref(), KmipOperation::Rekey),
        Operation::ReKeyKeyPair(r) => (
            r.private_key_unique_identifier.as_ref(),
            KmipOperation::Rekey,
        ),
        Operation::Certify(r) => (r.unique_identifier.as_ref(), KmipOperation::Certify),
        Operation::ReCertify(r) => (r.unique_identifier.as_ref(), KmipOperation::Certify),
        Operation::Encrypt(r) => (r.unique_identifier.as_ref(), KmipOperation::Encrypt),
        Operation::Decrypt(r) => (r.unique_identifier.as_ref(), KmipOperation::Decrypt),
        Operation::Sign(r) => (r.unique_identifier.as_ref(), KmipOperation::Sign),
        Operation::SignatureVerify(r) => {
            (r.unique_identifier.as_ref(), KmipOperation::SignatureVerify)
        }
        Operation::MAC(r) => (r.unique_identifier.as_ref(), KmipOperation::MAC),
        // Not revertible: a Crypto Officer split removes the source key and a join records a
        // ceremony activation; seeding the RNG, logging and PKCS#11 or Interop calls act
        // outside the object store.
        _ => return Err(()),
    };
    Ok(uid.map(|uid| (uid, kmip_operation)))
}

/// Snapshots the objects `operation` may change and `user` may change: its target and the
/// objects the target links to (key pair halves, certificates, replacement keys are updated
/// together). `budget` bounds the snapshots of the whole batch.
pub(super) async fn capture(
    kms: &KMS,
    user: &UserId,
    operation: &Operation,
    budget: &mut usize,
) -> PreState {
    match capture_inner(kms, user, operation, budget).await {
        Ok(snapshots) => PreState(snapshots),
        Err(e) => {
            error!("Undo: cannot snapshot the batch item: {e}");
            PreState(None)
        }
    }
}

async fn capture_inner(
    kms: &KMS,
    user: &UserId,
    operation: &Operation,
    budget: &mut usize,
) -> KResult<Option<Vec<(ObjectWithMetadata, HashSet<String>)>>> {
    let Ok(target) = touched_object(operation) else {
        return Ok(None);
    };
    let Some((target, kmip_operation)) = target else {
        return Ok(Some(Vec::new()));
    };
    // Only a plain identifier designates exactly the object snapshotted here: tag, HSM and
    // keyset handles are resolved by the operation itself.
    let Some(uid) = target
        .as_str()
        .filter(|uid| matches!(ObjectHandle::from(*uid), ObjectHandle::Uid(_)))
    else {
        return Ok(None);
    };
    // A missing object makes the operation fail, unless the identifier is a keyset reference
    let Some(owm) = kms.database.retrieve_object(uid).await? else {
        return Ok(None);
    };
    let bare_keyset_name =
        parse_keyset_identifier(uid).is_some_and(|keyset| keyset.version == KeysetVersion::Bare);
    if (bare_keyset_name && owm.attributes().rotate_name.is_some())
        // Covercrypt operations cascade to user decryption keys
        || owm.attributes().cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt)
        || !user_has_permission(user, Some(&owm), &kmip_operation, kms).await?
    {
        return Ok(None);
    }

    let linked: Vec<String> = owm
        .attributes()
        .link
        .iter()
        .flatten()
        .filter_map(|link| match &link.linked_object_identifier {
            LinkedObjectIdentifier::TextString(uid) => Some(uid.clone()),
            _ => None,
        })
        .collect();
    let mut objects = vec![owm];
    for uid in linked {
        if !matches!(ObjectHandle::from(uid.as_str()), ObjectHandle::Uid(_)) {
            return Ok(None);
        }
        let Some(linked) = kms.database.retrieve_object(&uid).await? else {
            continue;
        };
        // An object the requester cannot change is never restored on its behalf
        if objects.iter().any(|o| o.id() == linked.id())
            || !kms
                .user_can_perform_operation(&linked, user, &kmip_operation)
                .await?
        {
            continue;
        }
        objects.push(linked);
    }

    // Re-keying a wrapping key re-wraps its dependants, which cannot be restored here
    if kmip_operation == KmipOperation::Rekey {
        for owm in &objects {
            if !kms
                .database
                .find_wrapped_by(owm.id(), user)
                .await?
                .is_empty()
            {
                return Ok(None);
            }
        }
    }
    let Some(remaining) = budget.checked_sub(objects.len()) else {
        warn!("Undo: snapshot budget of the batch exhausted; the item cannot be undone");
        return Ok(None);
    };
    *budget = remaining;

    let mut snapshots = Vec::with_capacity(objects.len());
    for owm in objects {
        let tags = kms.database.retrieve_tags(owm.id()).await?;
        snapshots.push((owm, tags));
    }
    Ok(Some(snapshots))
}

/// Unique identifiers of the objects a successful operation returned as created or replaced.
fn response_objects(response: &Operation) -> Vec<&UniqueIdentifier> {
    match response {
        Operation::CreateResponse(r) => vec![&r.unique_identifier],
        Operation::RegisterResponse(r) => vec![&r.unique_identifier],
        Operation::ImportResponse(r) => vec![&r.unique_identifier],
        Operation::DeriveKeyResponse(r) => vec![&r.unique_identifier],
        Operation::CertifyResponse(r) => vec![&r.unique_identifier],
        Operation::ReCertifyResponse(r) => vec![&r.unique_identifier],
        Operation::ReKeyResponse(r) => vec![&r.unique_identifier],
        Operation::CreateKeyPairResponse(r) => {
            vec![
                &r.private_key_unique_identifier,
                &r.public_key_unique_identifier,
            ]
        }
        Operation::ReKeyKeyPairResponse(r) => {
            vec![
                &r.private_key_unique_identifier,
                &r.public_key_unique_identifier,
            ]
        }
        _ => Vec::new(),
    }
}

/// Builds the undo record of an executed item from the stored state it left; `None` when
/// its effects cannot be reverted.
pub(super) async fn record(
    kms: &KMS,
    item_index: usize,
    pre_state: PreState,
    response: Option<&Operation>,
) -> Option<UndoRecord> {
    let before = pre_state.0?;
    let stored = |uid: String| async move {
        match kms.database.retrieve_state(&uid).await {
            Ok(Some(state)) => Some((uid, state)),
            Ok(None) => None,
            Err(e) => {
                error!("Undo: cannot read object {uid} after batch item {item_index}: {e}");
                None
            }
        }
    };
    let mut created = Vec::new();
    for uid in response.map(response_objects).unwrap_or_default() {
        let uid = uid.as_str()?;
        if !matches!(ObjectHandle::from(uid), ObjectHandle::Uid(_)) {
            return None;
        }
        // An object that existed before (e.g. a replaced Import) is restored, not deleted
        if !before.iter().any(|(owm, _)| owm.id() == uid) {
            created.push(stored(uid.to_owned()).await?);
        }
    }
    let mut snapshots = Vec::with_capacity(before.len());
    for (owm, tags) in before {
        // An object the operation removed cannot be restored with its access grants
        let (_, after) = stored(owm.id().to_owned()).await?;
        snapshots.push(Snapshot {
            before: owm,
            tags,
            after,
        });
    }
    Some(UndoRecord {
        item_index,
        snapshots,
        created,
    })
}

/// Reverts one executed item; returns whether all its effects were reverted.
pub(super) async fn revert(kms: &KMS, user: &UserId, record: &UndoRecord) -> bool {
    match revert_inner(kms, user, record).await {
        Ok(reverted) => reverted,
        Err(e) => {
            error!(
                "Undo of batch item {} failed, it keeps its Success status: {e}",
                record.item_index
            );
            false
        }
    }
}

async fn revert_inner(kms: &KMS, user: &UserId, record: &UndoRecord) -> KResult<bool> {
    // Compare-and-set: an object changed since the item ran (by a later request, or by a
    // later item that could not be undone) is left as it is.
    // shortcut: the check and the transaction are separate statements, so a write landing
    // between them is overwritten; a store-level conditional update would close that window.
    let expected = record
        .created
        .iter()
        .map(|(uid, after)| (uid.as_str(), after))
        .chain(record.snapshots.iter().map(|s| (s.before.id(), &s.after)));
    for (uid, after) in expected {
        if kms.database.retrieve_state(uid).await?.as_ref() != Some(after) {
            warn!(
                user = user.as_str(),
                "Undo: object {uid} changed after batch item {}; the item keeps its Success \
                 status",
                record.item_index
            );
            return Ok(false);
        }
    }

    let mut operations = Vec::with_capacity(record.created.len() + 2 * record.snapshots.len());
    for (uid, _) in &record.created {
        operations.push(AtomicOperation::Delete(uid.clone()));
    }
    for snapshot in record.snapshots.iter().rev() {
        let owm = &snapshot.before;
        operations.push(AtomicOperation::UpdateObject((
            owm.id().to_owned(),
            owm.object().clone(),
            owm.attributes().clone(),
            Some(snapshot.tags.clone()),
        )));
        operations.push(AtomicOperation::UpdateState((
            owm.id().to_owned(),
            owm.state(),
        )));
    }
    kms.database.atomic(user, &operations).await?;

    for (uid, _) in &record.created {
        info!(
            user = user.as_str(),
            "Undo: batch item {} reverted, created object {uid} deleted", record.item_index
        );
    }
    for snapshot in &record.snapshots {
        info!(
            user = user.as_str(),
            "Undo: batch item {} reverted, object {} restored to state {}",
            record.item_index,
            snapshot.before.id(),
            snapshot.before.state()
        );
    }
    Ok(true)
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test assertions in fallible async tests"
)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_attributes::Attribute,
        kmip_objects::ObjectType,
        kmip_operations::{CreateSplitKey, Destroy, JoinSplitKey, SetAttribute},
        kmip_types::{Link, LinkType, SplitKeyMethod},
        requests::symmetric_key_create_request,
    };

    use super::*;
    use crate::{error::KmsError, tests::test_utils::test_kms};

    async fn create_key(kms: &KMS, owner: &UserId) -> KResult<String> {
        let request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        Ok(kms
            .create(request, owner)
            .await?
            .unique_identifier
            .to_string())
    }

    fn set(uid: &str, new_attribute: Attribute) -> SetAttribute {
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            new_attribute,
        }
    }

    async fn comment(kms: &KMS, uid: &str) -> KResult<Option<String>> {
        Ok(kms
            .database
            .retrieve_state(uid)
            .await?
            .and_then(|(_, attributes)| attributes.comment))
    }

    /// Runs a Set Attribute batch item with Undo semantics and returns its undo record.
    async fn run_item(kms: &KMS, user: &UserId, request: SetAttribute) -> KResult<UndoRecord> {
        let mut budget = MAX_UNDO_SNAPSHOTS;
        let pre_state = capture(
            kms,
            user,
            &Operation::SetAttribute(request.clone()),
            &mut budget,
        )
        .await;
        let response = Operation::SetAttributeResponse(kms.set_attribute(request, user).await?);
        record(kms, 0, pre_state, Some(&response))
            .await
            .ok_or_else(|| KmsError::InvalidRequest("the item must be undoable".to_owned()))
    }

    /// A Link to another user's object does not make Undo snapshot or restore that object.
    #[tokio::test]
    async fn undo_never_restores_another_users_linked_object() -> KResult<()> {
        let kms = test_kms().await?;
        let victim = UserId::from("undo_victim@example.com");
        let attacker = UserId::from("undo_attacker@example.com");
        let victim_key = create_key(&kms, &victim).await?;
        let attacker_key = create_key(&kms, &attacker).await?;
        kms.set_attribute(
            set(
                &attacker_key,
                Attribute::Link(Link {
                    link_type: LinkType::ReplacementObjectLink,
                    linked_object_identifier: LinkedObjectIdentifier::TextString(
                        victim_key.clone(),
                    ),
                }),
            ),
            &attacker,
        )
        .await?;

        let record = run_item(
            &kms,
            &attacker,
            set(&attacker_key, Attribute::Comment("attacker".to_owned())),
        )
        .await?;
        let snapshotted: Vec<&str> = record.snapshots.iter().map(|s| s.before.id()).collect();
        assert_eq!(snapshotted, vec![attacker_key.as_str()]);

        // The victim changes its key while the batch runs; the undo leaves it alone
        kms.set_attribute(
            set(&victim_key, Attribute::Comment("victim".to_owned())),
            &victim,
        )
        .await?;
        assert!(revert(&kms, &attacker, &record).await);
        assert_eq!(comment(&kms, &victim_key).await?.as_deref(), Some("victim"));
        assert_eq!(comment(&kms, &attacker_key).await?, None);
        Ok(())
    }

    /// An object changed after the item ran is not overwritten: the item keeps Success.
    #[tokio::test]
    async fn undo_leaves_an_object_changed_after_the_item() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("undo_cas_owner@example.com");
        let key = create_key(&kms, &owner).await?;
        let record = run_item(
            &kms,
            &owner,
            set(&key, Attribute::Comment("batch".to_owned())),
        )
        .await?;
        kms.set_attribute(set(&key, Attribute::Comment("later".to_owned())), &owner)
            .await?;
        assert!(!revert(&kms, &owner, &record).await);
        assert_eq!(comment(&kms, &key).await?.as_deref(), Some("later"));
        Ok(())
    }

    /// Handles that do not designate exactly one stored object, objects the requester may
    /// not change and operations with effects outside the object store cannot be undone.
    #[tokio::test]
    async fn undo_refuses_what_it_cannot_revert() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("undo_refuse_owner@example.com");
        let other = UserId::from("undo_refuse_other@example.com");
        let key = create_key(&kms, &owner).await?;
        let uid = |uid: &str| Some(UniqueIdentifier::TextString(uid.to_owned()));
        let comment =
            |target: &str| Operation::SetAttribute(set(target, Attribute::Comment("x".to_owned())));
        let cases = [
            (&owner, comment(r#"["some-tag"]"#)),
            (&owner, comment(&format!("{key}@latest"))),
            (&owner, comment("missing-object")),
            (&other, comment(&key)),
            (
                &owner,
                Operation::Destroy(Destroy {
                    unique_identifier: uid(&key),
                    remove: true,
                    ..Destroy::default()
                }),
            ),
            (
                &owner,
                Operation::CreateSplitKey(CreateSplitKey {
                    object_type: ObjectType::SymmetricKey,
                    unique_identifier: uid(&key),
                    split_key_parts: 3,
                    split_key_threshold: 3,
                    split_key_method: SplitKeyMethod::XOR,
                    prime_field_size: None,
                    attributes: None,
                    protection_storage_masks: None,
                }),
            ),
            (
                &owner,
                Operation::JoinSplitKey(JoinSplitKey {
                    unique_identifier: vec![],
                    object_type: ObjectType::SymmetricKey,
                    secret_data_type: None,
                    attributes: None,
                    protection_storage_masks: None,
                }),
            ),
        ];
        for (index, (user, operation)) in cases.into_iter().enumerate() {
            let mut budget = MAX_UNDO_SNAPSHOTS;
            assert!(
                capture(&kms, user, &operation, &mut budget)
                    .await
                    .0
                    .is_none(),
                "case {index} must not be undoable"
            );
        }
        // The snapshot budget of the batch bounds what an Undo batch keeps in memory
        let mut budget = 0;
        assert!(
            capture(&kms, &owner, &comment(&key), &mut budget)
                .await
                .0
                .is_none()
        );
        Ok(())
    }

    /// An Undo batch above the snapshot limit is refused before any item runs.
    #[tokio::test]
    async fn undo_batch_size_is_bounded() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::{
            kmip_0::{
                kmip_messages::{
                    RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
                },
                kmip_types::{BatchErrorContinuationOption, ErrorReason, ProtocolVersion},
            },
            kmip_2_1::{kmip_messages::RequestMessageBatchItem, kmip_operations::Query},
        };

        let kms = test_kms().await?;
        let items = MAX_UNDO_BATCH_ITEMS + 1;
        let err = kms
            .message(
                RequestMessage {
                    request_header: RequestMessageHeader {
                        protocol_version: ProtocolVersion {
                            protocol_version_major: 2,
                            protocol_version_minor: 1,
                        },
                        batch_count: i32::try_from(items)?,
                        batch_error_continuation_option: Some(BatchErrorContinuationOption::Undo),
                        ..Default::default()
                    },
                    batch_item: (0..items)
                        .map(|_| {
                            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                                Operation::Query(Query::default()),
                            ))
                        })
                        .collect(),
                },
                &UserId::from("undo_limit@example.com"),
            )
            .await
            .expect_err("an oversized Undo batch must be refused");
        assert!(
            matches!(
                err,
                KmsError::Kmip21Error(ErrorReason::Server_Limit_Exceeded, _)
            ),
            "{err:?}"
        );
        Ok(())
    }
}
