use std::{collections::BTreeSet, sync::Arc};

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::access_policy_from_attributes;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            kmip_operations::{Locate, LocateResponse},
            kmip_types::{StorageStatusMask, UniqueIdentifier},
        },
    },
    cosmian_kms_interfaces::{DestroyedFilter, FindOptions},
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, uid_utils::ObjectHandle},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

/// Server-side ceiling for Locate results and offsets (A04-3 / EXT2-4).
///
/// Prevents unbounded database queries and oversized response payloads when a client omits
/// `MaximumItems`, requests more objects than this threshold, or supplies an excessive offset.
const MAX_LOCATE_ITEMS: i32 = 1000;

pub(crate) async fn locate(
    kms: &KMS,
    request: Locate,
    state: Option<State>,
    user: &UserId,
) -> KResult<LocateResponse> {
    trace!("Locate request");
    if request.object_group_member.is_some() {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            "Locate Object Group Member is not supported".to_owned(),
        ));
    }
    let storage_status_mask = request.storage_status_mask;
    let attributes = request.attributes;
    // Determine the effective state filter: prefer explicit parameter, else Attributes.state
    let effective_state = state.or(attributes.state);

    // Apply a server-side cap on result set size (A04-3 / EXT2-4).
    // The effective limit is the smaller of: client-supplied MaximumItems (if any)
    // and the server-side MAX_LOCATE_ITEMS constant.  When MaximumItems is absent
    // the server cap is applied automatically to prevent unbounded DB result sets.
    let server_cap = usize::try_from(MAX_LOCATE_ITEMS)?;
    let effective_max = request.maximum_items.map_or(server_cap, |mi| {
        usize::try_from(mi.max(0))
            .unwrap_or(server_cap)
            .min(server_cap)
    });
    let offset = request.offset_items.map_or(Ok(0_usize), |offset| {
        usize::try_from(offset).map_err(|error| {
            KmsError::InvalidRequest(format!("OffsetItems must be non-negative: {error}"))
        })
    })?;
    if offset > server_cap {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!("OffsetItems must not exceed {MAX_LOCATE_ITEMS}"),
        ));
    }
    if effective_max == 0 {
        return Ok(LocateResponse {
            located_items: None,
            unique_identifier: None,
        });
    }
    let (include_online, include_destroyed) =
        storage_status_mask.as_ref().map_or((true, false), |mask| {
            (
                mask.contains(StorageStatusMask::OnlineStorage),
                mask.contains(StorageStatusMask::DestroyedStorage),
            )
        });
    if !include_online && !include_destroyed {
        return Ok(LocateResponse {
            located_items: Some(0),
            unique_identifier: None,
        });
    }
    let is_hsm_admin = kms
        .params
        .hsm_instances
        .iter()
        .any(|inst| inst.admin.iter().any(|a| a == "*" || a == user));
    let query_limit = offset.checked_add(effective_max).ok_or_else(|| {
        KmsError::InvalidRequest("OffsetItems and MaximumItems are too large".to_owned())
    })?;
    // HSMs record no per-user permissions: a user who is not an HSM admin only sees the HSM
    // keys granted to them. Resolving those grants first lets the HSM store look up just these
    // keys, so every store returns only visible rows and `query_limit` never under-fills a page.
    let hsm_granted_uids = if is_hsm_admin || kms.params.hsm_instances.is_empty() {
        None
    } else {
        Some(Arc::new(
            kms.database
                .list_user_operations_granted(user)
                .await?
                .into_iter()
                .filter(|(uid, (_, _, ops))| {
                    !ops.is_empty() && ObjectHandle::from(uid.as_str()).is_hsm()
                })
                .map(|(uid, _)| uid)
                .collect::<BTreeSet<_>>(),
        ))
    };
    let find_options = FindOptions {
        limit: Some(query_limit),
        destroyed: if include_destroyed {
            if include_online {
                DestroyedFilter::Include
            } else {
                DestroyedFilter::Only
            }
        } else {
            DestroyedFilter::Exclude
        },
        hsm_granted_uids,
    };
    // Find all the objects that match the attributes.
    // CryptoOfficer ownership bypass: active COs call find_all (no user filter) and
    // receive *all* matching objects in the database, while non-COs call find which
    // restricts to objects they own or hold explicit grants on.
    // NOTE: the bypass only manifests as a difference in the *returned UID list*,
    // not in the exit code. Observing the bypass requires diffing the result set across
    // CO vs non-CO callers against the same seeded objects, not just checking success/error.
    let mut uids_attrs = if kms.is_crypto_officer(user).await? {
        // CryptoOfficer: bypass user filtering and return all matching objects
        kms.database
            .find_all_with_options(
                Some(&attributes),
                effective_state,
                kms.vendor_id(),
                &find_options,
            )
            .await?
    } else {
        kms.database
            .find_with_options(
                Some(&attributes),
                effective_state,
                user,
                false,
                kms.vendor_id(),
                &find_options,
            )
            .await?
    };
    // KMIP 2.1 §6.1.28: results are returned in descending order of object creation. Each store
    // already orders its own page; merge them into one global order (stable, UID as tie-break).
    uids_attrs.sort_by(|a, b| {
        b.2.initial_date
            .cmp(&a.2.initial_date)
            .then_with(|| a.0.cmp(&b.0))
    });
    for (uid, _, attributes) in &uids_attrs {
        trace!("Found uid: {}, attributes: {}", uid, attributes);
    }

    // Every store returned fewer rows than requested, so the result is complete.
    let store_complete = uids_attrs.len() < query_limit;
    #[cfg(feature = "non-fips")]
    let access_policy_err = access_policy_from_attributes(kms.vendor_id(), &attributes).is_err();
    #[cfg(not(feature = "non-fips"))]
    let access_policy_err = true;
    let mut uids = Vec::with_capacity(uids_attrs.len().min(effective_max));
    let mut skipped = 0_usize;
    if access_policy_err {
        for (uid, state_found, attributes) in uids_attrs {
            trace!(
                "UID: {:?}, State: {:?}, Attributes: {}",
                uid, state_found, attributes
            );
            if effective_state.is_some_and(|state| state_found != state) {
                continue;
            }

            let is_destroyed =
                matches!(state_found, State::Destroyed | State::Destroyed_Compromised);
            if !(if is_destroyed {
                include_destroyed
            } else {
                include_online
            }) {
                continue;
            }

            // HSM key visibility (see `hsm_granted_uids` above), re-checked here so that a
            // store ignoring the candidate list cannot leak ungranted HSM keys.
            if ObjectHandle::from(uid.as_str()).is_hsm()
                && find_options
                    .hsm_granted_uids
                    .as_ref()
                    .is_some_and(|granted| !granted.contains(&uid))
            {
                trace!("Locate: filtering out HSM key {uid} — user {user} has no grants");
                continue;
            }

            if skipped < offset {
                skipped += 1;
                continue;
            }

            uids.push(UniqueIdentifier::TextString(uid));
            if uids.len() == effective_max {
                break;
            }
        }
    }
    // Each store caps its own result; with several stores (e.g. the database
    // and an HSM), the concatenation must still be capped.
    if uids.len() > effective_max {
        uids.truncate(effective_max);
    }
    trace!("UIDs count (post-truncate): {}", uids.len());
    // KMIP 2.1 §6.1.28: Located Items MAY be omitted when the count is unknown. It is
    // known when the stores returned every match and nothing was skipped by an offset.
    let located_items = (offset == 0 && store_complete)
        .then(|| i32::try_from(uids.len()))
        .transpose()?;
    let response = LocateResponse {
        located_items,
        unique_identifier: if uids.is_empty() { None } else { Some(uids) },
    };

    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap, HashSet},
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::{ErrorReason, State},
            kmip_2_1::{
                KmipOperation,
                kmip_attributes::Attributes,
                kmip_objects::{Object, ObjectType},
                kmip_operations::{Create, Destroy, Locate},
                kmip_types::{
                    CryptographicAlgorithm, ObjectGroupMember, StorageStatusMask, UniqueIdentifier,
                },
            },
        },
        cosmian_kms_interfaces::{
            AtomicOperation, DestroyedFilter, FindOptions, InterfaceError, InterfaceResult,
            ObjectWithMetadata, ObjectsStore,
        },
    };
    use time::OffsetDateTime;

    use super::{MAX_LOCATE_ITEMS, locate};
    use crate::{
        config::{HsmInstanceParams, ServerParams},
        core::KMS,
        error::KmsError,
        middlewares::UserId,
        result::KResult,
        tests::test_utils::{https_clap_config, test_kms},
    };

    fn unused<T>() -> InterfaceResult<T> {
        Err(InterfaceError::Default("not used by Locate".to_owned()))
    }

    /// An HSM-like store holding three keys. Like `HsmStore`, it honours `limit` and
    /// `hsm_granted_uids`; it records the options Locate passed.
    struct FakeHsmStore(Mutex<Vec<FindOptions>>);

    #[async_trait(?Send)]
    impl ObjectsStore for FakeHsmStore {
        async fn create(
            &self,
            _: Option<String>,
            _: &UserId,
            _: &Object,
            _: &Attributes,
            _: &HashSet<String>,
        ) -> InterfaceResult<String> {
            unused()
        }

        async fn retrieve(&self, _: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
            unused()
        }

        async fn retrieve_tags(&self, _: &str) -> InterfaceResult<HashSet<String>> {
            unused()
        }

        async fn update_object(
            &self,
            _: &str,
            _: &Object,
            _: &Attributes,
            _: Option<&HashSet<String>>,
        ) -> InterfaceResult<()> {
            unused()
        }

        async fn update_state(&self, _: &str, _: State) -> InterfaceResult<()> {
            unused()
        }

        async fn delete(&self, _: &str) -> InterfaceResult<()> {
            unused()
        }

        async fn atomic(&self, _: &UserId, _: &[AtomicOperation]) -> InterfaceResult<Vec<String>> {
            unused()
        }

        async fn is_object_owned_by(&self, _: &str, _: &UserId) -> InterfaceResult<bool> {
            unused()
        }

        async fn list_uids_for_tags(
            &self,
            _: &HashSet<String>,
        ) -> InterfaceResult<HashSet<String>> {
            unused()
        }

        async fn find(
            &self,
            _: Option<&Attributes>,
            _: Option<State>,
            _: &UserId,
            _: bool,
            _: &str,
        ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
            unused()
        }

        async fn find_with_options(
            &self,
            _: Option<&Attributes>,
            _: Option<State>,
            _: &UserId,
            _: bool,
            _: &str,
            options: &FindOptions,
        ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
            self.0
                .lock()
                .map_err(|e| InterfaceError::Default(e.to_string()))?
                .push(options.clone());
            Ok(["hsm::fake::0::a", "hsm::fake::0::b", "hsm::fake::0::c"]
                .into_iter()
                .filter(|uid| {
                    options
                        .hsm_granted_uids
                        .as_ref()
                        .is_none_or(|granted| granted.contains(*uid))
                })
                .take(options.limit.unwrap_or(usize::MAX))
                .map(|uid| (uid.to_owned(), State::Active, Attributes::default()))
                .collect())
        }

        async fn find_wrapped_by(
            &self,
            _: &str,
            _: &UserId,
        ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
            unused()
        }

        async fn find_due_for_rotation(
            &self,
            _: OffsetDateTime,
        ) -> InterfaceResult<Vec<(String, String)>> {
            unused()
        }

        async fn find_by_rotate_name(
            &self,
            _: &str,
            _: Option<i32>,
            _: &UserId,
        ) -> InterfaceResult<Vec<(String, Attributes)>> {
            unused()
        }

        async fn find_all(
            &self,
            _: Option<&Attributes>,
            _: Option<State>,
            _: &str,
        ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
            unused()
        }
    }

    /// A user who is not an HSM admin sees only the HSM keys granted to them, and the store
    /// query is bounded by `offset + maximum` without under-filling the page.
    #[tokio::test]
    async fn non_hsm_admin_locate_pages_only_granted_hsm_keys() -> KResult<()> {
        let mut kms =
            KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?;
        let mut params = ServerParams::try_from(https_clap_config())?;
        params.hsm_instances.push(HsmInstanceParams {
            model: "fake".to_owned(),
            admin: vec!["hsm-admin@example.com".to_owned()],
            slot_passwords: HashMap::new(),
            prefix: "hsm::fake".to_owned(),
        });
        kms.params = Arc::new(params);
        let store = Arc::new(FakeHsmStore(Mutex::default()));
        kms.database
            .register_objects_store("hsm::fake", store.clone())
            .await;
        let user = UserId::from("locate-hsm@example.com");
        let granted = ["hsm::fake::0::b".to_owned(), "hsm::fake::0::c".to_owned()];
        for uid in &granted {
            kms.database
                .grant_operations(uid, &user, HashSet::from([KmipOperation::Get]))
                .await?;
        }

        let response = locate(
            &kms,
            Locate {
                offset_items: Some(1),
                maximum_items: Some(1),
                ..Locate::default()
            },
            None,
            &user,
        )
        .await?;
        if response.unique_identifier
            != Some(vec![UniqueIdentifier::TextString(
                "hsm::fake::0::c".to_owned(),
            )])
        {
            return Err(KmsError::Default(format!(
                "expected the second granted HSM key, got {:?}",
                response.unique_identifier
            )));
        }
        let seen = store
            .0
            .lock()
            .map_err(|e| KmsError::Default(e.to_string()))?
            .clone();
        let expected = FindOptions {
            limit: Some(2),
            destroyed: DestroyedFilter::Exclude,
            hsm_granted_uids: Some(Arc::new(BTreeSet::from(granted))),
        };
        if seen != [expected] {
            return Err(KmsError::Default(format!(
                "unexpected HSM store options: {seen:?}"
            )));
        }
        Ok(())
    }

    #[tokio::test]
    async fn paged_locate_omits_an_indeterminate_count() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("locate-page@example.com");

        for _ in 0..2 {
            kms.create(
                Create {
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(256),
                        ..Attributes::default()
                    },
                    protection_storage_masks: None,
                },
                &user,
            )
            .await?;
        }

        let response = locate(
            &kms,
            Locate {
                maximum_items: Some(1),
                attributes: Attributes {
                    object_type: Some(ObjectType::SymmetricKey),
                    ..Attributes::default()
                },
                ..Locate::default()
            },
            None,
            &user,
        )
        .await?;

        if response.located_items.is_some() {
            return Err(KmsError::Default(
                "paged Locate returned a partial LocatedItems count".to_owned(),
            ));
        }
        if response.unique_identifier.as_ref().map_or(0, Vec::len) != 1 {
            return Err(KmsError::Default(
                "paged Locate did not return one result".to_owned(),
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn paged_locate_counts_a_complete_result() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("locate-count@example.com");

        for _ in 0..2 {
            kms.create(
                Create {
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(256),
                        ..Attributes::default()
                    },
                    protection_storage_masks: None,
                },
                &user,
            )
            .await?;
        }

        let page = |offset_items| Locate {
            maximum_items: Some(100),
            offset_items,
            attributes: Attributes {
                object_type: Some(ObjectType::SymmetricKey),
                ..Attributes::default()
            },
            ..Locate::default()
        };

        let response = locate(&kms, page(None), None, &user).await?;
        if response.located_items != Some(2)
            || response.unique_identifier.as_ref().map_or(0, Vec::len) != 2
        {
            return Err(KmsError::Default(format!(
                "complete Locate must count both keys: {response:?}"
            )));
        }

        // An offset hides part of the matches: the total is not known from the page.
        let response = locate(&kms, page(Some(1)), None, &user).await?;
        if response.located_items.is_some()
            || response.unique_identifier.as_ref().map_or(0, Vec::len) != 1
        {
            return Err(KmsError::Default(format!(
                "offset Locate must omit the count: {response:?}"
            )));
        }
        Ok(())
    }

    #[tokio::test]
    async fn locate_rejects_an_excessive_offset() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("locate-offset@example.com");
        let result = locate(
            &kms,
            Locate {
                offset_items: Some(MAX_LOCATE_ITEMS + 1),
                ..Locate::default()
            },
            None,
            &user,
        )
        .await;
        if !matches!(
            result,
            Err(KmsError::Kmip21Error(ErrorReason::Invalid_Field, _))
        ) {
            return Err(KmsError::Default(
                "Locate accepted an OffsetItems value above the page cap".to_owned(),
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn locate_with_zero_maximum_items_returns_an_empty_destroyed_page() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("locate-zero-page@example.com");
        let destroyed = kms
            .create(
                Create {
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(256),
                        ..Attributes::default()
                    },
                    protection_storage_masks: None,
                },
                &user,
            )
            .await?;
        kms.destroy(
            Destroy {
                unique_identifier: Some(destroyed.unique_identifier),
                ..Destroy::default()
            },
            &user,
        )
        .await?;

        let response = locate(
            &kms,
            Locate {
                maximum_items: Some(0),
                storage_status_mask: Some(StorageStatusMask::DestroyedStorage),
                ..Locate::default()
            },
            None,
            &user,
        )
        .await?;
        if response.unique_identifier.is_some() {
            return Err(KmsError::Default(
                "Locate returned objects despite MaximumItems being zero".to_owned(),
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn destroyed_only_locate_is_not_limited_before_status_filtering() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("locate-destroyed-page@example.com");
        let create = || Create {
            object_type: ObjectType::SymmetricKey,
            attributes: Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                ..Attributes::default()
            },
            protection_storage_masks: None,
        };
        kms.create(create(), &user).await?;
        let destroyed = kms.create(create(), &user).await?;
        kms.destroy(
            Destroy {
                unique_identifier: Some(destroyed.unique_identifier.clone()),
                ..Destroy::default()
            },
            &user,
        )
        .await?;

        let response = locate(
            &kms,
            Locate {
                maximum_items: Some(1),
                storage_status_mask: Some(StorageStatusMask::DestroyedStorage),
                attributes: Attributes {
                    object_type: Some(ObjectType::SymmetricKey),
                    ..Attributes::default()
                },
                ..Locate::default()
            },
            None,
            &user,
        )
        .await?;
        if response.unique_identifier != Some(vec![destroyed.unique_identifier]) {
            return Err(KmsError::Default(
                "destroyed-only Locate was limited before status filtering".to_owned(),
            ));
        }
        Ok(())
    }
    #[tokio::test]
    async fn locate_rejects_unsupported_object_group_member() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("locate-status@example.com");
        let fresh = kms
            .create(
                Create {
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(256),
                        ..Attributes::default()
                    },
                    protection_storage_masks: None,
                },
                &user,
            )
            .await?;

        let group_member_result = locate(
            &kms,
            Locate {
                object_group_member: Some(ObjectGroupMember::Group_Member_Fresh),
                ..Locate::default()
            },
            None,
            &user,
        )
        .await;
        if !matches!(
            group_member_result,
            Err(KmsError::Kmip21Error(
                cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::ErrorReason::Feature_Not_Supported,
                _
            ))
        ) {
            return Err(KmsError::Default(
                "Locate accepted unsupported Object Group Member".to_owned(),
            ));
        }

        let archival_response = locate(
            &kms,
            Locate {
                storage_status_mask: Some(StorageStatusMask::ArchivalStorage),
                attributes: Attributes {
                    unique_identifier: Some(fresh.unique_identifier.clone()),
                    ..Attributes::default()
                },
                ..Locate::default()
            },
            None,
            &user,
        )
        .await?;
        if archival_response.unique_identifier.is_some() {
            return Err(KmsError::Default(
                "Locate treated online objects as archival storage".to_owned(),
            ));
        }

        kms.destroy(
            Destroy {
                unique_identifier: Some(fresh.unique_identifier.clone()),
                ..Destroy::default()
            },
            &user,
        )
        .await?;

        let destroyed_response = locate(
            &kms,
            Locate {
                storage_status_mask: Some(StorageStatusMask::DestroyedStorage),
                attributes: Attributes {
                    unique_identifier: Some(fresh.unique_identifier.clone()),
                    ..Attributes::default()
                },
                ..Locate::default()
            },
            None,
            &user,
        )
        .await?;
        if destroyed_response.unique_identifier != Some(vec![fresh.unique_identifier]) {
            return Err(KmsError::Default(
                "Locate did not include destroyed storage when requested".to_owned(),
            ));
        }
        Ok(())
    }
}
