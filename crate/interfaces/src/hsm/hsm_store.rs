//! `HsmStore` — a single adapter that implements both `ObjectsStore` and `CryptoOracle`
//! for Hardware Security Module backends.  It consolidates what was previously two separate
//! types (`HsmStore` and `HsmCryptoOracle`) that always wrapped the same `Arc<dyn HSM>`.

use std::{collections::HashSet, sync::Arc};

use KmipKeyMaterial::TransparentRSAPublicKey;
use async_trait::async_trait;
use cosmian_kmip::{
    SafeBigInt,
    kmip_0::kmip_types::{CryptographicUsageMask, State},
    kmip_2_1::{
        extra::tagging::{SYSTEM_TAG_PRIVATE_KEY, SYSTEM_TAG_PUBLIC_KEY, SYSTEM_TAG_SYMMETRIC_KEY},
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial as KmipKeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey, SymmetricKey},
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType, RecommendedCurve,
        },
    },
};
use cosmian_logger::{debug, error, trace, warn};
use num_bigint_dig::{BigInt, Sign};
use zeroize::Zeroizing;

use crate::{
    AtomicOperation, CryptoAlgorithm, CryptoOracle, EcCurve, HSM, HsmKeyAlgorithm,
    HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, InterfaceError, InterfaceResult, KeyMaterial,
    KeyType, ObjectWithMetadata, ObjectsStore, SigningAlgorithm, UserId,
    crypto_oracle::{EncryptedContent, KeyMetadata},
};

/// Map an `EcCurve` (HSM interface curve enum) to the corresponding KMIP `RecommendedCurve`.
/// FIPS-approved NIST prime curves are always covered; the Edwards/Montgomery curves added for
/// `EdDSA`/X25519 HSM delegation (issue #1157) require the `non-fips` feature.
const fn ec_curve_to_recommended_curve(curve: EcCurve) -> RecommendedCurve {
    match curve {
        EcCurve::P224 => RecommendedCurve::P224,
        EcCurve::P256 => RecommendedCurve::P256,
        EcCurve::P384 => RecommendedCurve::P384,
        EcCurve::P521 => RecommendedCurve::P521,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed25519 => RecommendedCurve::CURVEED25519,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed448 => RecommendedCurve::CURVEED448,
        #[cfg(feature = "non-fips")]
        EcCurve::X25519 => RecommendedCurve::CURVE25519,
    }
}

const fn ec_curve_to_algorithm(curve: EcCurve) -> CryptographicAlgorithm {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => CryptographicAlgorithm::EC,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed25519 => CryptographicAlgorithm::Ed25519,
        #[cfg(feature = "non-fips")]
        EcCurve::Ed448 => CryptographicAlgorithm::Ed448,
        #[cfg(feature = "non-fips")]
        EcCurve::X25519 => CryptographicAlgorithm::ECDH,
    }
}

fn ec_curve_to_usage_mask(
    curve: Option<EcCurve>,
    object_type: ObjectType,
) -> CryptographicUsageMask {
    #[cfg(feature = "non-fips")]
    if matches!(curve, Some(EcCurve::X25519)) {
        return CryptographicUsageMask::DeriveKey;
    }
    #[cfg(not(feature = "non-fips"))]
    let _ = curve;

    if object_type == ObjectType::PublicKey {
        CryptographicUsageMask::Verify
    } else {
        CryptographicUsageMask::Sign
    }
}

const fn ec_domain_parameters_for_curve(curve: EcCurve) -> CryptographicDomainParameters {
    CryptographicDomainParameters {
        qlength: None,
        recommended_curve: Some(ec_curve_to_recommended_curve(curve)),
    }
}

fn ec_algorithm(curve: Option<EcCurve>) -> CryptographicAlgorithm {
    curve.map_or(CryptographicAlgorithm::EC, ec_curve_to_algorithm)
}

fn ec_key_format_type(object_type: ObjectType) -> KeyFormatType {
    if object_type == ObjectType::PublicKey {
        KeyFormatType::TransparentECPublicKey
    } else {
        KeyFormatType::TransparentECPrivateKey
    }
}

/// A single adapter that wraps an `Arc<dyn HSM>` and implements both [`ObjectsStore`] and
/// [`CryptoOracle`].  Callers can [`Clone`] the backend cheaply (only the inner `Arc` is
/// cloned) to register it in both the object-store and crypto-oracle maps.
#[derive(Clone)]
pub struct HsmStore {
    hsm: Arc<dyn HSM + Send + Sync>,
    hsm_admin: Vec<String>,
    vendor_id: String,
    /// UID routing prefix, e.g. `"hsm"`, `"hsm1"`, `"hsm2"`.
    prefix: String,
}

impl HsmStore {
    pub fn new(
        hsm: Arc<dyn HSM + Send + Sync>,
        hsm_admin: &[String],
        vendor_id: &str,
        prefix: &str,
    ) -> Self {
        Self {
            hsm,
            hsm_admin: hsm_admin.to_owned(),
            vendor_id: vendor_id.to_owned(),
            prefix: prefix.to_owned(),
        }
    }

    /// Returns `true` if `user` is an HSM admin.
    /// Wildcard `"*"` grants access to every user.
    fn is_admin(&self, user: &str) -> bool {
        self.hsm_admin.iter().any(|a| a == "*" || a == user)
    }

    /// Returns the name to use as the owner of HSM objects.
    /// Picks the first non-wildcard admin, falling back to `"admin"`.
    fn owner_name(&self) -> &str {
        self.hsm_admin
            .iter()
            .find(|a| a.as_str() != "*")
            .map_or("admin", String::as_str)
    }
}

#[async_trait(?Send)]
impl ObjectsStore for HsmStore {
    // Only single keys are created using this call,
    // keypair creation goes through the atomic operations
    /// Create a key on the HSM
    /// `tags` are not available on HSMs
    async fn create(
        &self,
        uid: Option<String>,
        owner: &UserId,
        object: &Object,
        attributes: &Attributes,
        _tags: &HashSet<String>,
    ) -> InterfaceResult<String> {
        if !self.is_admin(owner) {
            return Err(InterfaceError::Unauthorized(
                "Only the HSM Admin can create HSM objects".to_owned(),
            ));
        }
        // try converting the rest of the uid into a slot_id
        let uid = uid.as_ref().ok_or_else(|| {
            InterfaceError::InvalidRequest(
                format!("An HSM create request must have a uid in the form of 'hsm::<slot_id>::<key_id>'. Got {uid:?}"
            ))
        })?;
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        if object.object_type() != ObjectType::SymmetricKey {
            return Err(InterfaceError::InvalidRequest(
                "Only symmetric keys can be created on the HSM in this server".to_owned(),
            ));
        }
        let algorithm = attributes.cryptographic_algorithm.as_ref().ok_or_else(|| {
            InterfaceError::InvalidRequest(
                "Create: HSM keys must have a cryptographic algorithm specified".to_owned(),
            )
        })?;
        if *algorithm != CryptographicAlgorithm::AES {
            return Err(InterfaceError::InvalidRequest(
                "Only AES symmetric keys can be created on the HSM in this server".to_owned(),
            ));
        }
        let key_length = attributes.cryptographic_length.as_ref().ok_or_else(|| {
            InterfaceError::InvalidRequest(
                "Symmetric key must have a cryptographic length specified".to_owned(),
            )
        })?;
        self.hsm
            .create_key(
                slot_id,
                key_id.as_bytes(),
                HsmKeyAlgorithm::AES,
                usize::try_from(*key_length).map_err(|e| {
                    InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                })?,
                attributes.sensitive.unwrap_or(false),
            )
            .await?;
        debug!("Created HSM AES Key of length {key_length} with id {uid}",);
        Ok(uid.to_owned())
    }

    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        // try converting the rest of the UID into a slot_id and key id
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        match self.hsm.export(slot_id, key_id.as_bytes()).await {
            Ok(Some(hsm_object)) => {
                let mut owm =
                    to_object_with_metadata(&hsm_object, uid, self.owner_name(), &self.vendor_id)?;
                // Enrich attributes with keyset metadata from CKA_LABEL and CKA dates.
                if let Ok(Some(meta)) = self.hsm.get_key_metadata(slot_id, key_id.as_bytes()).await
                {
                    let attrs = owm.attributes_mut();
                    attrs.rotate_name = meta.rotate_name;
                    attrs.rotate_generation = meta.rotate_generation;
                    // Reconstruct rotate_interval from CKA_START_DATE / CKA_END_DATE.
                    // HsmStore::update_object is a no-op for KMIP attributes so there is
                    // no persistent KMIP storage for rotate_interval on HSM keys; we
                    // recover it as (end_date − start_date) × 86400 s so that downstream
                    // operations (e.g. auto-rotation re-key) can propagate the schedule.
                    if let (Some(start), Some(end)) = (meta.start_date, meta.end_date) {
                        let days = (end - start).whole_days();
                        if days > 0 {
                            attrs.rotate_interval = Some(days * crate::SECS_PER_DAY);
                        }
                    }
                }
                Ok(Some(owm))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                // The key cannot be exported — this may be because it is
                // non-extractable (sensitive flag in PKCS#11) or because
                // the PKCS#11 find-by-id/label re-lookup failed after initial
                // discovery. In either case, fall back to a metadata-only stub
                // so that attribute-only KMIP operations (GetAttributes, Locate
                // enrichment) succeed without accessing the key material.
                // Fixes: https://github.com/Cosmian/kms/issues/933
                debug!(
                    "HSM key {uid} export failed ({e}); falling back to metadata-only stub for \
                     attribute operations"
                );
                let meta = self
                    .hsm
                    .get_key_metadata(slot_id, key_id.as_bytes())
                    .await?;
                let Some(meta) = meta else {
                    return Ok(None);
                };
                if meta.sensitive {
                    let attrs = build_sensitive_stub_attributes(&meta);
                    let object = build_sensitive_stub_object(&meta);
                    Ok(Some(ObjectWithMetadata::new(
                        uid.to_owned(),
                        object,
                        self.owner_name().to_owned(),
                        State::Active,
                        attrs,
                    )))
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn retrieve_tags(&self, _uid: &str) -> InterfaceResult<HashSet<String>> {
        // Not supported for HSMs
        Ok(HashSet::new())
    }

    async fn update_object(
        &self,
        uid: &str,
        _object: &Object,
        _attributes: &Attributes,
        _tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()> {
        // HSM PKCS#11 slots have no generic KMIP attribute storage: attributes
        // such as Name cannot be persisted to the HSM. We return Ok so that
        // KMIP attribute-only operations (ModifyAttribute, SetAttribute) succeed
        // without error.  Operations that require key material (encrypt, decrypt,
        // wrap, unwrap) always go through the HSM crypto oracle and are unaffected.
        // See: https://github.com/Cosmian/kms/issues/933
        warn!(
            "ModifyAttribute/SetAttribute on HSM key {uid}: attribute update accepted but not \
             persisted to PKCS#11 slot (HSM does not support KMIP attribute storage)"
        );
        Ok(())
    }

    async fn update_state(&self, _uid: &str, _state: State) -> InterfaceResult<()> {
        // not supported for HSMs
        Err(InterfaceError::InvalidRequest(
            "Update state is not supported for HSMs".to_owned(),
        ))
    }

    async fn delete(&self, uid: &str) -> InterfaceResult<()> {
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        self.hsm.delete(slot_id, key_id.as_bytes()).await?;
        Ok(())
    }

    async fn atomic(
        &self,
        user: &UserId,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        if let Some((uid, _object, attributes, _tags, algorithm)) =
            is_asymmetric_keypair_creation(operations)
        {
            debug!("Creating {algorithm:?} keypair with uid: {uid}");
            if !self.is_admin(user) {
                return Err(InterfaceError::Unauthorized(
                    "Only the HSM Admin can create HSM keypairs".to_owned(),
                ));
            }
            let (slot_id, sk_id) = parse_uid_with_prefix(&uid, &self.prefix)?;
            let pk_id = sk_id.clone() + SYSTEM_TAG_PUBLIC_KEY;
            let default_key_length = match algorithm {
                HsmKeypairAlgorithm::RSA => 2048,
                HsmKeypairAlgorithm::EC => 256,
                #[cfg(feature = "non-fips")]
                HsmKeypairAlgorithm::Ed25519 | HsmKeypairAlgorithm::X25519 => 256,
                #[cfg(feature = "non-fips")]
                HsmKeypairAlgorithm::Ed448 => 456,
            };
            self.hsm
                .create_keypair(
                    slot_id,
                    sk_id.as_bytes(),
                    pk_id.as_bytes(),
                    algorithm,
                    usize::try_from(
                        attributes
                            .cryptographic_length
                            .unwrap_or(default_key_length),
                    )
                    .map_err(|e| {
                        InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                    })?,
                    attributes.sensitive.unwrap_or_default(),
                )
                .await?;
            return Ok(vec![
                format!("{}::{slot_id}::{sk_id}", self.prefix),
                format!("{}::{slot_id}::{pk_id}", self.prefix),
            ]);
        }

        // Handle attribute-only updates (e.g., Fresh flag persisted after export/get).
        // The HSM does not store KMIP metadata attributes, so delegate to update_object()
        // which already accepts gracefully without error.
        if operations
            .iter()
            .all(|op| matches!(op, AtomicOperation::UpdateObject(_)))
        {
            for op in operations {
                if let AtomicOperation::UpdateObject((uid, object, attrs, tags)) = op {
                    self.update_object(uid, object, attrs, tags.as_ref())
                        .await?;
                }
            }
            return Ok(vec![]);
        }

        Err(InterfaceError::InvalidRequest(
            "HSM atomic operations only support RSA keypair creations for now".to_owned(),
        ))
    }

    async fn is_object_owned_by(&self, _uid: &str, owner: &UserId) -> InterfaceResult<bool> {
        let is_admin = self.is_admin(owner);
        debug!("Is {owner} an HSM admin? {}", is_admin);
        Ok(is_admin)
    }

    async fn list_uids_for_tags(
        &self,
        _tags: &HashSet<String>,
    ) -> InterfaceResult<HashSet<String>> {
        // Not Tags on the HSM
        Ok(HashSet::new())
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &UserId,
        user_must_be_owner: bool,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let slot_ids = self.hsm.get_available_slot_list().await?;
        let mut uids = Vec::new();
        // When the caller requires ownership (e.g. /access/owned), non-admin
        // users should not see HSM keys — only HSM admins "own" HSM keys.
        if user_must_be_owner && !self.is_admin(user) {
            debug!(
                "User '{}' is not an HSM admin; skipping HSM keys for ownership query",
                user
            );
            return Ok(uids);
        }
        let mut search_attributes = researched_attributes.cloned().unwrap_or_else(|| {
            debug!("No researched_attributes provided. Defaulting to empty filter attributes");
            Attributes::default()
        });
        match check_basic_compatibility(vendor_id, &search_attributes, state) {
            Ok(()) => {}
            Err(e) => {
                debug!("{e}");
                return Ok(uids);
            }
        }
        let object_filter = match HsmObjectFilter::try_from(&search_attributes) {
            Ok(object_filter) => object_filter,
            Err(e) => {
                debug!("HSM find: incompatible filter, skipping HSM search: {e}");
                return Ok(uids);
            }
        };
        let key_size_filter = search_attributes.get_cryptographic_length();
        let key_id_filter = match search_attributes.unique_identifier {
            Some(unique_identifier) => {
                let Some(str) = unique_identifier.as_str() else {
                    return Ok(uids);
                };
                Some(str.to_owned())
            }
            None => None,
        };

        for slot_id in slot_ids {
            let found = self
                .hsm
                .find(slot_id, object_filter.clone())
                .await
                .unwrap_or(vec![]);
            for object_id in found {
                trace!("Getting metadata for: {:02X?}", object_id);
                let object_meta = self
                    .hsm
                    .get_key_metadata(slot_id, &object_id)
                    .await
                    .unwrap_or_default();
                if let Some(expected_key_size) = key_size_filter {
                    if let Some(ref meta) = object_meta {
                        if meta.key_length_in_bits != expected_key_size {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                let object_string = match str::from_utf8(&object_id) {
                    Ok(object_string) => object_string,
                    Err(err) => {
                        error!("Failed to decode object_id {}", err);
                        continue;
                    }
                };
                let uid = format!("{}::{slot_id}::{object_string}", self.prefix);
                trace!("Found: {uid}");
                if let Some(ref wanted_id) = key_id_filter {
                    if !uid.eq(wanted_id) {
                        continue;
                    }
                }
                // Populate basic attributes from HSM metadata so callers
                // (Locate, /access/owned) can display key info without a
                // separate GetAttributes round-trip.
                let attrs = build_find_attributes(&object_meta, &object_filter);
                uids.push((uid, State::Active, attrs));
            }
        }

        Ok(uids)
    }

    async fn find_due_for_rotation(
        &self,
        now: time::OffsetDateTime,
    ) -> InterfaceResult<Vec<(String, String)>> {
        let today = now.date();
        let slot_ids = self.hsm.get_available_slot_list().await?;
        let mut due_uids = Vec::new();

        for slot_id in slot_ids {
            let found = self
                .hsm
                .find(slot_id, HsmObjectFilter::Any)
                .await
                .unwrap_or_default();
            for object_id in found {
                let Some(meta) = self
                    .hsm
                    .get_key_metadata(slot_id, &object_id)
                    .await
                    .unwrap_or_default()
                else {
                    continue;
                };
                // A key is due for rotation when end_date is set and today >= end_date
                let Some(end_date) = meta.end_date else {
                    continue;
                };
                if today >= end_date {
                    let Ok(object_string) = std::str::from_utf8(&object_id) else {
                        continue;
                    };
                    let uid = format!("{}::{slot_id}::{object_string}", self.prefix);
                    // HSM objects have no KMIP "owner" — the HSM instance is single-tenant.
                    // Return an empty owner string; the scheduler must resolve ownership
                    // from the KMS system metadata if multi-tenancy is needed in future.
                    due_uids.push((uid, String::new()));
                }
            }
        }

        Ok(due_uids)
    }

    /// Find HSM keys by keyset name, with optional generation and latest filters.
    ///
    /// The keyset name is parsed from `CKA_LABEL` which carries the format
    /// `rotate_name::generation::key_id[@latest]`. This allows keys to be
    /// addressed by their logical name rather than their physical UID.
    async fn find_by_rotate_name(
        &self,
        name: &str,
        generation: Option<i32>,
        // PKCS#11 objects have no KMIP "owner" field — ownership cannot be filtered
        // at the HSM layer.  The KMS server is assumed to be single-tenant with respect
        // to a given HSM instance (each deployment's HSM is dedicated to one server).
        // The `owner` parameter is intentionally unused here; the SQL implementation
        // (which is multi-tenant) does filter by owner.
        _owner: &UserId,
    ) -> InterfaceResult<Vec<(String, Attributes)>> {
        let slot_ids = self.hsm.get_available_slot_list().await?;
        let mut results = Vec::new();

        for slot_id in slot_ids {
            let found = self
                .hsm
                .find(slot_id, HsmObjectFilter::Any)
                .await
                .unwrap_or_default();
            for object_id in found {
                let Some(meta) = self
                    .hsm
                    .get_key_metadata(slot_id, &object_id)
                    .await
                    .unwrap_or_default()
                else {
                    continue;
                };
                // Only consider keys that belong to this keyset
                let Some(ref key_rotate_name) = meta.rotate_name else {
                    continue;
                };
                if key_rotate_name != name {
                    continue;
                }
                // Optional generation filter
                if let Some(gen_filter) = generation {
                    if meta.rotate_generation != Some(gen_filter) {
                        continue;
                    }
                }
                // Optional latest filter — removed: caller selects max generation instead
                let Ok(object_string) = std::str::from_utf8(&object_id) else {
                    continue;
                };
                let uid = format!("{}::{slot_id}::{object_string}", self.prefix);
                let attrs = build_keyset_attributes(&meta);
                results.push((uid, attrs));
            }
        }

        Ok(results)
    }

    async fn set_key_label(&self, uid: &str, label: &str) -> InterfaceResult<()> {
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        self.hsm
            .set_key_label(slot_id, key_id.as_bytes(), label)
            .await
    }

    async fn set_key_rotation_dates(
        &self,
        uid: &str,
        start_date: Option<time::Date>,
        end_date: Option<time::Date>,
    ) -> InterfaceResult<()> {
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        self.hsm
            .set_key_dates(slot_id, key_id.as_bytes(), start_date, end_date)
            .await
    }

    /// Count all non-destroyed objects on this HSM.
    ///
    /// On an HSM every object present in a slot is by definition non-destroyed:
    /// deleted keys are physically removed from the device rather than being
    /// transitioned to a `Destroyed` state.  All HSM objects are also key
    /// material, so this delegates directly to [`Self::count_non_destroyed_keys`].
    async fn count_all_non_destroyed(&self) -> InterfaceResult<u64> {
        self.count_non_destroyed_keys().await
    }

    /// Count non-destroyed key objects across all HSM slots.
    ///
    /// All objects present in an HSM are cryptographic key material and are by
    /// definition non-destroyed (deleted keys are removed from the HSM).
    /// Each PKCS#11 slot is queried via `find(slot, HsmObjectFilter::Any)` and
    /// the returned key IDs are counted.  Slot errors are non-fatal: a failed
    /// slot contributes 0 and a warning is logged, so a single unavailable slot
    /// does not block the aggregate count.
    async fn count_non_destroyed_keys(&self) -> InterfaceResult<u64> {
        let slot_ids = self
            .hsm
            .get_available_slot_list()
            .await
            .unwrap_or_else(|e| {
                warn!("HSM count_non_destroyed_keys: failed to list slots: {e}");
                vec![]
            });
        let mut total: u64 = 0;
        for slot_id in slot_ids {
            match self.hsm.find(slot_id, HsmObjectFilter::Any).await {
                Ok(keys) => {
                    total = total.saturating_add(u64::try_from(keys.len()).unwrap_or(u64::MAX));
                }
                Err(e) => {
                    debug!("HSM count_non_destroyed_keys: slot {slot_id} query failed: {e}");
                }
            }
        }
        Ok(total)
    }

    /// HSM keys are physically stored on the device and never wrapped in KMIP format.
    async fn find_wrapped_by(
        &self,
        _wrapping_key_uid: &str,
        _user: &UserId,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        Ok(vec![])
    }

    async fn find_all(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        // HSM objects have no concept of user ownership — delegate to `find` with the HSM admin
        // user, which will return all HSM objects that match the filter.
        let owner = UserId::from(self.owner_name());
        self.find(researched_attributes, state, &owner, false, vendor_id)
            .await
    }
}

#[async_trait]
impl CryptoOracle for HsmStore {
    async fn encrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<EncryptedContent> {
        if authenticated_encryption_additional_data.is_some() {
            return Err(InterfaceError::InvalidRequest(
                "Additional authenticated data are not supported on HSMs for now".to_owned(),
            ));
        }
        let (mut slot_id, mut key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        let supported_algorithms = self.hsm.get_supported_algorithms(slot_id).await?;
        let cryptographic_algorithm = if let Some(ca) = cryptographic_algorithm {
            ca
        } else {
            debug!("Using default algorithm to encrypt");
            match self.hsm.get_key_type(slot_id, key_id.as_bytes()).await? {
                None => {
                    return Err(InterfaceError::InvalidRequest(format!(
                        "The key type of key: {uid}, cannot be determined"
                    )));
                }
                Some(key_type) => match key_type {
                    KeyType::AesKey => CryptoAlgorithm::get_aes_algorithm(&supported_algorithms)?,
                    KeyType::RsaPublicKey => {
                        CryptoAlgorithm::get_rsa_algorithm(&supported_algorithms)?
                    }
                    KeyType::RsaPrivateKey => {
                        // try fetching the corresponding public key
                        let pk_uid = format!("{uid}_pk");
                        debug!(
                            "encrypt: an RSA private key {uid} was specified. Trying to use \
                             public key {pk_uid} for encryption"
                        );
                        (slot_id, key_id) = parse_uid_with_prefix(&pk_uid, &self.prefix)?;
                        self.hsm
                            .get_key_type(slot_id, key_id.as_bytes())
                            .await?
                            .ok_or_else(|| {
                                InterfaceError::InvalidRequest(format!(
                                    "The key {uid} is a private key, but no public key {pk_uid} \
                                     is available"
                                ))
                            })?;
                        CryptoAlgorithm::get_rsa_algorithm(&supported_algorithms)?
                    }
                    KeyType::EcPrivateKey | KeyType::EcPublicKey => {
                        return Err(InterfaceError::InvalidRequest(
                            "EC keys cannot be used to encrypt: EC keys only support Sign/Verify"
                                .to_owned(),
                        ));
                    }
                },
            }
        };
        self.hsm
            .encrypt(slot_id, key_id.as_bytes(), cryptographic_algorithm, data)
            .await
    }

    async fn decrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        if authenticated_encryption_additional_data.is_some() {
            return Err(InterfaceError::InvalidRequest(
                "Additional authenticated data are not supported on HSMs for now".to_owned(),
            ));
        }
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        let supported_algorithms = self.hsm.get_supported_algorithms(slot_id).await?;
        let cryptographic_algorithm = if let Some(ca) = cryptographic_algorithm {
            ca
        } else {
            debug!("Using default algorithm to decrypt");
            match self.hsm.get_key_type(slot_id, key_id.as_bytes()).await? {
                None => {
                    return Err(InterfaceError::InvalidRequest(
                        "The key {}type is not known".to_owned(),
                    ));
                }
                Some(key_type) => match key_type {
                    KeyType::AesKey => CryptoAlgorithm::get_aes_algorithm(&supported_algorithms)?,
                    KeyType::RsaPrivateKey => {
                        CryptoAlgorithm::get_rsa_algorithm(&supported_algorithms)?
                    }
                    KeyType::RsaPublicKey => {
                        return Err(InterfaceError::Default(
                            "An RSA public key cannot be used to decrypt".to_owned(),
                        ));
                    }
                    KeyType::EcPrivateKey | KeyType::EcPublicKey => {
                        return Err(InterfaceError::InvalidRequest(
                            "EC keys cannot be used to decrypt: EC keys only support Sign/Verify"
                                .to_owned(),
                        ));
                    }
                },
            }
        };
        self.hsm
            .decrypt(slot_id, key_id.as_bytes(), cryptographic_algorithm, data)
            .await
    }

    async fn get_key_type(&self, uid: &str) -> InterfaceResult<Option<KeyType>> {
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        self.hsm.get_key_type(slot_id, key_id.as_bytes()).await
    }

    async fn get_key_metadata(&self, uid: &str) -> InterfaceResult<Option<KeyMetadata>> {
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        self.hsm.get_key_metadata(slot_id, key_id.as_bytes()).await
    }

    async fn sign(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_parameters: Option<
            &cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters,
        >,
        input_is_digest: bool,
    ) -> InterfaceResult<Vec<u8>> {
        let (slot_id, key_id) = parse_uid_with_prefix(uid, &self.prefix)?;
        let key_type = match self.hsm.get_key_type(slot_id, key_id.as_bytes()).await? {
            Some(KeyType::RsaPrivateKey) => KeyType::RsaPrivateKey,
            Some(KeyType::EcPrivateKey) => KeyType::EcPrivateKey,
            Some(other) => {
                return Err(InterfaceError::InvalidRequest(format!(
                    "Sign: key {uid} is a {other:?}, expected an RSA or EC private key"
                )));
            }
            None => {
                return Err(InterfaceError::InvalidRequest(format!(
                    "Sign: key {uid} not found on the HSM"
                )));
            }
        };
        let curve = self
            .hsm
            .get_key_metadata(slot_id, key_id.as_bytes())
            .await?
            .and_then(|metadata| metadata.curve);
        let algorithm = SigningAlgorithm::from_kmip(
            cryptographic_parameters,
            key_type,
            curve,
            input_is_digest,
            data.len(),
        )?;
        debug!("sign: using algorithm {algorithm:?} for key {uid}");
        self.hsm
            .sign(slot_id, key_id.as_bytes(), algorithm, data)
            .await
    }

    async fn signature_verify(
        &self,
        uid: &str,
        _data: &[u8],
        _signature: &[u8],
        _cryptographic_parameters: Option<
            &cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters,
        >,
    ) -> InterfaceResult<bool> {
        Err(InterfaceError::NotSupported(format!(
            "SignatureVerify via HSM is not yet implemented for key: {uid}"
        )))
    }

    async fn mac(
        &self,
        uid: &str,
        _data: &[u8],
        _cryptographic_parameters: Option<
            &cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters,
        >,
    ) -> InterfaceResult<Vec<u8>> {
        Err(InterfaceError::NotSupported(format!(
            "MAC via HSM is not yet implemented for key: {uid}"
        )))
    }

    async fn mac_verify(
        &self,
        uid: &str,
        _data: &[u8],
        _mac_data: &[u8],
        _cryptographic_parameters: Option<
            &cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters,
        >,
    ) -> InterfaceResult<bool> {
        Err(InterfaceError::NotSupported(format!(
            "MACVerify via HSM is not yet implemented for key: {uid}"
        )))
    }
}

/// Build a metadata-only `Attributes` struct for a non-extractable (sensitive) HSM key.
///
/// Used when `hsm.export()` fails with a sensitive-key error. The stub allows
/// attribute-only KMIP operations (`ModifyAttribute`, `GetAttributes`) to succeed
/// without accessing the key material.
/// See: <https://github.com/Cosmian/kms/issues/933>
fn build_sensitive_stub_attributes(meta: &KeyMetadata) -> Attributes {
    let (algorithm, obj_type, usage_mask, key_format_type) = match meta.key_type {
        KeyType::AesKey => (
            CryptographicAlgorithm::AES,
            ObjectType::SymmetricKey,
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
            KeyFormatType::Raw,
        ),
        KeyType::RsaPrivateKey => (
            CryptographicAlgorithm::RSA,
            ObjectType::PrivateKey,
            CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::Sign,
            KeyFormatType::PKCS1,
        ),
        KeyType::RsaPublicKey => (
            CryptographicAlgorithm::RSA,
            ObjectType::PublicKey,
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::Verify,
            KeyFormatType::PKCS1,
        ),
        KeyType::EcPrivateKey => (
            ec_algorithm(meta.curve),
            ObjectType::PrivateKey,
            ec_curve_to_usage_mask(meta.curve, ObjectType::PrivateKey),
            ec_key_format_type(ObjectType::PrivateKey),
        ),
        KeyType::EcPublicKey => (
            ec_algorithm(meta.curve),
            ObjectType::PublicKey,
            ec_curve_to_usage_mask(meta.curve, ObjectType::PublicKey),
            ec_key_format_type(ObjectType::PublicKey),
        ),
    };
    // Reconstruct rotate_interval from CKA_START_DATE / CKA_END_DATE.
    // HsmStore::update_object is a no-op for KMIP attributes, so this is the only
    // way to expose the scheduled interval to attribute-only callers (e.g. re-key).
    let rotate_interval = match (meta.start_date, meta.end_date) {
        (Some(start), Some(end)) => {
            let days = (end - start).whole_days();
            if days > 0 {
                Some(days * crate::SECS_PER_DAY)
            } else {
                None
            }
        }
        _ => None,
    };
    Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_length: Some(i32::try_from(meta.key_length_in_bits).unwrap_or_default()),
        object_type: Some(obj_type),
        cryptographic_usage_mask: Some(usage_mask),
        key_format_type: Some(key_format_type),
        cryptographic_domain_parameters: meta.curve.map(ec_domain_parameters_for_curve),
        sensitive: Some(meta.sensitive),
        rotate_name: meta.rotate_name.clone(),
        rotate_generation: meta.rotate_generation,
        rotate_interval,
        ..Attributes::default()
    }
}

/// Build a stub KMIP `Object` for a non-extractable (sensitive) HSM key.
///
/// The `key_value` is intentionally empty because the key bytes cannot be
/// exported from the HSM. This stub is only used for attribute-only operations.
/// See: <https://github.com/Cosmian/kms/issues/933>
fn build_sensitive_stub_object(meta: &KeyMetadata) -> Object {
    let length = i32::try_from(meta.key_length_in_bits).unwrap_or_default();
    match meta.key_type {
        KeyType::AesKey => {
            let attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(length),
                object_type: Some(ObjectType::SymmetricKey),
                sensitive: Some(meta.sensitive),
                ..Attributes::default()
            };
            Object::SymmetricKey(SymmetricKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentSymmetricKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: KmipKeyMaterial::TransparentSymmetricKey {
                            key: zeroize::Zeroizing::new(vec![]),
                        },
                        attributes: Some(attributes),
                    }),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(length),
                    key_wrapping_data: None,
                },
            })
        }
        // For RSA sensitive keys (unusual but possible), build a minimal SymmetricKey-shaped
        // stub so callers can still perform attribute-only operations.  The object_type in
        // the attributes is set correctly (PrivateKey / PublicKey).
        KeyType::RsaPrivateKey | KeyType::RsaPublicKey => {
            let obj_type = if meta.key_type == KeyType::RsaPrivateKey {
                ObjectType::PrivateKey
            } else {
                ObjectType::PublicKey
            };
            let attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(length),
                object_type: Some(obj_type),
                sensitive: Some(meta.sensitive),
                ..Attributes::default()
            };
            // Return a SymmetricKey wrapper — the key material is empty and the
            // sensitive flag signals callers not to attempt material access.
            Object::SymmetricKey(SymmetricKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentSymmetricKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: KmipKeyMaterial::TransparentSymmetricKey {
                            key: zeroize::Zeroizing::new(vec![]),
                        },
                        attributes: Some(attributes),
                    }),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(length),
                    key_wrapping_data: None,
                },
            })
        }
        KeyType::EcPrivateKey | KeyType::EcPublicKey => {
            let obj_type = if meta.key_type == KeyType::EcPrivateKey {
                ObjectType::PrivateKey
            } else {
                ObjectType::PublicKey
            };
            let algorithm = ec_algorithm(meta.curve);
            let recommended_curve =
                ec_curve_to_recommended_curve(meta.curve.unwrap_or(EcCurve::P256));
            let attributes = Attributes {
                cryptographic_algorithm: Some(algorithm),
                cryptographic_length: Some(length),
                object_type: Some(obj_type),
                key_format_type: Some(ec_key_format_type(obj_type)),
                cryptographic_domain_parameters: meta.curve.map(ec_domain_parameters_for_curve),
                sensitive: Some(meta.sensitive),
                ..Attributes::default()
            };
            if obj_type == ObjectType::PrivateKey {
                Object::PrivateKey(PrivateKey {
                    key_block: KeyBlock {
                        key_format_type: KeyFormatType::TransparentECPrivateKey,
                        key_compression_type: None,
                        key_value: Some(KeyValue::Structure {
                            key_material: KmipKeyMaterial::TransparentECPrivateKey {
                                recommended_curve,
                                d: Box::new(SafeBigInt::from_bytes_be(&[])),
                            },
                            attributes: Some(attributes),
                        }),
                        cryptographic_algorithm: Some(algorithm),
                        cryptographic_length: Some(length),
                        key_wrapping_data: None,
                    },
                })
            } else {
                Object::PublicKey(PublicKey {
                    key_block: KeyBlock {
                        key_format_type: KeyFormatType::TransparentECPublicKey,
                        key_compression_type: None,
                        key_value: Some(KeyValue::Structure {
                            key_material: KmipKeyMaterial::TransparentECPublicKey {
                                recommended_curve,
                                q_string: vec![],
                            },
                            attributes: Some(attributes),
                        }),
                        cryptographic_algorithm: Some(algorithm),
                        cryptographic_length: Some(length),
                        key_wrapping_data: None,
                    },
                })
            }
        }
    }
}

/// Build an `Attributes` struct populated with keyset metadata from `KeyMetadata`.
/// Used by `find_by_rotate_name` to return `rotate_name`/`generation`/`latest` to callers.
fn build_keyset_attributes(meta: &KeyMetadata) -> Attributes {
    let mut attrs = build_find_attributes(&Some(meta.clone()), &HsmObjectFilter::Any);
    attrs.rotate_name.clone_from(&meta.rotate_name);
    attrs.rotate_generation = meta.rotate_generation;
    attrs
}

fn build_find_attributes(meta: &Option<KeyMetadata>, filter: &HsmObjectFilter) -> Attributes {
    let mut attrs = Attributes::default();
    if let Some(m) = meta {
        attrs.cryptographic_length = Some(i32::try_from(m.key_length_in_bits).unwrap_or_default());
        match m.key_type {
            KeyType::AesKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::AES);
                attrs.object_type = Some(ObjectType::SymmetricKey);
                attrs.key_format_type = Some(KeyFormatType::Raw);
            }
            KeyType::RsaPrivateKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
                attrs.object_type = Some(ObjectType::PrivateKey);
                attrs.key_format_type = Some(KeyFormatType::PKCS1);
            }
            KeyType::RsaPublicKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
                attrs.object_type = Some(ObjectType::PublicKey);
                attrs.key_format_type = Some(KeyFormatType::PKCS1);
            }
            KeyType::EcPrivateKey => {
                attrs.cryptographic_algorithm = Some(ec_algorithm(m.curve));
                attrs.object_type = Some(ObjectType::PrivateKey);
                attrs.key_format_type = Some(ec_key_format_type(ObjectType::PrivateKey));
                attrs.cryptographic_domain_parameters = m.curve.map(ec_domain_parameters_for_curve);
            }
            KeyType::EcPublicKey => {
                attrs.cryptographic_algorithm = Some(ec_algorithm(m.curve));
                attrs.object_type = Some(ObjectType::PublicKey);
                attrs.key_format_type = Some(ec_key_format_type(ObjectType::PublicKey));
                attrs.cryptographic_domain_parameters = m.curve.map(ec_domain_parameters_for_curve);
            }
        }
    } else {
        // No metadata available — infer from the filter
        match filter {
            HsmObjectFilter::AesKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::AES);
                attrs.object_type = Some(ObjectType::SymmetricKey);
                attrs.key_format_type = Some(KeyFormatType::Raw);
            }
            HsmObjectFilter::RsaKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
            }
            HsmObjectFilter::RsaPrivateKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
                attrs.object_type = Some(ObjectType::PrivateKey);
                attrs.key_format_type = Some(KeyFormatType::PKCS1);
            }
            HsmObjectFilter::RsaPublicKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
                attrs.object_type = Some(ObjectType::PublicKey);
                attrs.key_format_type = Some(KeyFormatType::PKCS1);
            }
            HsmObjectFilter::EcKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::EC);
            }
            HsmObjectFilter::EcPrivateKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::EC);
                attrs.object_type = Some(ObjectType::PrivateKey);
                attrs.key_format_type = Some(KeyFormatType::TransparentECPrivateKey);
            }
            HsmObjectFilter::EcPublicKey => {
                attrs.cryptographic_algorithm = Some(CryptographicAlgorithm::EC);
                attrs.object_type = Some(ObjectType::PublicKey);
                attrs.key_format_type = Some(KeyFormatType::TransparentECPublicKey);
            }
            HsmObjectFilter::Any => {}
        }
    }
    attrs
}

fn check_basic_compatibility(
    vendor_id: &str,
    researched_attributes: &Attributes,
    state: Option<State>,
) -> InterfaceResult<()> {
    // HSM keys are always active.
    if let Some(s) = state {
        if s != State::Active {
            return Err(InterfaceError::Default(format!(
                "Unsupported state for HSMs: expected Active, got {s:?}"
            )));
        }
    }

    if researched_attributes.link.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: link".to_owned(),
        ));
    }

    if !researched_attributes.get_tags(vendor_id).is_empty() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: tags".to_owned(),
        ));
    }

    if researched_attributes.object_group.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: object_group".to_owned(),
        ));
    }

    if researched_attributes.object_group_member.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: object_group_member".to_owned(),
        ));
    }

    if researched_attributes.comment.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: comment".to_owned(),
        ));
    }

    if researched_attributes.contact_information.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: contact_information".to_owned(),
        ));
    }

    if let Some(critical) = researched_attributes.critical {
        if critical {
            return Err(InterfaceError::Default(
                "Unsupported attribute for HSMs: critical = true".to_owned(),
            ));
        }
    }

    if researched_attributes.description.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: description".to_owned(),
        ));
    }

    if researched_attributes.digest.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: digest".to_owned(),
        ));
    }

    if researched_attributes.short_unique_identifier.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: short_unique_identifier".to_owned(),
        ));
    }

    if researched_attributes.cryptographic_usage_mask.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: cryptographic_usage_mask".to_owned(),
        ));
    }

    if researched_attributes.x_509_certificate_identifier.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: x_509_certificate_identifier".to_owned(),
        ));
    }

    if researched_attributes.x_509_certificate_issuer.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: x_509_certificate_issuer".to_owned(),
        ));
    }

    if researched_attributes.x_509_certificate_subject.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: x_509_certificate_subject".to_owned(),
        ));
    }

    // HSM keys do not have KMIP Name attributes.  If the caller filters by Name,
    // no HSM key can ever match — return empty rather than ignoring the filter
    // and leaking unrelated internal keys (e.g. the server KEK). (issue #935)
    if researched_attributes
        .name
        .as_ref()
        .is_some_and(|names| !names.is_empty())
    {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: name".to_owned(),
        ));
    }

    // HSM keys do not carry ApplicationSpecificInformation; filter should return empty.
    if researched_attributes
        .application_specific_information
        .is_some()
    {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: application_specific_information".to_owned(),
        ));
    }

    Ok(())
}

/// The creation of RSA/EC key pairs is done via 2 atomic operations,
/// one to create the private key and one to generate the public key.
/// All the information we need is contained in the atomic operation
/// to create the private key, so we recover it here
///
/// # Returns
/// - the UID of the private key
/// - the object of the private key
/// - the attributes of the private key
/// - the `HsmKeypairAlgorithm` to delegate key generation to (RSA or EC)
fn is_asymmetric_keypair_creation(
    operations: &[AtomicOperation],
) -> Option<(
    String,
    Object,
    Attributes,
    HashSet<String>,
    HsmKeypairAlgorithm,
)> {
    operations.iter().find_map(|op| match op {
        AtomicOperation::Create((uid, _owner, object, attributes, tags)) => {
            if object.object_type() != ObjectType::PrivateKey {
                return None;
            }
            let algorithm = match attributes.cryptographic_algorithm {
                Some(CryptographicAlgorithm::RSA) => HsmKeypairAlgorithm::RSA,
                // X25519 is requested via CryptographicAlgorithm::ECDH + a CURVE25519
                // RecommendedCurve (KMIP has no dedicated "X25519" CryptographicAlgorithm);
                // any other ECDH/EC/ECDSA request maps to a NIST prime curve (issue #1157).
                #[cfg(feature = "non-fips")]
                Some(CryptographicAlgorithm::ECDH)
                    if matches!(
                        attributes
                            .cryptographic_domain_parameters
                            .as_ref()
                            .and_then(|cdp| cdp.recommended_curve),
                        Some(RecommendedCurve::CURVE25519)
                    ) =>
                {
                    HsmKeypairAlgorithm::X25519
                }
                Some(
                    CryptographicAlgorithm::EC
                    | CryptographicAlgorithm::ECDH
                    | CryptographicAlgorithm::ECDSA,
                ) => HsmKeypairAlgorithm::EC,
                #[cfg(feature = "non-fips")]
                Some(CryptographicAlgorithm::Ed25519) => HsmKeypairAlgorithm::Ed25519,
                #[cfg(feature = "non-fips")]
                Some(CryptographicAlgorithm::Ed448) => HsmKeypairAlgorithm::Ed448,
                _ => return None,
            };
            Some((
                uid.clone(),
                object.clone(),
                attributes.clone(),
                tags.clone(),
                algorithm,
            ))
        }
        _ => None,
    })
}

/// Parse the `uid` into a `(slot_id, key_id)` pair, stripping the given prefix.
fn parse_uid_with_prefix(uid: &str, prefix: &str) -> Result<(usize, String), InterfaceError> {
    let rest = uid
        .strip_prefix(&format!("{prefix}::"))
        .ok_or_else(|| {
            InterfaceError::InvalidRequest(format!(
                "An HSM request must have a uid in the form of '{prefix}::<slot_id>::<key_id>', got: {uid}"
            ))
        })?;
    let (slot_id, key_id) = rest.split_once("::").ok_or_else(|| {
        InterfaceError::InvalidRequest(format!(
            "An HSM request must have a uid in the form of '{prefix}::<slot_id>::<key_id>', got: {uid}"
        ))
    })?;
    let slot_id = slot_id.parse::<usize>().map_err(|e| {
        InterfaceError::InvalidRequest(format!("The slot_id must be a valid unsigned integer: {e}"))
    })?;
    Ok((slot_id, key_id.to_owned()))
}

fn to_object_with_metadata(
    hsm_object: &HsmObject,
    uid: &str,
    user: &str,
    vendor_id: &str,
) -> InterfaceResult<ObjectWithMetadata> {
    match hsm_object.key_material() {
        KeyMaterial::AesKey(bytes) => {
            let length: i32 = 8 * i32::try_from(bytes.len())
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid key length: {e}")))?;
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(length),
                object_type: Some(ObjectType::SymmetricKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt
                        | CryptographicUsageMask::Decrypt
                        | CryptographicUsageMask::WrapKey
                        | CryptographicUsageMask::UnwrapKey
                        | CryptographicUsageMask::KeyAgreement,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert(SYSTEM_TAG_SYMMETRIC_KEY.to_owned());
            attributes
                .set_tags(vendor_id, tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = KmipKeyMaterial::TransparentSymmetricKey { key: bytes.clone() };
            let object = Object::SymmetricKey(SymmetricKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentSymmetricKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(
                        8 * i32::try_from(bytes.len()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })?,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                State::Active,
                attributes,
            ))
        }
        KeyMaterial::RsaPrivateKey(km) => {
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(
                    8 * i32::try_from(km.modulus.len()).map_err(|e| {
                        InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                    })?,
                ),
                object_type: Some(ObjectType::PrivateKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Decrypt
                        | CryptographicUsageMask::UnwrapKey
                        | CryptographicUsageMask::Sign,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert(SYSTEM_TAG_PRIVATE_KEY.to_owned());
            attributes
                .set_tags(vendor_id, tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = KmipKeyMaterial::TransparentRSAPrivateKey {
                modulus: Box::new(BigInt::from_bytes_be(Sign::Plus, km.modulus.as_slice())),
                private_exponent: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.private_exponent.as_slice(),
                ))),
                public_exponent: Some(Box::new(BigInt::from_bytes_be(
                    Sign::Plus,
                    km.public_exponent.as_slice(),
                ))),
                p: Some(Box::new(SafeBigInt::from_bytes_be(km.prime_1.as_slice()))),
                q: Some(Box::new(SafeBigInt::from_bytes_be(km.prime_2.as_slice()))),
                prime_exponent_p: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.exponent_1.as_slice(),
                ))),
                prime_exponent_q: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.exponent_2.as_slice(),
                ))),
                c_r_t_coefficient: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.coefficient.as_slice(),
                ))),
            };
            let object = Object::PrivateKey(PrivateKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPrivateKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(
                        8 * i32::try_from(km.modulus.len()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })?,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                State::Active,
                attributes,
            ))
        }
        KeyMaterial::RsaPublicKey(km) => {
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(
                    i32::try_from(km.modulus.len()).map_err(|e| {
                        InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                    })? * 8,
                ),
                object_type: Some(ObjectType::PublicKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt
                        | CryptographicUsageMask::WrapKey
                        | CryptographicUsageMask::Verify,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert(SYSTEM_TAG_PUBLIC_KEY.to_owned());
            attributes
                .set_tags(vendor_id, tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = TransparentRSAPublicKey {
                modulus: Box::new(BigInt::from_bytes_be(Sign::Plus, km.modulus.as_slice())),
                public_exponent: Box::new(BigInt::from_bytes_be(
                    Sign::Plus,
                    km.public_exponent.as_slice(),
                )),
            };
            let object = Object::PublicKey(PublicKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPublicKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(
                        i32::try_from(km.modulus.len()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })? * 8,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                State::Active,
                attributes,
            ))
        }
        KeyMaterial::EcPrivateKey(km) => {
            let recommended_curve = ec_curve_to_recommended_curve(km.curve);
            let algorithm = ec_curve_to_algorithm(km.curve);
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(algorithm),
                cryptographic_length: Some(i32::try_from(km.curve.key_length_in_bits()).map_err(
                    |e| InterfaceError::InvalidRequest(format!("Invalid key length: {e}")),
                )?),
                object_type: Some(ObjectType::PrivateKey),
                cryptographic_usage_mask: Some(ec_curve_to_usage_mask(
                    Some(km.curve),
                    ObjectType::PrivateKey,
                )),
                key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
                cryptographic_domain_parameters: Some(ec_domain_parameters_for_curve(km.curve)),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert(SYSTEM_TAG_PRIVATE_KEY.to_owned());
            attributes
                .set_tags(vendor_id, tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = KmipKeyMaterial::TransparentECPrivateKey {
                recommended_curve,
                d: Box::new(SafeBigInt::from_bytes_be(km.d.as_slice())),
            };
            let object = Object::PrivateKey(PrivateKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentECPrivateKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
                    cryptographic_algorithm: Some(algorithm),
                    cryptographic_length: Some(
                        i32::try_from(km.curve.key_length_in_bits()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })?,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                State::Active,
                attributes,
            ))
        }
        KeyMaterial::EcPublicKey(km) => {
            let recommended_curve = ec_curve_to_recommended_curve(km.curve);
            let algorithm = ec_curve_to_algorithm(km.curve);
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(algorithm),
                cryptographic_length: Some(i32::try_from(km.curve.key_length_in_bits()).map_err(
                    |e| InterfaceError::InvalidRequest(format!("Invalid key length: {e}")),
                )?),
                object_type: Some(ObjectType::PublicKey),
                cryptographic_usage_mask: Some(ec_curve_to_usage_mask(
                    Some(km.curve),
                    ObjectType::PublicKey,
                )),
                key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                cryptographic_domain_parameters: Some(ec_domain_parameters_for_curve(km.curve)),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert(SYSTEM_TAG_PUBLIC_KEY.to_owned());
            attributes
                .set_tags(vendor_id, tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = KmipKeyMaterial::TransparentECPublicKey {
                recommended_curve,
                q_string: km.q.clone(),
            };
            let object = Object::PublicKey(PublicKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentECPublicKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
                    cryptographic_algorithm: Some(algorithm),
                    cryptographic_length: Some(
                        i32::try_from(km.curve.key_length_in_bits()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })?,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                State::Active,
                attributes,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    #[cfg(feature = "non-fips")]
    use cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;
    use cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_types::{CryptographicAlgorithm, Name, NameType, RecommendedCurve},
    };
    #[cfg(feature = "non-fips")]
    use cosmian_kmip::kmip_2_1::{
        kmip_data_structures::{KeyMaterial as KmipKeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_types::KeyFormatType,
    };
    use zeroize::Zeroizing;

    use super::check_basic_compatibility;
    #[cfg(feature = "non-fips")]
    use super::{
        build_sensitive_stub_attributes, build_sensitive_stub_object, to_object_with_metadata,
    };
    use crate::{
        CryptoAlgorithm, EcCurve, HSM, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject,
        HsmObjectFilter, InterfaceError, InterfaceResult, KeyMetadata, KeyType, ObjectsStore,
        SigningAlgorithm, crypto_oracle::EncryptedContent, hsm::HsmStore,
    };
    #[cfg(feature = "non-fips")]
    use crate::{EcPrivateKeyMaterial, KeyMaterial};

    // ── mockall-generated test double for HSM ─────────────────────────────────

    mockall::mock! {
        /// Auto-generated test double for the `HSM` trait.
        /// All async methods get expectation machinery; `hsm_lib` is a concrete
        /// no-op implementation that always returns `None` (avoids mockall's
        /// limitations with `&self`-bounded reference return types).
        pub Hsm {}

        #[async_trait]
        impl HSM for Hsm {
            async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>>;
            async fn find(
                &self,
                slot_id: usize,
                object_filter: HsmObjectFilter,
            ) -> InterfaceResult<Vec<Vec<u8>>>;
            async fn get_supported_algorithms(
                &self,
                slot_id: usize,
            ) -> InterfaceResult<Vec<CryptoAlgorithm>>;
            async fn create_key(
                &self,
                slot_id: usize,
                id: &[u8],
                algorithm: HsmKeyAlgorithm,
                key_length_in_bits: usize,
                sensitive: bool,
            ) -> InterfaceResult<()>;
            async fn create_keypair(
                &self,
                slot_id: usize,
                sk_id: &[u8],
                pk_id: &[u8],
                algorithm: HsmKeypairAlgorithm,
                key_length_in_bits: usize,
                sensitive: bool,
            ) -> InterfaceResult<()>;
            async fn export(
                &self,
                slot_id: usize,
                object_id: &[u8],
            ) -> InterfaceResult<Option<HsmObject>>;
            async fn delete(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<()>;
            async fn encrypt(
                &self,
                slot_id: usize,
                key_id: &[u8],
                algorithm: CryptoAlgorithm,
                data: &[u8],
            ) -> InterfaceResult<EncryptedContent>;
            async fn decrypt(
                &self,
                slot_id: usize,
                key_id: &[u8],
                algorithm: CryptoAlgorithm,
                data: &[u8],
            ) -> InterfaceResult<Zeroizing<Vec<u8>>>;
            async fn get_key_type(
                &self,
                slot_id: usize,
                key_id: &[u8],
            ) -> InterfaceResult<Option<KeyType>>;
            async fn get_key_metadata(
                &self,
                slot_id: usize,
                key_id: &[u8],
            ) -> InterfaceResult<Option<KeyMetadata>>;
            async fn sign(
                &self,
                slot_id: usize,
                key_id: &[u8],
                algorithm: SigningAlgorithm,
                data: &[u8],
            ) -> InterfaceResult<Vec<u8>>;
            async fn generate_random(
                &self,
                slot_id: usize,
                len: usize,
            ) -> InterfaceResult<Vec<u8>>;
            async fn seed_random(&self, slot_id: usize, seed: &[u8]) -> InterfaceResult<()>;
            async fn set_key_dates(
                &self,
                slot_id: usize,
                key_id: &[u8],
                start_date: Option<time::Date>,
                end_date: Option<time::Date>,
            ) -> InterfaceResult<()>;
            async fn set_key_label(
                &self,
                slot_id: usize,
                key_id: &[u8],
                label: &str,
            ) -> InterfaceResult<()>;
            fn hsm_lib(&self) -> Option<&'static dyn std::any::Any> { None }
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Locate with a Name filter must not match any HSM key (issue #935):
    /// HSM keys have no KMIP Name, so the filter should yield empty results
    /// rather than silently ignoring the Name and leaking internal keys.
    #[test]
    fn test_name_filter_rejected_for_hsm() {
        let attrs = Attributes {
            name: Some(vec![Name {
                name_value: "test-duplicate".to_owned(),
                name_type: NameType::UninterpretedTextString,
            }]),
            ..Default::default()
        };

        let result = check_basic_compatibility("cosmian", &attrs, None);
        assert!(
            matches!(result, Err(InterfaceError::Default(ref msg)) if msg.contains("name")),
            "Expected name attribute to be rejected for HSM, got: {result:?}"
        );
    }

    /// Locate with no Name filter should be compatible (basic `SymmetricKey` search).
    #[test]
    fn test_no_name_filter_compatible() {
        use cosmian_kmip::kmip_2_1::kmip_objects::ObjectType;
        let attrs = Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Default::default()
        };

        let result = check_basic_compatibility("cosmian", &attrs, None);
        assert!(
            result.is_ok(),
            "Expected ObjectType-only filter to be compatible with HSM, got: {result:?}"
        );
    }

    /// `count_all_non_destroyed` must equal `count_non_destroyed_keys` for an `HsmStore`
    /// because all objects present on an HSM are non-destroyed key material by definition.
    ///
    /// Uses a `MockHsm` with two slots (3 + 2 keys) to verify that both methods return 5
    /// and that `count_all_non_destroyed` is not hard-coded to 0.
    #[tokio::test]
    async fn test_count_all_non_destroyed_delegates_to_count_non_destroyed_keys()
    -> InterfaceResult<()> {
        let mut mock = MockHsm::new();
        mock.expect_get_available_slot_list()
            .returning(|| Ok(vec![0, 1]));
        mock.expect_find()
            .returning(|slot_id, _filter| match slot_id {
                0 => Ok(vec![vec![0], vec![1], vec![2]]), // 3 keys in slot 0
                1 => Ok(vec![vec![0], vec![1]]),          // 2 keys in slot 1
                _ => Ok(vec![]),
            });

        let store = HsmStore::new(Arc::new(mock), &["admin".to_owned()], "cosmian", "hsm");

        let via_all = store.count_all_non_destroyed().await?;
        let via_keys = store.count_non_destroyed_keys().await?;

        if via_all != 5 {
            return Err(InterfaceError::Default(format!(
                "count_all_non_destroyed should return 5 (3+2), got {via_all}"
            )));
        }
        if via_all != via_keys {
            return Err(InterfaceError::Default(format!(
                "count_all_non_destroyed ({via_all}) must equal count_non_destroyed_keys \
                 ({via_keys}) for HsmStore"
            )));
        }
        Ok(())
    }

    #[test]
    fn test_hsm_object_filter_accepts_ecdh_filters() {
        let attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            object_type: Some(ObjectType::PublicKey),
            ..Default::default()
        };

        assert!(matches!(
            HsmObjectFilter::try_from(&attrs),
            Ok(HsmObjectFilter::EcPublicKey)
        ));
    }

    #[test]
    fn test_ec_domain_parameters_leave_qlength_unset() {
        let params = super::ec_domain_parameters_for_curve(EcCurve::P384);
        assert_eq!(params.qlength, None);
        assert_eq!(params.recommended_curve, Some(RecommendedCurve::P384));
    }

    #[tokio::test]
    async fn test_retrieve_non_sensitive_export_error_is_propagated() {
        let mut mock = MockHsm::new();
        mock.expect_export()
            .return_once(|_, _| Err(InterfaceError::Default("export failed".to_owned())));
        mock.expect_get_key_metadata().return_once(|_, _| {
            Ok(Some(KeyMetadata {
                key_type: KeyType::EcPrivateKey,
                key_length_in_bits: 256,
                sensitive: false,
                id: "key".to_owned(),
                curve: Some(EcCurve::P256),
                start_date: None,
                end_date: None,
                rotate_name: None,
                rotate_generation: None,
            }))
        });

        let store = HsmStore::new(Arc::new(mock), &["admin".to_owned()], "cosmian", "hsm");
        let result = store.retrieve("hsm::1::key").await;

        assert!(matches!(
            result,
            Err(InterfaceError::Default(ref msg)) if msg == "export failed"
        ));
    }

    #[tokio::test]
    async fn test_retrieve_sensitive_export_error_falls_back_to_stub() {
        let mut mock = MockHsm::new();
        mock.expect_export()
            .return_once(|_, _| Err(InterfaceError::Default("sensitive".to_owned())));
        mock.expect_get_key_metadata().return_once(|_, _| {
            Ok(Some(KeyMetadata {
                key_type: KeyType::EcPrivateKey,
                key_length_in_bits: 256,
                sensitive: true,
                id: "key".to_owned(),
                curve: Some(EcCurve::P256),
                start_date: None,
                end_date: None,
                rotate_name: None,
                rotate_generation: None,
            }))
        });

        let store = HsmStore::new(Arc::new(mock), &["admin".to_owned()], "cosmian", "hsm");
        let result = store.retrieve("hsm::1::key").await;
        assert!(result.is_ok());
        let Ok(result) = result else {
            return;
        };
        assert!(result.is_some());
        let Some(owm) = result else {
            return;
        };

        assert_eq!(owm.attributes().sensitive, Some(true));
        assert_eq!(owm.attributes().object_type, Some(ObjectType::PrivateKey));
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn test_hsm_object_filter_accepts_eddsa_filters() {
        for algorithm in [
            CryptographicAlgorithm::Ed25519,
            CryptographicAlgorithm::Ed448,
        ] {
            let attrs = Attributes {
                cryptographic_algorithm: Some(algorithm),
                object_type: Some(ObjectType::PrivateKey),
                ..Default::default()
            };

            assert!(matches!(
                HsmObjectFilter::try_from(&attrs),
                Ok(HsmObjectFilter::EcPrivateKey)
            ));
        }
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn test_sensitive_x25519_stub_preserves_ecdh_metadata() {
        let meta = KeyMetadata {
            key_type: KeyType::EcPrivateKey,
            key_length_in_bits: 256,
            sensitive: true,
            id: "x25519".to_owned(),
            curve: Some(EcCurve::X25519),
            start_date: None,
            end_date: None,
            rotate_name: None,
            rotate_generation: None,
        };

        let attrs = build_sensitive_stub_attributes(&meta);
        assert_eq!(
            attrs.cryptographic_algorithm,
            Some(CryptographicAlgorithm::ECDH)
        );
        assert_eq!(
            attrs.cryptographic_usage_mask,
            Some(CryptographicUsageMask::DeriveKey)
        );
        assert_eq!(
            attrs.key_format_type,
            Some(KeyFormatType::TransparentECPrivateKey)
        );
        assert_eq!(
            attrs
                .cryptographic_domain_parameters
                .and_then(|params| params.recommended_curve),
            Some(RecommendedCurve::CURVE25519)
        );
        let object = build_sensitive_stub_object(&meta);
        assert!(matches!(object, Object::PrivateKey(_)));
        let Object::PrivateKey(private_key) = object else {
            return;
        };
        assert_eq!(
            private_key.key_block.cryptographic_algorithm,
            Some(CryptographicAlgorithm::ECDH)
        );
        assert!(matches!(
            private_key.key_block.key_value.as_ref(),
            Some(KeyValue::Structure {
                key_material: KmipKeyMaterial::TransparentECPrivateKey {
                    recommended_curve: RecommendedCurve::CURVE25519,
                    ..
                },
                ..
            })
        ));
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn test_to_object_with_metadata_preserves_eddsa_algorithm() {
        let hsm_object = HsmObject::new(
            KeyMaterial::EcPrivateKey(EcPrivateKeyMaterial {
                curve: EcCurve::Ed25519,
                d: Zeroizing::new(vec![1; 32]),
            }),
            "[]".to_owned(),
        );
        let owm_result =
            to_object_with_metadata(&hsm_object, "hsm::1::ed25519", "admin", "cosmian");
        assert!(owm_result.is_ok());
        let Ok(owm) = owm_result else {
            return;
        };
        let attrs = owm.attributes();
        assert_eq!(
            attrs.cryptographic_algorithm,
            Some(CryptographicAlgorithm::Ed25519)
        );
        assert_eq!(
            attrs.key_format_type,
            Some(KeyFormatType::TransparentECPrivateKey)
        );
        assert_eq!(
            attrs
                .cryptographic_domain_parameters
                .as_ref()
                .and_then(|params| params.recommended_curve),
            Some(RecommendedCurve::CURVEED25519)
        );
    }
}
