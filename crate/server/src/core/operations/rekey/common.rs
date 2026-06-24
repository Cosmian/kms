//! Shared logic for KMIP `ReKey` (§6.1.46), `ReKeyKeyPair` (§6.1.47), and `ReCertify` (§6.1.45) operations.
//!
//! All section references are to KMIP 2.1 (OASIS Standard).
//!
//! All rotation operations follow the same pattern via the [`RekeyOperation`] trait:
//! - Validate inputs and resolve candidates for rotation.
//! - Detect wrapping context on existing objects.
//! - Generate replacement material (new key/cert) with fresh UIDs.
//! - Prepare attributes: links, lifecycle dates, rotation metadata.
//! - Re-wrap new objects if the originals were wrapped.
//! - Phase 1: persist new objects atomically.
//! - Phase 2: retire old objects, finalize dependants (rewrap keys / relink certs).
//! - Build and return the KMIP response.

use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::KeyWrappingSpecification,
            kmip_objects::{Object, ObjectType},
            kmip_types::{
                EncodingOption, EncryptionKeyInformation, LinkType, LinkedObjectIdentifier,
                UniqueIdentifier,
            },
        },
        time_normalize,
    },
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use cosmian_logger::{info, warn};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::{
        KMS,
        operations::key_ops::setup_object_lifecycle,
        wrapping::{unwrap_object, wrap_and_cache, wrap_object},
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

// ─── Shared helpers (used by all rotation trait implementors) ────────────────

/// Copy the `WrappingKeyLink` from an old (wrapped) object to the new object's attributes.
///
/// If the old object was wrapped, the wrapping key UID is preserved as a
/// `LinkType::WrappingKeyLink` on the replacement's attributes so that
/// dependant re-wrapping and attribute queries work correctly.
pub(crate) fn preserve_wrapping_key_link(old_object: &Object, new_attrs: &mut Attributes) {
    if let Some(wrapping_key_uid) = old_object.wrapping_key_uid() {
        new_attrs.set_link(
            LinkType::WrappingKeyLink,
            LinkedObjectIdentifier::TextString(wrapping_key_uid),
        );
    }
}

/// Retrieve all eligible objects matching the given identifier, filtered by state and type.
///
/// Filters by:
/// - State: `Active`, `Deactivated`, or `Compromised`.
///   - `Active` / `Deactivated`: clearly eligible per KMIP §6.1.46 (`Wrong_Key_Lifecycle_State`
///     is not listed as a possible error, confirming Deactivated keys are rotatable).
///   - `Compromised`: explicitly allowed because the primary response to a key compromise is
///     to rotate it immediately — blocking rotation of compromised keys would be
///     counter-productive from a security standpoint.
///   - `PreActive`: rejected — key material has not yet entered service; rotation is meaningless.
///   - `Destroyed` / `Destroyed_Compromised`: rejected — key material is gone; nothing to rotate.
/// - Object type: the specified `object_type`
///
/// When a specific UID resolves to a key of the correct type but in an
/// ineligible state, an explicit error is returned rather than silently
/// skipping. For tag-based queries, ineligible keys are filtered out.
pub(crate) async fn retrieve_eligible_keys(
    kms: &KMS,
    uid_or_tags: &str,
    object_type: ObjectType,
) -> KResult<Vec<ObjectWithMetadata>> {
    let is_tag_query = uid_or_tags.starts_with('[');
    let objects = kms.database.retrieve_objects(uid_or_tags).await?;
    let mut eligible = Vec::new();

    for owm in objects.into_values() {
        if owm.object().object_type() != object_type {
            continue;
        }
        let is_eligible = matches!(
            owm.state(),
            State::Active | State::Deactivated | State::Compromised
        );
        if !is_eligible {
            // For direct UID queries, give an explicit error instead of silently skipping
            if !is_tag_query {
                return Err(KmsError::InvalidRequest(format!(
                    "key '{}' is in state '{}' — only Active, Deactivated, or Compromised keys \
                     can be rotated",
                    owm.id(),
                    owm.state()
                )));
            }
            continue;
        }
        eligible.push(owm);
    }
    Ok(eligible)
}

// ─── Trait: RekeyOperation ───────────────────────────────────────────────────

/// An existing object that is a candidate for rotation.
#[allow(dead_code)]
pub(crate) struct RotationCandidate {
    /// The object-with-metadata from the database.
    pub owm: ObjectWithMetadata,
    /// The UID of this object.
    pub uid: String,
    /// The KMIP object type.
    pub object_type: ObjectType,
}

/// A newly generated replacement object ready for Phase 1 commit.
#[allow(dead_code)]
pub(crate) struct ReplacementObject {
    /// The fresh UID for the replacement.
    pub new_uid: String,
    /// The UID of the old object being replaced.
    pub old_uid: String,
    /// The new KMIP object (key or certificate).
    pub object: Object,
    /// Attributes for the new object.
    pub attributes: Attributes,
    /// Tags for the new object (used in `AtomicOperation::Create`).
    pub tags: HashSet<String>,
    /// If `Some`, dependants of the old object will be re-wrapped/re-linked
    /// to this UID during Phase 2. `None` means no dependant processing for this slot.
    pub rewrap_to: Option<String>,
}

/// Unified trait for all rotation operations: `ReKey`, `ReKeyKeyPair`, and `ReCertify`.
///
/// Each implementor provides type-specific logic for the 8 steps of the rotation pipeline.
/// The shared [`execute_rekey`] orchestrator drives the pipeline in order.
///
/// The associated types `Candidates` and `Replacements` encode the expected cardinality
/// at compile time (e.g. `[RotationCandidate; 1]` for symmetric, `[RotationCandidate; 2]`
/// for key pairs), eliminating runtime indexing errors.
pub(crate) trait RekeyOperation {
    /// The KMIP request type (e.g. `ReKey`, `ReKeyKeyPair`, `Certify`).
    type Request;
    /// The KMIP response type (e.g. `ReKeyResponse`, `ReKeyKeyPairResponse`).
    type Response;
    /// The set of rotation candidates produced by [`Self::validate`].
    /// Use `[RotationCandidate; 1]` for single-object operations (symmetric, certificate)
    /// or `[RotationCandidate; 2]` for key pairs (SK + PK).
    type Candidates: AsRef<[RotationCandidate]>;
    /// The set of replacement objects produced by [`Self::generate_replacement`].
    /// Use `[ReplacementObject; 1]` for single-object operations
    /// or `[ReplacementObject; 2]` for key pairs.
    type Replacements: AsRef<[ReplacementObject]> + AsMut<[ReplacementObject]>;

    /// Step 1: Parse request, validate inputs, check permissions.
    ///
    /// Returns [`Self::Candidates`] — the existing objects eligible for rotation.
    fn validate(
        &self,
        kms: &KMS,
        request: &Self::Request,
        user: &str,
    ) -> impl std::future::Future<Output = KResult<Self::Candidates>>;

    /// Step 2: Detect wrapping context on existing object(s).
    ///
    /// Returns one `Option<KeyWrappingSpecification>` per candidate.
    /// The default implementation extracts wrapping data from each candidate's key block.
    /// Certificates (which have no key block) naturally return `None`.
    fn detect_wrapping(
        &self,
        candidates: &Self::Candidates,
    ) -> Vec<Option<KeyWrappingSpecification>> {
        candidates
            .as_ref()
            .iter()
            .map(|c| c.owm.object().rewrap_spec())
            .collect()
    }

    /// Step 3: Generate replacement material (new key/cert + fresh UIDs).
    ///
    /// Returns [`Self::Replacements`] — one replacement per candidate.
    fn generate_replacement(
        &self,
        kms: &KMS,
        candidates: &Self::Candidates,
    ) -> impl std::future::Future<Output = KResult<Self::Replacements>>;

    /// Step 4: Prepare attributes — links, lifecycle dates, rotation metadata.
    fn prepare_attributes(
        &self,
        kms: &KMS,
        candidates: &Self::Candidates,
        replacements: &mut Self::Replacements,
    ) -> KResult<()>;

    /// Step 5: Re-wrap new objects if originals were wrapped.
    ///
    /// The default implementation handles both:
    /// 1. Server-wide KEK wrapping (via `wrap_and_cache` — no-op if no KEK configured)
    /// 2. Re-wrapping with the same spec as the old object (if it was wrapped)
    ///
    /// Certificates should override with a no-op since they are never wrapped.
    fn rewrap_new_objects(
        &self,
        kms: &KMS,
        user: &str,
        replacements: &mut Self::Replacements,
        wrap_specs: &[Option<KeyWrappingSpecification>],
    ) -> impl std::future::Future<Output = KResult<()>> {
        default_rewrap_new_objects(kms, user, replacements.as_mut(), wrap_specs)
    }

    /// Step 6: Phase 1 — persist new objects atomically.
    ///
    /// The default implementation creates all replacement objects in a single atomic transaction.
    fn persist_new_key(
        &self,
        kms: &KMS,
        user: &str,
        replacements: &Self::Replacements,
    ) -> impl std::future::Future<Output = KResult<()>> {
        async move {
            let operations: Vec<AtomicOperation> = replacements
                .as_ref()
                .iter()
                .map(|r| {
                    AtomicOperation::Create((
                        r.new_uid.clone(),
                        r.object.clone(),
                        r.attributes.clone(),
                        r.tags.clone(),
                    ))
                })
                .collect();
            kms.database.atomic(user, &operations).await?;
            Ok(())
        }
    }

    /// Step 7: Phase 2 — retire old objects + finalize dependants.
    ///
    /// For keys: rewrap all dependants with the new wrapping key.
    /// For certificates: relink keys' `CertificateLink` to the new cert UID.
    ///
    /// The default implementation builds [`KeyRetirement`] entries from each
    /// candidate/replacement pair and delegates to [`finalize_rekey`].
    /// Override this for certificate-specific logic.
    fn finalize_dependants(
        &self,
        kms: &KMS,
        user: &str,
        candidates: &Self::Candidates,
        replacements: &Self::Replacements,
    ) -> impl std::future::Future<Output = KResult<()>> {
        default_finalize_dependants(kms, user, candidates.as_ref(), replacements.as_ref())
    }

    /// Step 8: Build the KMIP response from the completed replacements.
    fn build_response(&self, replacements: &Self::Replacements) -> Self::Response;
}

/// Default implementation for [`RekeyOperation::finalize_dependants`].
///
/// Builds [`KeyRetirement`] entries from each candidate/replacement pair,
/// delegates to [`finalize_rekey`], and logs the result.
async fn default_finalize_dependants(
    kms: &KMS,
    user: &str,
    candidates: &[RotationCandidate],
    replacements: &[ReplacementObject],
) -> KResult<()> {
    let retirements: Vec<KeyRetirement<'_>> = candidates
        .iter()
        .zip(replacements.iter())
        .map(|(c, r)| KeyRetirement {
            old_owm: &c.owm,
            new_uid: &r.new_uid,
            rewrap_to: r.rewrap_to.as_deref(),
        })
        .collect();

    Box::pin(finalize_rekey(kms, user, &retirements)).await?;

    for (c, r) in candidates.iter().zip(replacements.iter()) {
        info!(
            "Rekey finalized: old={} → new={}, user={user}",
            c.uid, r.new_uid
        );
    }
    Ok(())
}

/// Default implementation for [`RekeyOperation::rewrap_new_objects`].
///
/// For each replacement object:
/// 1. Applies server-wide KEK wrapping via `wrap_and_cache` (no-op if none configured).
/// 2. If the old object was wrapped (spec present) and the new object is still unwrapped,
///    applies the same wrapping specification and caches the unwrapped copy.
async fn default_rewrap_new_objects(
    kms: &KMS,
    user: &str,
    replacements: &mut [ReplacementObject],
    wrap_specs: &[Option<KeyWrappingSpecification>],
) -> KResult<()> {
    for (replacement, spec) in replacements.iter_mut().zip(wrap_specs.iter()) {
        // Step 1: server-wide KEK wrapping (no-op if no KEK configured or already wrapped)
        Box::pin(wrap_and_cache(
            kms,
            user,
            &UniqueIdentifier::TextString(replacement.new_uid.clone()),
            &mut replacement.object,
        ))
        .await?;

        // Step 2: re-wrap with original spec if old key was wrapped and new key is still unwrapped
        let Some(mut rewrap_spec) = spec.clone() else {
            continue;
        };
        if replacement.object.is_wrapped() {
            continue;
        }
        if replacement
            .object
            .key_block()
            .is_ok_and(|kb| kb.key_bytes().is_ok())
        {
            rewrap_spec.encoding_option = Some(EncodingOption::NoEncoding);
        }

        let unwrapped_object = replacement.object.clone();
        Box::pin(wrap_object(
            &mut replacement.object,
            &rewrap_spec,
            kms,
            user,
        ))
        .await?;
        kms.database
            .unwrapped_cache()
            .insert(
                replacement.new_uid.clone(),
                &replacement.object,
                unwrapped_object,
            )
            .await?;
    }
    Ok(())
}

/// Execute the full rotation pipeline using a [`RekeyOperation`] implementor.
///
/// This orchestrator drives the 8-step rotation flow in order:
/// validate → detect wrapping → generate → prepare attributes → rewrap → commit → finalize → respond.
pub(crate) async fn execute_rekey<T: RekeyOperation>(
    op: &T,
    kms: &KMS,
    request: &T::Request,
    user: &str,
) -> KResult<T::Response> {
    let candidates = op.validate(kms, request, user).await?;
    let wrap_specs = op.detect_wrapping(&candidates);
    let mut replacements = op.generate_replacement(kms, &candidates).await?;
    op.prepare_attributes(kms, &candidates, &mut replacements)?;
    op.rewrap_new_objects(kms, user, &mut replacements, &wrap_specs)
        .await?;
    op.persist_new_key(kms, user, &replacements).await?;
    op.finalize_dependants(kms, user, &candidates, &replacements)
        .await?;
    Ok(op.build_response(&replacements))
}

// ─── Shared helpers (used by trait implementors) ─────────────────────────────

/// Dates computed for a replacement key based on the existing key's dates and an optional offset.
///
/// Per KMIP 1.4 §4.4 Table 172 / §4.5 Table 176 / §4.8 Table 186:
/// - `activation = initialization + offset` (if offset provided)
/// - `deactivation = old_deactivation + (new_activation - old_activation)` (if both exist)
#[allow(clippy::struct_field_names)]
pub(crate) struct ReplacementDates {
    pub initialization_date: OffsetDateTime,
    pub activation_date: Option<OffsetDateTime>,
    pub deactivation_date: Option<OffsetDateTime>,
}

/// Compute the replacement key's dates from the existing key's attributes and an optional offset.
///
/// KMIP 1.4 §4.4 Table 172 / §4.5 Table 176 / §4.8 Table 186:
/// - Initialization Date (IT₂) = now (always > IT₁)
/// - Activation Date (AT₂) = IT₂ + Offset (if offset provided), else IT₂ (immediate activation)
/// - Deactivation Date = DT₁ + (AT₂ - AT₁) (if both DT₁ and AT₁ exist)
pub(crate) fn compute_replacement_dates(
    old_attrs: &Attributes,
    offset: Option<i64>,
) -> KResult<ReplacementDates> {
    let now = time_normalize()?;

    let activation_date = Some(offset.map_or(now, |secs| now + time::Duration::seconds(secs)));

    let deactivation_date = match (old_attrs.deactivation_date, old_attrs.activation_date) {
        (Some(old_deactivation), Some(old_activation)) => {
            // DT₂ = DT₁ + (AT₂ - AT₁)
            activation_date.map(|new_activation| {
                let shift = new_activation - old_activation;
                old_deactivation + shift
            })
        }
        _ => None,
    };

    Ok(ReplacementDates {
        initialization_date: now,
        activation_date,
        deactivation_date,
    })
}

/// Prepare attributes for a replacement key, following KMIP 1.4 §4.4 Table 173 / §4.5 Table 177 / §4.8 Table 187.
///
/// This function:
/// - Copies attributes from the existing key
/// - Removes stale unique identifier and links
/// - Sets `ReplacedObjectLink` → old key
/// - Transfers the Name from old key (already in the cloned attributes)
/// - Sets Initial Date, Last Change Date to now
/// - Applies offset-based date computation
/// - Clears fields that must not be carried over (`destroy_date`, compromise dates, revocation)
pub(crate) fn prepare_replacement_attributes(
    old_attrs: &Attributes,
    old_uid: &str,
    offset: Option<i64>,
) -> KResult<Attributes> {
    let dates = compute_replacement_dates(old_attrs, offset)?;

    let mut new_attrs = old_attrs.clone();

    // Clear fields that must not be set on the replacement key
    new_attrs.unique_identifier = None;
    new_attrs.destroy_date = None;
    new_attrs.compromise_date = None;
    new_attrs.compromise_occurrence_date = None;

    // Remove any existing replacement/replaced links (from a previous rekey)
    new_attrs.remove_link(LinkType::ReplacementObjectLink);
    new_attrs.remove_link(LinkType::ReplacedObjectLink);

    // Set the ReplacedObjectLink on the new key pointing to the old key
    new_attrs.set_link(
        LinkType::ReplacedObjectLink,
        LinkedObjectIdentifier::TextString(old_uid.to_owned()),
    );

    // Set dates per spec
    new_attrs.initial_date = Some(dates.initialization_date);
    new_attrs.last_change_date = Some(dates.initialization_date);
    new_attrs.activation_date = dates.activation_date;
    if dates.deactivation_date.is_some() {
        new_attrs.deactivation_date = dates.deactivation_date;
    }

    Ok(new_attrs)
}

/// Clean attributes from an existing key to use as input to `Create` / `CreateKeyPair`.
///
/// Removes identity, lifecycle dates, rotation metadata, and vendor tags that must not
/// leak from the old key into the generation request. The cryptographic parameters
/// (algorithm, length, domain parameters) are preserved so the replacement key has
/// identical cryptographic properties.
///
/// Used by both `symmetric.rs` and `keypair.rs` in their `generate_replacement` step.
pub(crate) fn clean_attributes_for_generation(
    old_attrs: &Attributes,
    vendor_id: &str,
) -> Attributes {
    let mut attrs = old_attrs.clone();
    // Identity — the new key gets its own UID and links
    attrs.unique_identifier = None;
    attrs.link = None;
    attrs.name = None;
    // Lifecycle dates — must not leak from old key
    attrs.initial_date = None;
    attrs.last_change_date = None;
    attrs.activation_date = None;
    attrs.deactivation_date = None;
    attrs.destroy_date = None;
    attrs.compromise_date = None;
    attrs.compromise_occurrence_date = None;
    // Generation format — let Create/CreateKeyPair choose
    attrs.key_format_type = None;
    // Rotation metadata — new key starts fresh (set_rotation_metadata_on_new_key applies later)
    attrs.rotate_interval = None;
    attrs.rotate_name = None;
    attrs.rotate_offset = None;
    // Vendor tags — assigned fresh by Create
    attrs.remove_vendor_attribute(vendor_id, "tag");
    attrs
}

/// Update the old key's attributes after a rekey operation.
///
/// Per KMIP 1.4 §4.4 Table 173 / §4.5 Table 177 / §4.8 Table 187:
/// - Sets `ReplacementObjectLink` → new key
/// - Removes the Name attribute (transferred to the replacement)
/// - Updates Last Change Date to now
pub(crate) fn update_old_key_after_rekey(old_attrs: &mut Attributes, new_uid: &str) -> KResult<()> {
    let now = time_normalize()?;

    old_attrs.set_link(
        LinkType::ReplacementObjectLink,
        LinkedObjectIdentifier::TextString(new_uid.to_owned()),
    );

    // Remove the Name from the old key (it's taken over by the new key)
    old_attrs.name = None;

    // Update Last Change Date
    old_attrs.last_change_date = Some(now);

    Ok(())
}

/// Set rotation metadata on the **new** key after a manual rekey.
///
/// Per the auto-rotation spec (Manual rekey table):
/// - `rotate_generation` = old value + 1
/// - `rotate_date` = now
/// - `rotate_interval` = 0 (manual rekey does not inherit the policy)
/// - `rotate_name` = inherited from old key (required for keyset resolution)
/// - `rotate_offset` = None (cleared for manual rekey)
pub(crate) fn set_rotation_metadata_on_new_key(
    new_attrs: &mut Attributes,
    old_attrs: &Attributes,
) -> KResult<()> {
    new_attrs.rotate_generation = Some(old_attrs.rotate_generation.unwrap_or(0) + 1);
    new_attrs.rotate_date = Some(time_normalize()?);
    // Manual rekey: do not inherit the rotation policy — user must re-arm explicitly
    new_attrs.rotate_interval = Some(0);
    // Inherit rotate_name so keyset resolution (name@latest, bare name) can find the new key
    new_attrs.rotate_name.clone_from(&old_attrs.rotate_name);
    new_attrs.rotate_offset = None;
    // Mark the new key as the latest in the keyset
    new_attrs.rotate_latest = Some(true);
    Ok(())
}

/// Clear rotation flags on the **old** key after a rekey.
///
/// - `rotate_interval` = 0 (prevent the scheduler from picking it up again)
/// - `rotate_latest` = false (the old key is no longer the latest in the keyset)
/// - `rotate_generation` = 0 if unset (ensure gen-0 is queryable via `@first`/`@0`)
pub(crate) const fn clear_rotation_flags_on_old_key(old_attrs: &mut Attributes) {
    old_attrs.rotate_interval = Some(0);
    old_attrs.rotate_latest = Some(false);
    // Ensure the original key has an explicit generation so that keyset
    // addressing with @first / @0 can find it via find_by_rotate_name.
    if old_attrs.rotate_generation.is_none() {
        old_attrs.rotate_generation = Some(0);
    }
}

/// Returns `true` if `attrs` represents the latest generation in its named keyset.
///
/// The latest key is the one with the highest `rotate_generation` value for the
/// given `rotate_name`. If the key has no `rotate_name` it is trivially the latest.
pub(crate) async fn is_keyset_latest(
    kms: &KMS,
    uid: &str,
    attrs: &Attributes,
    user: &str,
) -> KResult<bool> {
    let Some(name) = attrs.rotate_name.as_deref() else {
        return Ok(true);
    };
    let current_gen = attrs.rotate_generation.unwrap_or(0);
    let all = kms.database.find_by_rotate_name(name, None, user).await?;
    Ok(!all.iter().any(|(other_uid, other_attrs)| {
        other_uid != uid && other_attrs.rotate_generation.unwrap_or(0) > current_gen
    }))
}

/// Enforce privileged-user restriction for rekey operations that create new keys.
///
/// Both `ReKey` and `ReKeyKeyPair` create replacement keys, so the caller
/// must either have `Create` permission or be in the privileged users list
/// (configured in `kms.params.privileged_users`).
pub(crate) async fn enforce_privileged_user(kms: &KMS, user: &str) -> KResult<()> {
    kms.enforce_create_permission(user).await
}

/// Validate that request attributes do not attempt to change cryptographic parameters.
///
/// Per KMIP §4.4 / §4.5, a rekey operation must preserve the algorithm, curve,
/// and key length of the original key. Changing these requires a new `Create` or
/// `CreateKeyPair` operation instead.
///
/// The `attrs_iter` yields each `Option<&Attributes>` from the request (one for
/// symmetric `ReKey`, up to three for `ReKeyKeyPair`).
pub(crate) fn validate_no_crypto_param_change<'a>(
    existing_attrs: &Attributes,
    attrs_iter: impl IntoIterator<Item = Option<&'a Attributes>>,
    operation_name: &str,
) -> KResult<()> {
    for req_attrs in attrs_iter.into_iter().flatten() {
        if let Some(algo) = req_attrs.cryptographic_algorithm {
            if existing_attrs.cryptographic_algorithm != Some(algo) {
                kms_bail!(KmsError::InvalidRequest(format!(
                    "{operation_name}: changing the cryptographic algorithm is not allowed. \
                     Use Create/CreateKeyPair for a different algorithm."
                )))
            }
        }
        if let Some(ref cdp) = req_attrs.cryptographic_domain_parameters {
            if let Some(ref existing_cdp) = existing_attrs.cryptographic_domain_parameters {
                if cdp.recommended_curve.is_some()
                    && cdp.recommended_curve != existing_cdp.recommended_curve
                {
                    kms_bail!(KmsError::InvalidRequest(format!(
                        "{operation_name}: changing the recommended curve is not allowed. \
                         Use Create/CreateKeyPair for a different curve."
                    )))
                }
            }
        }
        if let Some(len) = req_attrs.cryptographic_length {
            if existing_attrs.cryptographic_length.is_some()
                && existing_attrs.cryptographic_length != Some(len)
            {
                kms_bail!(KmsError::InvalidRequest(format!(
                    "{operation_name}: changing the cryptographic length is not allowed. \
                     Use Create/CreateKeyPair for a different key size."
                )))
            }
        }
    }
    Ok(())
}

// ─── Phase 2: Finalize rekey (retire old keys + rewrap dependants) ───────────

/// Describes one old key being retired as part of a rekey operation.
///
/// Used by [`finalize_rekey`] to batch-retire multiple keys (e.g., both the
/// private key and public key in a key pair rekey) in a single atomic commit.
pub(crate) struct KeyRetirement<'a> {
    /// The old key's metadata (object + attributes).
    pub old_owm: &'a ObjectWithMetadata,
    /// The UID of the new replacement key.
    pub new_uid: &'a str,
    /// If `Some`, all keys that were wrapped by this old key will be re-wrapped
    /// using the key at this UID. Typically this is the same as `new_uid` for
    /// symmetric keys and the new public key UID for key pairs.
    /// `None` means no dependant re-wrapping for this slot (e.g., private keys
    /// are never used as wrapping keys).
    pub rewrap_to: Option<&'a str>,
}

/// Phase 2 of a rekey operation: retire old keys, re-wrap dependants, and commit atomically.
///
/// This function:
/// 1. For each [`KeyRetirement`] slot, retires the old key (sets `ReplacementObjectLink`,
///    clears rotation flags, updates the embedded attributes).
/// 2. For each slot with `rewrap_to = Some(new_wrapping_uid)`, finds all keys wrapped
///    by the old key and re-wraps them with the new wrapping key.
/// 3. Commits all resulting updates in a single atomic database transaction.
///
/// # Known concurrency limitation
///
/// This function reads dependant objects (via `find_wrapped_by`) and then writes them back
/// in the same `atomic()` call, but there is **no optimistic lock** guarding those reads.
/// If two rotation requests for the same key execute concurrently — whether two manual
/// `Re-Key` requests or one manual and one auto-rotation tick — the following race is
/// possible:
///
/// 1. Both callers read the old key and its dependants at the same snapshot.
/// 2. Both callers generate a new key (different UIDs, no collision on `Create`).
/// 3. Both callers commit Phase 2: the second writer silently overwrites the first writer's
///    `ReplacementObjectLink` on the old key, and re-wraps dependants a second time.
///    The first new key becomes a dangling orphan.
///
/// The auto-rotation background task (`run_auto_rotation`) is currently a no-op stub
/// (TODO comment in `auto_rotate.rs`), so this race cannot be triggered in production
/// today. Before the scheduler is wired up, `ObjectsStore` must gain a conditional-update
/// primitive (optimistic locking via a `version` column / Lua CAS in Redis) so that Phase 2
/// can abort with a `Conflict` error if the old key was modified between the read and the
/// commit.
///
/// Tracking issue: <https://github.com/Cosmian/kms/issues/1006>
// TODO(concurrency): replace the unconditional `UpdateObject` for the old key with a
// `compare_and_swap` / `update_object_if_version` that aborts if the key was concurrently
// modified. See issue above for the full design.
pub(crate) async fn finalize_rekey(
    kms: &KMS,
    owner: &str,
    retirements: &[KeyRetirement<'_>],
) -> KResult<()> {
    let mut operations: Vec<AtomicOperation> = Vec::new();

    for retirement in retirements {
        let (old_object, old_attributes) = retire_old_key(retirement.old_owm, retirement.new_uid)?;

        operations.push(AtomicOperation::UpdateObject((
            retirement.old_owm.id().to_owned(),
            old_object,
            old_attributes,
            None,
        )));

        if let Some(new_wrapping_uid) = retirement.rewrap_to {
            Box::pin(rewrap_dependants(
                kms,
                owner,
                retirement.old_owm.id(),
                new_wrapping_uid,
                &mut operations,
            ))
            .await?;
        }
    }

    kms.database.atomic(owner, &operations).await?;
    Ok(())
}

/// Set up a newly generated key with replacement attributes and links.
///
/// Applies the `ReplacedObjectLink` pointing to the old UID, an optional
/// paired-key cross-link, and the Name from the replacement attributes.
/// Then runs [`setup_object_lifecycle`] to set state / dates / digest.
pub(crate) fn setup_new_key(
    key_object: &mut Object,
    replacement_attrs: &Attributes,
    object_type: ObjectType,
    old_uid: &str,
    paired_key: Option<(&str, LinkType)>,
) -> KResult<Attributes> {
    if let Ok(key_attrs) = key_object.attributes_mut() {
        key_attrs.name.clone_from(&replacement_attrs.name);
        key_attrs.set_link(
            LinkType::ReplacedObjectLink,
            LinkedObjectIdentifier::TextString(old_uid.to_owned()),
        );
        if let Some((paired_uid, link_type)) = paired_key {
            key_attrs.set_link(
                link_type,
                LinkedObjectIdentifier::TextString(paired_uid.to_owned()),
            );
        }
    }

    // Pass the activation_date directly to setup_object_lifecycle:
    // - Past/present date → Active (replacement inherits active state)
    // - Future date → PreActive (scheduled activation)
    // - None → PreActive (requires explicit Activate)
    setup_object_lifecycle(key_object, object_type, replacement_attrs.activation_date)
}

/// Apply replacement attributes, lifecycle setup, and tag extraction to one key slot.
///
/// Combines [`setup_new_key`] + attribute/tag extraction into a single call to
/// avoid repetition when processing both the SK and PK in `prepare_attributes`.
pub(crate) fn finalize_replacement_key(
    replacement: &mut ReplacementObject,
    new_attrs: &Attributes,
    object_type: ObjectType,
    old_uid: &str,
    paired_key: Option<(&str, LinkType)>,
    vendor_id: &str,
) -> KResult<()> {
    setup_new_key(
        &mut replacement.object,
        new_attrs,
        object_type,
        old_uid,
        paired_key,
    )?;
    let attrs = replacement.object.attributes().cloned().unwrap_or_default();
    replacement.tags = attrs.get_tags(vendor_id);
    replacement.attributes = attrs;
    Ok(())
}

/// Compute a fresh UID for a rotation replacement key.
///
/// - Pure UUID → fresh UUID (e.g. `"abc-…"` → `"def-…"`)
/// - User name → `"<name>_<new-uuid>"` (e.g. `"toto"` → `"toto_def-…"`)
/// - Already-prefixed → strip old UUID suffix, re-use prefix
///   (e.g. `"toto_abc-…"` → `"toto_def-…"`)
pub(crate) fn compute_rotation_uid(old_uid: &str) -> String {
    if Uuid::parse_str(old_uid).is_ok() {
        Uuid::new_v4().to_string()
    } else {
        let prefix = old_uid
            .rsplit_once('_')
            .filter(|(_, suffix)| Uuid::parse_str(suffix).is_ok())
            .map_or(old_uid, |(prefix, _)| prefix);
        format!("{prefix}_{}", Uuid::new_v4())
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

/// Prepare an old key (private, public, or symmetric) for replacement.
///
/// Clones the object and attributes from the OWM, sets `ReplacementObjectLink`
/// pointing to the new key, and clears rotation flags so the scheduler won't
/// pick it up again.
fn retire_old_key(
    owm: &ObjectWithMetadata,
    new_uid: &str,
) -> KResult<(
    cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object,
    Attributes,
)> {
    let mut old_object = owm.object().clone();
    let mut old_attributes = owm.attributes().clone();
    update_old_key_after_rekey(&mut old_attributes, new_uid)?;
    clear_rotation_flags_on_old_key(&mut old_attributes);
    if let Ok(obj_attrs) = old_object.attributes_mut() {
        update_old_key_after_rekey(obj_attrs, new_uid)?;
    }
    Ok((old_object, old_attributes))
}

/// Re-wrap all keys that were wrapped by the old wrapping key, pointing them
/// to the new wrapping key UID.
async fn rewrap_dependants(
    kms: &KMS,
    owner: &str,
    old_uid: &str,
    new_uid: &str,
    operations: &mut Vec<AtomicOperation>,
) -> KResult<()> {
    let wrapped_dependants = kms
        .database
        .find_wrapped_by(old_uid, owner)
        .await
        .unwrap_or_default();

    for (dep_uid, _dep_state, _dep_attrs) in wrapped_dependants {
        let Some(dep_owm) = kms.database.retrieve_object(&dep_uid).await? else {
            warn!("wrapped dependant {dep_uid} not found, skipping");
            continue;
        };
        // Security: only re-wrap dependants owned by the caller
        if dep_owm.owner() != owner {
            warn!(
                "skipping re-wrap of dependant {dep_uid}: owned by '{}', not by '{owner}'",
                dep_owm.owner()
            );
            continue;
        }
        let mut dep_object = dep_owm.object().clone();
        // Use the full metadata attributes from retrieve_object (not from find_wrapped_by)
        // because find_wrapped_by may return incomplete attributes for wrapped objects
        // (Object::attributes() fails on wrapped keys, losing activation_date etc.)
        let dep_attrs = dep_owm.attributes().clone();

        if let Some(op) =
            rewrap_single_dependant(kms, owner, &dep_uid, &mut dep_object, dep_attrs, new_uid)
                .await?
        {
            operations.push(op);
        }
    }
    Ok(())
}

/// Unwrap and re-wrap a single dependant object with the new wrapping key.
///
/// Returns `Some(AtomicOperation)` if the re-wrap succeeded, `None` if skipped.
async fn rewrap_single_dependant(
    kms: &KMS,
    owner: &str,
    dep_uid: &str,
    dep_object: &mut Object,
    mut dep_attrs: Attributes,
    new_uid: &str,
) -> KResult<Option<AtomicOperation>> {
    let dep_wrap_spec = dep_object
        .key_block()
        .ok()
        .and_then(|kb| kb.key_wrapping_data.as_ref())
        .map(|kwd| KeyWrappingSpecification {
            wrapping_method: kwd.wrapping_method,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(new_uid.to_owned()),
                cryptographic_parameters: kwd
                    .encryption_key_information
                    .as_ref()
                    .and_then(|e| e.cryptographic_parameters.clone()),
            }),
            mac_or_signature_key_information: kwd.mac_signature_key_information.clone().map(|m| {
                cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::MacSignatureKeyInformation {
                    unique_identifier: UniqueIdentifier::TextString(new_uid.to_owned()),
                    cryptographic_parameters: m.cryptographic_parameters,
                }
            }),
            attribute_name: None,
            encoding_option: kwd.encoding_option,
        });

    let Some(spec) = dep_wrap_spec else {
        return Ok(None);
    };

    if let Err(e) = unwrap_object(dep_object, kms, owner).await {
        warn!("failed to unwrap dependant {dep_uid}: {e}, skipping");
        return Ok(None);
    }
    if let Err(e) = crate::core::wrapping::wrap_object(dep_object, &spec, kms, owner).await {
        warn!("failed to re-wrap dependant {dep_uid} with new key: {e}, skipping");
        return Ok(None);
    }

    dep_attrs.set_link(
        LinkType::WrappingKeyLink,
        LinkedObjectIdentifier::TextString(new_uid.to_owned()),
    );
    dep_attrs.set_wrapping_key_id(kms.vendor_id(), new_uid);

    Ok(Some(AtomicOperation::UpdateObject((
        dep_uid.to_owned(),
        dep_object.clone(),
        dep_attrs,
        None,
    ))))
}
