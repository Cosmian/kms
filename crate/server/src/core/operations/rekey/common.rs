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
    },
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use cosmian_logger::{info, warn};

use crate::{
    core::{
        KMS,
        operations::key_ops::ObjectLifecycleExt,
        wrapping::{unwrap_object, wrap_and_cache, wrap_object},
    },
    error::KmsError,
    result::KResult,
};

impl KMS {
    /// Retrieve all eligible objects matching the given identifier, filtered by state and type.
    ///
    /// Filters by:
    /// - State: `Active`, `Deactivated`, or `Compromised`.
    /// - Object type: the specified `object_type`
    ///
    /// When a specific UID resolves to a key of the correct type but in an
    /// ineligible state, an explicit error is returned rather than silently
    /// skipping. For tag-based queries, ineligible keys are filtered out.
    pub(crate) async fn retrieve_eligible_keys(
        &self,
        uid_or_tags: &str,
        object_type: ObjectType,
    ) -> KResult<Vec<ObjectWithMetadata>> {
        let is_tag_query = uid_or_tags.starts_with('[');
        let objects = self.database.retrieve_objects(uid_or_tags).await?;
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
                if !is_tag_query {
                    return Err(KmsError::InvalidRequest(format!(
                        "key '{}' is in state '{}' — only Active, Deactivated, or Compromised \
                         keys can be rotated",
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

    /// Returns `true` if `attrs` represents the latest generation in its named keyset.
    pub(crate) async fn is_keyset_latest(
        &self,
        uid: &str,
        attrs: &Attributes,
        user: &str,
    ) -> KResult<bool> {
        let Some(name) = attrs.rotate_name.as_deref() else {
            return Ok(true);
        };
        let current_gen = attrs.rotate_generation.unwrap_or(0);
        let all = self.database.find_by_rotate_name(name, None, user).await?;
        Ok(!all.iter().any(|(other_uid, other_attrs)| {
            other_uid != uid && other_attrs.rotate_generation.unwrap_or(0) > current_gen
        }))
    }

    /// Reject a Re-Key / Re-KeyKeyPair request when the selected key is not the latest
    /// generation in its named keyset.
    ///
    /// No-ops for keys that are not part of a named keyset (no `rotate_name`).
    pub(crate) async fn enforce_keyset_latest(
        &self,
        uid: &str,
        attrs: &Attributes,
        user: &str,
        op_name: &str,
    ) -> KResult<()> {
        if !self.is_keyset_latest(uid, attrs, user).await? {
            return Err(KmsError::InvalidRequest(format!(
                "{op_name}: key '{uid}' is not the latest in its keyset — only the latest \
                 generation can be rotated"
            )));
        }
        Ok(())
    }

    /// Phase 2 of a rekey operation: retire old keys, re-wrap dependants, and commit atomically.
    pub(crate) async fn finalize_rekey(
        &self,
        owner: &str,
        retirements: &[KeyRetirement<'_>],
    ) -> KResult<()> {
        let mut operations: Vec<AtomicOperation> = Vec::new();

        for retirement in retirements {
            let (old_object, old_attributes) =
                retire_old_key(retirement.old_owm, retirement.new_uid)?;

            operations.push(AtomicOperation::UpdateObject((
                retirement.old_owm.id().to_owned(),
                old_object,
                old_attributes,
                None,
            )));

            // KMIP §4.57 transition 6: old key becomes Deactivated after Re-Key
            operations.push(AtomicOperation::UpdateState((
                retirement.old_owm.id().to_owned(),
                State::Deactivated,
            )));

            if let Some(new_wrapping_uid) = retirement.rewrap_to {
                Box::pin(self.rewrap_dependants(
                    owner,
                    retirement.old_owm.id(),
                    new_wrapping_uid,
                    &mut operations,
                ))
                .await?;
            }
        }

        self.database.atomic(owner, &operations).await?;
        Ok(())
    }

    /// Default implementation for [`RekeyOperation::finalize_dependants`].
    pub(crate) async fn default_finalize_dependants(
        &self,
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

        Box::pin(self.finalize_rekey(user, &retirements)).await?;

        for (c, r) in candidates.iter().zip(replacements.iter()) {
            info!(
                "Rekey finalized: old={} → new={}, user={user}",
                c.uid, r.new_uid
            );
        }
        Ok(())
    }

    /// Default implementation for [`RekeyOperation::rewrap_new_objects`].
    pub(crate) async fn default_rewrap_new_objects(
        &self,
        user: &str,
        replacements: &mut [ReplacementObject],
        wrap_specs: &[Option<KeyWrappingSpecification>],
    ) -> KResult<()> {
        for (replacement, spec) in replacements.iter_mut().zip(wrap_specs.iter()) {
            Box::pin(wrap_and_cache(
                self,
                user,
                &UniqueIdentifier::TextString(replacement.new_uid.clone()),
                &mut replacement.object,
            ))
            .await?;

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
                self,
                user,
            ))
            .await?;
            self.database
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

    /// Re-wrap all keys that were wrapped by the old wrapping key.
    pub(crate) async fn rewrap_dependants(
        &self,
        owner: &str,
        old_uid: &str,
        new_uid: &str,
        operations: &mut Vec<AtomicOperation>,
    ) -> KResult<()> {
        let wrapped_dependants = self
            .database
            .find_wrapped_by(old_uid, owner)
            .await
            .unwrap_or_default();

        for (dep_uid, _dep_state, _dep_attrs) in wrapped_dependants {
            let Some(dep_owm) = self.database.retrieve_object(&dep_uid).await? else {
                warn!("wrapped dependant {dep_uid} not found, skipping");
                continue;
            };
            if dep_owm.owner() != owner {
                warn!(
                    "skipping re-wrap of dependant {dep_uid}: owned by '{}', not by '{owner}'",
                    dep_owm.owner()
                );
                continue;
            }
            let mut dep_object = dep_owm.object().clone();
            let dep_attrs = dep_owm.attributes().clone();

            if let Some(op) = self
                .rewrap_single_dependant(owner, &dep_uid, &mut dep_object, dep_attrs, new_uid)
                .await?
            {
                operations.push(op);
            }
        }
        Ok(())
    }

    /// Unwrap and re-wrap a single dependant object with the new wrapping key.
    async fn rewrap_single_dependant(
        &self,
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
                mac_or_signature_key_information: kwd.mac_signature_key_information.clone().map(
                    |m| {
                        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::MacSignatureKeyInformation {
                            unique_identifier: UniqueIdentifier::TextString(new_uid.to_owned()),
                            cryptographic_parameters: m.cryptographic_parameters,
                        }
                    },
                ),
                attribute_name: None,
                encoding_option: kwd.encoding_option,
            });

        let Some(spec) = dep_wrap_spec else {
            return Ok(None);
        };

        if let Err(e) = unwrap_object(dep_object, self, owner).await {
            warn!("failed to unwrap dependant {dep_uid}: {e}, skipping");
            return Ok(None);
        }
        if let Err(e) = crate::core::wrapping::wrap_object(dep_object, &spec, self, owner).await {
            warn!("failed to re-wrap dependant {dep_uid} with new key: {e}, skipping");
            return Ok(None);
        }

        dep_attrs.set_link(
            LinkType::WrappingKeyLink,
            LinkedObjectIdentifier::TextString(new_uid.to_owned()),
        );
        dep_attrs.set_wrapping_key_id(self.vendor_id(), new_uid);

        Ok(Some(AtomicOperation::UpdateObject((
            dep_uid.to_owned(),
            dep_object.clone(),
            dep_attrs,
            None,
        ))))
    }
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

impl RotationCandidate {
    /// Follow `PublicKeyLink` on this candidate's private key to resolve the paired public key UID.
    pub(crate) fn public_key_uid(&self) -> KResult<String> {
        self.owm
            .attributes()
            .get_link(LinkType::PublicKeyLink)
            .map(|l| l.to_string())
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "ReKeyKeyPair: the private key has no PublicKeyLink. Cannot determine the \
                     paired public key."
                        .to_owned(),
                )
            })
    }
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

impl ReplacementObject {
    /// Apply replacement attributes, lifecycle setup, and tag extraction to this key slot.
    ///
    /// Combines [`setup_new_key`] + attribute/tag extraction into a single call to
    /// avoid repetition when processing both the SK and PK in `prepare_attributes`.
    pub(crate) fn finalize(
        &mut self,
        new_attrs: &Attributes,
        object_type: ObjectType,
        old_uid: &str,
        paired_key: Option<(&str, LinkType)>,
        vendor_id: &str,
    ) -> KResult<()> {
        setup_new_key(
            &mut self.object,
            new_attrs,
            object_type,
            old_uid,
            paired_key,
        )?;
        // Stamp the embedded attributes with the correct UID.
        // `create_symmetric_key_kmip_object` always assigns a random UUID to
        // `attributes.unique_identifier`; replace it with `new_uid` so that
        // GetAttributes always returns a `unique_identifier` that matches the
        // object's actual stored UID.
        if let Ok(embedded_attrs) = self.object.attributes_mut() {
            embedded_attrs.unique_identifier =
                Some(UniqueIdentifier::TextString(self.new_uid.clone()));
        }
        let attrs = self.object.attributes().cloned().unwrap_or_default();
        self.tags = attrs.get_tags(vendor_id);
        self.attributes = attrs;
        Ok(())
    }

    /// Finalize this replacement for a keypair rotation step.
    ///
    /// Applies lifecycle setup, cross-link, wrapping key preservation,
    /// and optionally marks this key as the rewrap target for dependants.
    #[allow(clippy::too_many_arguments)] // Builder-style method grouping related keypair params
    pub(crate) fn prepare_for_keypair(
        &mut self,
        new_attrs: &Attributes,
        candidate: &RotationCandidate,
        cross_link_uid: &str,
        link_type: LinkType,
        object_type: ObjectType,
        is_rewrap_target: bool,
        vendor_id: &str,
    ) -> KResult<()> {
        self.finalize(
            new_attrs,
            object_type,
            &candidate.uid,
            Some((cross_link_uid, link_type)),
            vendor_id,
        )?;
        candidate
            .owm
            .object()
            .copy_wrapping_key_link_to(&mut self.attributes);
        if is_rewrap_target {
            self.rewrap_to = Some(self.new_uid.clone());
        }
        Ok(())
    }
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
        kms.default_rewrap_new_objects(user, replacements.as_mut(), wrap_specs)
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
        kms.default_finalize_dependants(user, candidates.as_ref(), replacements.as_ref())
    }

    /// Step 8: Build the KMIP response from the completed replacements.
    fn build_response(&self, replacements: &Self::Replacements) -> Self::Response;
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

// ─── Phase 2: Finalize rekey (retire old keys + rewrap dependants) ───────────

/// Describes one old key being retired as part of a rekey operation.
///
/// Used by [`KMS::finalize_rekey`] to batch-retire multiple keys (e.g., both the
/// private key and public key in a key pair rekey) in a single atomic commit.
pub(crate) struct KeyRetirement<'a> {
    /// The old key's metadata (object + attributes).
    pub old_owm: &'a ObjectWithMetadata,
    /// The UID of the new replacement key.
    pub new_uid: &'a str,
    /// If `Some`, all keys that were wrapped by this old key will be re-wrapped
    /// using the key at this UID.
    pub rewrap_to: Option<&'a str>,
}

/// Set up a newly generated key with replacement attributes and links.
///
/// Applies the `ReplacedObjectLink` pointing to the old UID, an optional
/// paired-key cross-link, and the Name from the replacement attributes.
/// Then calls [`ObjectLifecycleExt::setup_with_lifecycle`] to set state / dates / digest.
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

    key_object.setup_with_lifecycle(object_type, replacement_attrs.activation_date)
}

// ─── Private helpers ─────────────────────────────────────────────────────────

fn retire_old_key(owm: &ObjectWithMetadata, new_uid: &str) -> KResult<(Object, Attributes)> {
    let mut old_object = owm.object().clone();
    let mut old_attributes = owm.attributes().clone();
    old_attributes.retire_for_replacement(new_uid)?;
    old_attributes.clear_rotation_flags();
    // KMIP §4.57 transition 6: persist Deactivated in all attribute layers so that
    // destroy.rs effective-state logic reads Deactivated (not the stale Active value).
    old_attributes.state = Some(State::Deactivated);
    if let Ok(obj_attrs) = old_object.attributes_mut() {
        obj_attrs.retire_for_replacement(new_uid)?;
        obj_attrs.state = Some(State::Deactivated);
    }
    Ok((old_object, old_attributes))
}
