//! KMIP `ReCertify` — certificate rotation with new UID and replacement links.
//!
//! This implements the [`RekeyOperation`] trait for certificate renewal/rotation.
//! Unlike the standard `Certify` operation (which replaces in-place via Upsert),
//! `ReCertify` creates a **new certificate with a fresh UID** and links it to the
//! old certificate via `ReplacedObject` / `ReplacementObject` links.
//!
//! The old certificate remains Active but is marked with a `ReplacementObjectLink`
//! pointing to the new certificate. Keys linked to the old certificate are updated
//! to point to the new certificate via their `CertificateLink`.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_data_structures::KeyWrappingSpecification,
            kmip_objects::ObjectType,
            kmip_operations::{Certify, ReCertify, ReCertifyResponse},
            kmip_types::{LinkType, LinkedObjectIdentifier, UniqueIdentifier},
        },
        time_normalize,
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::trace;

use super::rekey::{RekeyOperation, ReplacementObject, RotationCandidate, execute_rekey};
use crate::{
    core::{
        KMS,
        operations::certify::{build_and_sign_certificate, get_issuer, get_subject},
        retrieve_object_utils::retrieve_object_for_operation,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Implementor of [`RekeyOperation`] for certificate rotation (`ReCertify`).
pub(crate) struct CertificateRekey {
    /// The `offset` from the `ReCertify` request (date computation per KMIP §6.1.45).
    offset: Option<i64>,
}

/// KMIP `ReCertify` operation — certificate rotation with new UID.
///
/// Creates a new certificate for the same subject/issuer, assigns a fresh UID,
/// and links old → new via `ReplacementObjectLink`. Keys referencing the old
/// certificate are updated to point to the new one.
pub(crate) async fn recertify(
    kms: &KMS,
    request: ReCertify,
    owner: &str,
) -> KResult<ReCertifyResponse> {
    trace!("ReCertify: {}", serde_json::to_string(&request)?);
    Box::pin(execute_rekey(
        &CertificateRekey {
            offset: request.offset,
        },
        kms,
        &request,
        owner,
    ))
    .await
}

impl RekeyOperation for CertificateRekey {
    type Candidates = [RotationCandidate; 1];
    type Replacements = [ReplacementObject; 1];
    type Request = ReCertify;
    type Response = ReCertifyResponse;

    async fn validate(
        &self,
        kms: &KMS,
        request: &ReCertify,
        user: &str,
    ) -> KResult<[RotationCandidate; 1]> {
        KMS::reject_protection_storage_masks(request.protection_storage_masks.is_some())?;

        kms.enforce_create_permission(user).await?;

        let uid = request
            .unique_identifier
            .as_ref()
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "ReCertify: unique_identifier of the certificate to rotate is required"
                        .to_owned(),
                )
            })?
            .as_str()
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "ReCertify: unique_identifier must be a text string".to_owned(),
                )
            })?;

        let owm = Box::pin(retrieve_object_for_operation(
            uid,
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await?;

        if owm.object().object_type() != ObjectType::Certificate {
            kms_bail!(KmsError::InvalidRequest(format!(
                "ReCertify: object {uid} is not a Certificate"
            )));
        }

        if owm.state() != State::Active && owm.state() != State::Deactivated {
            kms_bail!(KmsError::InvalidRequest(format!(
                "ReCertify: certificate '{uid}' is in state '{}' — only Active or Deactivated \
                 certificates can be renewed",
                owm.state()
            )));
        }

        Ok([RotationCandidate {
            owm,
            uid: uid.to_owned(),
        }])
    }

    async fn generate_replacement(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate; 1],
    ) -> KResult<[ReplacementObject; 1]> {
        let [candidate] = candidates;
        // Certificates are never members of a named keyset — always use a fresh UUID.
        let new_uid = UniqueIdentifier::rotation_successor(None, None);

        // Build a Certify request that references the existing certificate for renewal.
        // We pass the old certificate's UID so `get_subject` produces a `Subject::Certificate`.
        let certify_request = Certify {
            unique_identifier: Some(UniqueIdentifier::TextString(candidate.uid.clone())),
            certificate_request_type: None,
            certificate_request_value: None,
            attributes: Some(Attributes {
                // The new certificate UID is set in the attributes so `get_subject` uses it.
                unique_identifier: Some(UniqueIdentifier::TextString(new_uid.clone())),
                // Preserve issuer links from the old certificate's attributes
                ..candidate.owm.attributes().clone()
            }),
            protection_storage_masks: None,
        };

        // Resolve subject (will produce Subject::Certificate from existing cert)
        let owner = candidate.owm.owner();
        let subject = Box::pin(get_subject(kms, &certify_request, owner)).await?;
        // Resolve issuer from the old certificate's attributes
        let issuer = Box::pin(get_issuer(&subject, kms, &certify_request, owner)).await?;
        // Build and sign the new certificate
        let (certificate_object, tags, attributes) =
            build_and_sign_certificate(kms.vendor_id(), &issuer, &subject, certify_request)?;

        Ok([ReplacementObject {
            new_uid,
            old_uid: candidate.uid.clone(),
            object: certificate_object,
            attributes,
            tags,
            // Certificates don't wrap anything, no dependant re-wrapping needed.
            rewrap_to: None,
        }])
    }

    fn prepare_attributes(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate; 1],
        replacements: &mut [ReplacementObject; 1],
    ) -> KResult<()> {
        let [candidate] = candidates;
        let old_attrs = candidate.owm.attributes();
        let [replacement] = replacements;

        // Use shared date computation for offset-based activation/deactivation
        let base_attrs = old_attrs.for_replacement(&replacement.old_uid, self.offset)?;
        replacement.attributes.activation_date = base_attrs.activation_date;
        replacement.attributes.deactivation_date = base_attrs.deactivation_date;
        replacement.attributes.initial_date = base_attrs.initial_date;
        replacement.attributes.last_change_date = base_attrs.last_change_date;

        // Compute state based on activation_date (certificates bypass setup_object_lifecycle)
        let now = time_normalize()?;
        let state = if replacement
            .attributes
            .activation_date
            .is_some_and(|d| d <= now)
        {
            State::Active
        } else {
            State::PreActive
        };
        replacement.attributes.state = Some(state);

        // Set ReplacedObjectLink on the new certificate pointing to the old one
        replacement.attributes.set_link(
            LinkType::ReplacedObjectLink,
            LinkedObjectIdentifier::TextString(replacement.old_uid.clone()),
        );

        // Preserve links to associated keys from the old certificate
        for link_type in [LinkType::PublicKeyLink, LinkType::PrivateKeyLink] {
            if let Some(link) = old_attrs.get_link(link_type) {
                replacement.attributes.set_link(link_type, link);
            }
        }

        // Set rotation metadata + vendor tags
        replacement
            .attributes
            .set_rotation_metadata_from(old_attrs)?;
        replacement.tags.extend(old_attrs.get_tags(kms.vendor_id()));

        Ok(())
    }

    async fn rewrap_new_objects(
        &self,
        _kms: &KMS,
        _user: &str,
        _replacements: &mut [ReplacementObject; 1],
        _wrap_specs: &[Option<KeyWrappingSpecification>],
    ) -> KResult<()> {
        // Certificates are never wrapped — no-op.
        Ok(())
    }

    async fn finalize_dependants(
        &self,
        kms: &KMS,
        user: &str,
        candidates: &[RotationCandidate; 1],
        replacements: &[ReplacementObject; 1],
    ) -> KResult<()> {
        let [candidate] = candidates;
        let [replacement] = replacements;

        // Phase 2: Update the old certificate with ReplacementObjectLink
        let mut old_object = candidate.owm.object().clone();
        let mut old_attributes = candidate.owm.attributes().clone();
        old_attributes.retire_for_replacement(&replacement.new_uid)?;
        if let Ok(obj_attrs) = old_object.attributes_mut() {
            obj_attrs.retire_for_replacement(&replacement.new_uid)?;
        }

        let mut operations = vec![AtomicOperation::UpdateObject((
            candidate.uid.clone(),
            old_object,
            old_attributes,
            None,
        ))];

        // Relink keys: update CertificateLink on linked PK/SK to point to new cert UID
        relink_keys_to_new_certificate(
            kms,
            user,
            &candidate.uid,
            candidate.owm.attributes(),
            &replacement.new_uid,
            &mut operations,
        )
        .await?;

        kms.database.atomic(user, &operations).await?;
        Ok(())
    }

    fn build_response(&self, replacements: &[ReplacementObject; 1]) -> ReCertifyResponse {
        let [replacement] = replacements;
        ReCertifyResponse {
            unique_identifier: UniqueIdentifier::TextString(replacement.new_uid.clone()),
        }
    }
}

/// Update `CertificateLink` on any keys that reference the old certificate
/// to point to the new certificate UID.
async fn relink_keys_to_new_certificate(
    kms: &KMS,
    _user: &str,
    old_cert_uid: &str,
    old_cert_attrs: &Attributes,
    new_cert_uid: &str,
    operations: &mut Vec<AtomicOperation>,
) -> KResult<()> {
    // Collect key UIDs linked from the old certificate
    let key_uids: Vec<String> = [LinkType::PublicKeyLink, LinkType::PrivateKeyLink]
        .iter()
        .filter_map(|lt| old_cert_attrs.get_link(*lt).map(|l| l.to_string()))
        .collect();

    for key_uid in key_uids {
        if let Some(op) = relink_single_key(kms, &key_uid, old_cert_uid, new_cert_uid).await? {
            operations.push(op);
        }
    }
    Ok(())
}

/// Update a single key's `CertificateLink` if it points to the old certificate.
async fn relink_single_key(
    kms: &KMS,
    key_uid: &str,
    old_cert_uid: &str,
    new_cert_uid: &str,
) -> KResult<Option<AtomicOperation>> {
    let Some(key_owm) = kms.database.retrieve_object(key_uid).await? else {
        return Ok(None);
    };
    let Some(cert_link) = key_owm.attributes().get_link(LinkType::CertificateLink) else {
        return Ok(None);
    };
    if cert_link.to_string() != old_cert_uid {
        return Ok(None);
    }

    let mut key_object = key_owm.object().clone();
    let mut key_attrs = key_owm.attributes().clone();
    let new_link = LinkedObjectIdentifier::TextString(new_cert_uid.to_owned());
    key_attrs.set_link(LinkType::CertificateLink, new_link.clone());
    if let Ok(obj_attrs) = key_object.attributes_mut() {
        obj_attrs.set_link(LinkType::CertificateLink, new_link);
    }
    Ok(Some(AtomicOperation::UpdateObject((
        key_uid.to_owned(),
        key_object,
        key_attrs,
        None,
    ))))
}
