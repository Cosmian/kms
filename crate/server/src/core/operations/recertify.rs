//! KMIP `ReCertify` — certificate rotation with new UID and replacement links.
//!
//! This implements the [`RekeyOperation`] trait for certificate renewal/rotation.
//! Unlike the standard `Certify` operation (which replaces in-place via Upsert),
//! `ReCertify` creates a **new certificate with a fresh UID** and links it to the
//! old certificate via `ReplacedObject` / `ReplacementObject` links.
//!
//! The old certificate receives a `ReplacementObjectLink` pointing to the new
//! certificate; an Active old certificate is retired by setting its Deactivation Date
//! to now (KMIP 2.1 §4.18, §4.57 transition 6). Keys linked to the old certificate are
//! updated to point to the new certificate via their `CertificateLink`.

use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_data_structures::KeyWrappingSpecification,
            kmip_objects::ObjectType,
            kmip_operations::{Certify, ReCertify, ReCertifyResponse},
            kmip_types::{
                CertificateRequestType, LinkType, LinkedObjectIdentifier, UniqueIdentifier,
            },
        },
        time_normalize,
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::{trace, warn};

use super::rekey::{RekeyOperation, ReplacementObject, RotationCandidate, execute_rekey};
use crate::{
    core::{
        KMS,
        certificate::linked_id_str,
        operations::certify::{build_and_sign_certificate, get_issuer, get_subject},
        retrieve_object_utils::retrieve_object_for_operation,
        uid_utils::{ObjectHandle, from_request},
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

/// Implementor of [`RekeyOperation`] for certificate rotation (`ReCertify`).
pub(crate) struct CertificateRekey {
    /// The `offset` from the `ReCertify` request (date computation per KMIP §6.1.45).
    offset: Option<i64>,
    /// Explicit issuer certificate link from the `ReCertify` request, if provided.
    /// When present, overrides the old certificate's own `PrivateKeyLink` so that
    /// CA-signed certificates are re-signed by the original issuer CA rather than
    /// by the subject's private key.
    issuer_cert_id: Option<String>,
    /// Explicit issuer private key link from the `ReCertify` request, if provided.
    issuer_private_key_id: Option<String>,
    /// Certificate Request Type from the `ReCertify` request.
    certificate_request_type: Option<CertificateRequestType>,
    /// Certificate Request Value from the `ReCertify` request: when present, the new
    /// certificate is issued from it (KMIP 2.1 §6.1.45: the request takes precedence).
    certificate_request_value: Option<Vec<u8>>,
    /// Certificate Request Unique Identifier from the `ReCertify` request: a managed
    /// Certificate Request to issue the new certificate from.
    certificate_request_unique_identifier: Option<UniqueIdentifier>,
}

/// KMIP `ReCertify` operation — certificate rotation with new UID.
///
/// Creates a new certificate for the same subject/issuer, assigns a fresh UID,
/// and links old → new via `ReplacementObjectLink`. Keys referencing the old
/// certificate are updated to point to the new one.
pub(crate) async fn recertify(
    kms: &KMS,
    request: ReCertify,
    owner: &UserId,
) -> KResult<ReCertifyResponse> {
    trace!("ReCertify request");
    let (issuer_cert_id, issuer_private_key_id) =
        request.attributes.as_ref().map_or((None, None), |attrs| {
            let cert = attrs
                .get_link(LinkType::CertificateLink)
                .map(|id| id.to_string());
            let key = attrs
                .get_link(LinkType::PrivateKeyLink)
                .map(|id| id.to_string());
            (cert, key)
        });
    Box::pin(execute_rekey(
        &CertificateRekey {
            offset: request.offset,
            issuer_cert_id,
            issuer_private_key_id,
            certificate_request_type: request.certificate_request_type,
            certificate_request_value: request.certificate_request_value.clone(),
            certificate_request_unique_identifier: request
                .certificate_request_unique_identifier
                .clone(),
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
        user: &UserId,
    ) -> KResult<[RotationCandidate; 1]> {
        KMS::reject_protection_storage_masks(request.protection_storage_masks.is_some())?;

        kms.enforce_create_permission(user).await?;

        let uid = from_request(request.unique_identifier.as_ref(), "ReCertify")?;

        let owm = Arc::unwrap_or_clone(
            Box::pin(retrieve_object_for_operation(
                uid,
                KmipOperation::Certify,
                kms,
                user,
            ))
            .await?,
        );

        let object_type = owm.object().object_type();
        if object_type != ObjectType::Certificate {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Object_Type,
                format!("ReCertify: object {uid} is a {object_type:?}, not a Certificate"),
            ));
        }

        // Table 302 lists no lifecycle-state reason: refuse with Permission Denied.
        let state = owm.effective_state();
        if state != State::Active && state != State::Deactivated {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Permission_Denied,
                format!(
                    "ReCertify: certificate '{uid}' is in state '{state}' — only Active or \
                     Deactivated certificates can be renewed"
                ),
            ));
        }
        if self.certificate_request_value.is_some() && self.certificate_request_type.is_none() {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                "ReCertify: Certificate Request Type is required with a Certificate Request"
                    .to_owned(),
            ));
        }

        Ok([RotationCandidate {
            owm,
            uid: uid.as_str().to_owned(),
        }])
    }

    async fn generate_replacement(
        &self,
        kms: &KMS,
        user: &UserId,
        candidates: &[RotationCandidate; 1],
    ) -> KResult<[ReplacementObject; 1]> {
        let [candidate] = candidates;
        // Derive the new UID: if the certificate is enrolled in a keyset
        // (`rotate_name` is set), follow the SQL keyset UID scheme (`name@N`);
        // otherwise generate a fresh UUID.
        let old_attrs = candidate.owm.attributes();
        let new_uid = UniqueIdentifier::rotation_successor(
            old_attrs.rotate_name.as_deref(),
            old_attrs.rotate_generation,
        );

        // Build a Certify request that references the existing certificate for renewal.
        // We pass the old certificate's UID so `get_subject` produces a `Subject::Certificate`.
        //
        // Base attributes come from the old certificate (preserves subject DN, validity, etc.).
        // Explicit issuer links from the ReCertify request override the cert's own PrivateKeyLink
        // so that CA-signed certificates are re-signed by the original issuer CA rather than by
        // the subject's private key (which the cert's PrivateKeyLink points to).
        let mut base_attrs = candidate.owm.attributes().clone();
        // KMIP 2.1 Table 299: not carried over to the new certificate
        base_attrs.revocation_reason = None;
        base_attrs.destroy_date = None;
        base_attrs.compromise_date = None;
        base_attrs.compromise_occurrence_date = None;
        base_attrs.state = None;
        if let Some(cert_id) = &self.issuer_cert_id {
            base_attrs.set_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::TextString(cert_id.clone()),
            );
            // The old cert's PrivateKeyLink points to the SUBJECT's private key, not the
            // issuer's.  When an explicit issuer cert is supplied, remove that link so
            // `get_issuer` derives the issuer private key from the issuer cert's own links
            // rather than misidentifying the subject key as the issuer key.
            if self.issuer_private_key_id.is_none() {
                base_attrs.remove_link(LinkType::PrivateKeyLink);
            }
        }
        if let Some(key_id) = &self.issuer_private_key_id {
            base_attrs.set_link(
                LinkType::PrivateKeyLink,
                LinkedObjectIdentifier::TextString(key_id.clone()),
            );
        }
        let certify_request = Certify {
            // A managed Certificate Request, when given, is the subject; otherwise the
            // existing certificate is renewed (an inline request takes precedence over both)
            unique_identifier: Some(
                self.certificate_request_unique_identifier
                    .clone()
                    .unwrap_or_else(|| UniqueIdentifier::TextString(candidate.uid.clone())),
            ),
            certificate_request_type: self.certificate_request_type,
            certificate_request_value: self.certificate_request_value.clone(),
            attributes: Some(Attributes {
                // The new certificate UID is set in the attributes so `get_subject` uses it.
                unique_identifier: Some(UniqueIdentifier::TextString(new_uid.clone())),
                ..base_attrs
            }),
            protection_storage_masks: None,
        };

        // Resolve subject and issuer as the requester: a grant on the certificate does not
        // extend to the owner's issuer key or Certificate Request objects.
        let subject = Box::pin(get_subject(kms, &certify_request, user)).await?;
        let issuer = Box::pin(get_issuer(&subject, kms, &certify_request, user)).await?;
        // Build and sign the new certificate
        let (certificate_object, tags, attributes) = build_and_sign_certificate(
            kms,
            &issuer,
            &subject,
            certify_request,
            kms.params.kms_public_url.as_deref(),
        )?;

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

    fn rewrap_new_objects(
        &self,
        _kms: &KMS,
        _user: &UserId,
        _replacements: &mut [ReplacementObject; 1],
        _wrap_specs: &[Option<KeyWrappingSpecification>],
    ) -> impl Future<Output = KResult<()>> {
        // Certificates are never wrapped — no-op, hence an already-completed future.
        std::future::ready(Ok(()))
    }

    async fn finalize_dependants(
        &self,
        kms: &KMS,
        user: &UserId,
        candidates: &[RotationCandidate; 1],
        replacements: &[ReplacementObject; 1],
    ) -> KResult<()> {
        let [candidate] = candidates;
        let [replacement] = replacements;

        // Phase 2: Update the old certificate with ReplacementObjectLink; only an Active
        // certificate is retired (Deactivation Date = now, §4.57 transition 6).
        let deactivate = candidate.owm.effective_state() == State::Active;
        let mut old_object = candidate.owm.object().clone();
        let mut old_attributes = candidate.owm.attributes().clone();
        old_attributes.retire_for_replacement(&replacement.new_uid, deactivate)?;
        if let Ok(obj_attrs) = old_object.attributes_mut() {
            obj_attrs.retire_for_replacement(&replacement.new_uid, deactivate)?;
        }
        if deactivate {
            old_attributes.state = Some(State::Deactivated);
            if let Ok(obj_attrs) = old_object.attributes_mut() {
                obj_attrs.state = Some(State::Deactivated);
            }
        }

        let mut operations = vec![AtomicOperation::UpdateObject((
            candidate.uid.clone(),
            old_object,
            old_attributes,
            None,
        ))];
        if deactivate {
            // UpdateObject only rewrites the `attributes` JSON column; the `state` column
            // must be updated separately so that `find_due_for_rotation` sees it.
            operations.push(AtomicOperation::UpdateState((
                candidate.uid.clone(),
                State::Deactivated,
            )));
        }

        // Relink keys: update CertificateLink on linked PK/SK to point to new cert UID
        relink_keys_to_new_certificate(
            kms,
            user,
            ObjectHandle::from(&candidate.uid),
            candidate.owm.attributes(),
            ObjectHandle::from(&replacement.new_uid),
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
    user: &UserId,
    old_cert: ObjectHandle<'_>,
    old_cert_attrs: &Attributes,
    new_cert: ObjectHandle<'_>,
    operations: &mut Vec<AtomicOperation>,
) -> KResult<()> {
    for lt in [LinkType::PublicKeyLink, LinkType::PrivateKeyLink] {
        if let Some(key_uid) = old_cert_attrs.get_link(lt) {
            let key_uid_str = linked_id_str(&key_uid);
            if let Some(op) = relink_single_key(
                kms,
                user,
                ObjectHandle::from(&*key_uid_str),
                old_cert,
                new_cert,
            )
            .await?
            {
                operations.push(op);
            }
        }
    }
    Ok(())
}

/// Update a single key's `CertificateLink` if it points to the old certificate.
///
/// A key the requester cannot `Certify` with is left untouched.
async fn relink_single_key(
    kms: &KMS,
    user: &UserId,
    key: ObjectHandle<'_>,
    old_cert: ObjectHandle<'_>,
    new_cert: ObjectHandle<'_>,
) -> KResult<Option<AtomicOperation>> {
    let key_uid = key.as_str();
    let Some(key_owm) = kms.database.retrieve_object_arc(key_uid).await? else {
        return Ok(None);
    };
    let Some(cert_link) = key_owm.attributes().get_link(LinkType::CertificateLink) else {
        return Ok(None);
    };
    if cert_link.to_string() != old_cert.as_str() {
        return Ok(None);
    }
    if !kms
        .user_can_perform_operation(&key_owm, user, &KmipOperation::Certify)
        .await?
    {
        warn!("ReCertify: not relinking key '{key_uid}': '{user}' cannot certify with it");
        return Ok(None);
    }

    let mut key_object = key_owm.object().clone();
    let mut key_attrs = key_owm.attributes().clone();
    let new_link = LinkedObjectIdentifier::TextString(new_cert.as_str().to_owned());
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
