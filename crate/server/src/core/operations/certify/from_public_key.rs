use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{
        kmip_operations::{Certify, CertifyResponse},
        kmip_types::{LinkType, LinkedObjectIdentifier, StateEnumeration},
    },
    openssl::kmip_public_key_to_openssl,
};

use crate::{
    core::{
        extra_database_params::ExtraDatabaseParams,
        operations::certify::certificate_from_subject_and_pk, KMS,
    },
    database::{object_with_metadata::ObjectWithMetadata, AtomicOperation},
    error::KmsError,
    result::KResult,
};

pub async fn create_certificate_from_public_key(
    mut public_key: ObjectWithMetadata,
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    let mut attributes = request.attributes.clone().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify from Public Key: the attributes specifying the issuer private key is (and/or \
             certificate is) as well as the subject name are missing"
                .to_string(),
        )
    })?;
    let certificate_subject_name = attributes
        .certificate_attributes
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest("The subject name is not found in the attributes".to_string())
        })?
        .subject_name()?;

    // Convert the Public Key to openssl format
    let certificate_pkey = kmip_public_key_to_openssl(&public_key.object)?;

    // we want to transfer some of the public key attributes to the certificate
    // links to the private key, if any, user tags
    if let Some(link) = public_key.attributes.get_link(LinkType::PrivateKeyLink) {
        attributes.add_link(LinkType::PrivateKeyLink, link)
    }
    // link to this public key
    attributes.add_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(public_key.id.clone()),
    );
    // Merge public key tags and tags passed in the request
    let mut user_tags: HashSet<String> = public_key.attributes.get_tags();
    user_tags.extend(attributes.get_tags());
    //filter out system tags
    let user_tags = user_tags
        .into_iter()
        .filter(|t| !t.starts_with('_'))
        .collect();

    // generate a certificate and id
    let (certificate_id, certificate) = certificate_from_subject_and_pk(
        certificate_subject_name,
        certificate_pkey,
        kms,
        request,
        user,
        params,
    )
    .await?;

    // Update the public key with the certificate info
    public_key
        .attributes
        .add_link(LinkType::CertificateLink, certificate_id.clone().into());

    kms.db
        .atomic(
            user,
            vec![
                // upsert the certificate
                AtomicOperation::Upsert((
                    certificate_id.to_string(),
                    certificate,
                    attributes.clone(),
                    Some(user_tags),
                    StateEnumeration::Active,
                )),
                // update the public key
                AtomicOperation::UpdateObject((
                    public_key.id,
                    public_key.object,
                    public_key.attributes,
                    None,
                )),
            ]
            .as_slice(),
            params,
        )
        .await?;
    Ok(CertifyResponse {
        unique_identifier: certificate_id,
    })
}
