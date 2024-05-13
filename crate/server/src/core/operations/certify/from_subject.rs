use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{
        kmip_operations::{Certify, CertifyResponse, CreateKeyPair},
        kmip_types::{LinkType, LinkedObjectIdentifier, StateEnumeration, UniqueIdentifier},
    },
    openssl::kmip_public_key_to_openssl,
};
use uuid::Uuid;

use crate::{
    core::{
        certificate::retrieve_issuer_private_key_and_certificate,
        extra_database_params::ExtraDatabaseParams,
        operations::{
            certify::certificate_from_subject_and_pk, create_key_pair::generate_key_pair_and_tags,
        },
        KMS,
    },
    database::AtomicOperation,
    error::KmsError,
    result::KResult,
};

pub async fn create_certificate_from_subject(
    certificate_id: UniqueIdentifier,
    kms: &KMS,
    request: Certify,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    let mut attributes = request.attributes.clone().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify from Subject: the attributes specifying the issuer private key is (and/or \
             certificate is) as well as the subject name are missing"
                .to_string(),
        )
    })?;
    let certificate_subject_name = attributes
        .certificate_attributes
        .as_ref()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Certify from Subject: the subject name is not found in the attributes".to_string(),
            )
        })?
        .subject_name()?;

    // retrieve the issuer sk and certificate from either the certificate link or the private key link
    // Retrieve the issuer certificate id if provided
    let issuer_certificate_id = attributes.get_link(LinkType::CertificateLink);
    // Retrieve the issuer private key id if provided
    let issuer_private_key_id = attributes.get_link(LinkType::PrivateKeyLink);

    // Retrieve the issuer certificate and the issuer private key
    let (issuer_private_key, issuer_certificate) = retrieve_issuer_private_key_and_certificate(
        issuer_private_key_id.map(|id| id.to_string()),
        issuer_certificate_id.map(|id| id.to_string()),
        kms,
        user,
        params,
    )
    .await?;

    // If no cryptographic algorithm or parameters are specified, use the one of the issuer
    if attributes.cryptographic_algorithm.is_none() {
        attributes.cryptographic_algorithm = issuer_private_key
            .attributes
            .cryptographic_algorithm
            .clone();
    }
    if attributes.cryptographic_parameters.is_none() {
        attributes.cryptographic_parameters = issuer_private_key
            .attributes
            .cryptographic_parameters
            .clone();
    }
    if attributes.cryptographic_domain_parameters.is_none() {
        attributes.cryptographic_domain_parameters = issuer_private_key
            .attributes
            .cryptographic_domain_parameters
            .clone();
    }
    if attributes.cryptographic_length.is_none() {
        attributes.cryptographic_length =
            issuer_private_key.attributes.cryptographic_length.clone();
    }

    // set the usage masks

    // crete a key pair with the same algorithm as the issuer private key
    // generate uids and create the key pair and tags

    let sk_uid = Uuid::new_v4().to_string();
    let pk_uid = Uuid::new_v4().to_string();
    let create_key_pair_request = CreateKeyPair {
        common_attributes: None,
        private_key_attributes: None,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
        public_key_attributes: None,
    };
    let (key_pair, sk_tags, pk_tags) =
        generate_key_pair_and_tags(create_key_pair_request, &sk_uid, &pk_uid)?;
    let private_key = key_pair.private_key();
    let public_key = key_pair.public_key();

    // Convert the Public Key to openssl format
    let certificate_pkey = kmip_public_key_to_openssl(public_key)?;
    let (certificate_id, certificate) = certificate_from_subject_and_pk(
        certificate_subject_name,
        certificate_pkey,
        kms,
        request,
        user,
        params,
    )
    .await?;

    // now we have the 3 objects, sk, pk, cert.
    // Update attributes and tags
    let user_tags: HashSet<String> = attributes
        .get_tags()
        .into_iter()
        .filter(|t| !t.starts_with('_'))
        .collect();

    // secret

    // we want to transfer some of the public key attributes to the certificate
    // links to the private key, if any, user tags
    if let Some(link) = public_key.attributes()?.get_link(LinkType::PrivateKeyLink) {
        attributes.add_link(LinkType::PrivateKeyLink, link)
    }
    // link to this public key
    attributes.add_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(pk_uid.clone()),
    );
    // Merge public key tags and tags passed in the request

    attributes.set_tags(user_tags)?;

    let mut private_key_attributes = key_pair.private_key().attributes()?.clone();
    // Update the private key with the certificate info
    private_key_attributes.add_link(LinkType::CertificateLink, certificate_id.clone().into());

    let mut public_key_attributes = key_pair.public_key().attributes()?.clone();
    // Update the public key with the certificate info
    public_key_attributes.add_link(LinkType::CertificateLink, certificate_id.clone().into());

    let operations = vec![
        AtomicOperation::Create((
            sk_uid.clone(),
            key_pair.private_key().to_owned(),
            private_key_attributes,
            sk_tags,
        )),
        AtomicOperation::Create((
            pk_uid.clone(),
            key_pair.public_key().to_owned(),
            public_key_attributes,
            pk_tags,
        )),
        AtomicOperation::Upsert((
            certificate_id.to_string(),
            certificate,
            attributes.clone(),
            Some(user_tags),
            StateEnumeration::Active,
        )),
    ];

    todo!()
}
