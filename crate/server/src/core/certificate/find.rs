use cosmian_kmip::kmip::{
    kmip_types::{LinkType, LinkedObjectIdentifier},
    KmipOperation,
};
use cosmian_kms_server_database::{ExtraStoreParams, ObjectWithMetadata};
use tracing::trace;

use crate::{
    core::{retrieve_object_utils::retrieve_object_for_operation, KMS},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Retrieve the certificate associated to the given private key.
///
/// If the private key is not provided, the private key is retrieved from the certificate.
/// If the certificate id is not provided, the certificate is retrieved from the private key.
/// If none are provided, an error is returned.
///
/// Retrieval is done by following links through the public key when necessary.
pub(crate) async fn retrieve_issuer_private_key_and_certificate(
    private_key_id: Option<String>,
    certificate_id: Option<String>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<(ObjectWithMetadata, ObjectWithMetadata)> {
    trace!(
        "Retrieving issuer private key and certificate: private_key_id: {:?}, certificate_id: {:?}",
        private_key_id,
        certificate_id
    );
    if let (Some(private_key_id), Some(certificate_id)) = (&private_key_id, &certificate_id) {
        // Retrieve the certificate
        let certificate = retrieve_object_for_operation(
            certificate_id,
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
        .await?;
        let private_key = retrieve_object_for_operation(
            private_key_id,
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
        .await?;
        return Ok((private_key, certificate))
    }

    if let Some(private_key_id) = &private_key_id {
        let private_key = retrieve_object_for_operation(
            private_key_id,
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
        .await?;
        let certificate = retrieve_certificate_for_private_key(
            &private_key,
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
        .await?;
        return Ok((private_key, certificate))
    }

    if let Some(certificate_id) = &certificate_id {
        // Retrieve the certificate
        let certificate = retrieve_object_for_operation(
            certificate_id,
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
        .await?;
        let private_key = retrieve_private_key_for_certificate(
            certificate_id,
            KmipOperation::Certify,
            kms,
            user,
            params,
        )
        .await?;
        return Ok((private_key, certificate))
    }

    kms_bail!(KmsError::InvalidRequest(
        "Either an issuer certificate id or an issuer private key id or both must be provided"
            .to_owned(),
    ))
}

/// Retrieve the certificate associated to the given private key
pub(crate) async fn retrieve_certificate_for_private_key(
    private_key: &ObjectWithMetadata,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> Result<ObjectWithMetadata, KmsError> {
    trace!(
        "Retrieving certificate for private key: {}",
        private_key.id()
    );
    // recover the Certificate Link inside the Private Key
    let certificate_id = private_key
        .attributes()
        .get_link(LinkType::PKCS12CertificateLink)
        .or_else(|| private_key.attributes().get_link(LinkType::CertificateLink));

    let certificate_id = if let Some(certificate_id) = certificate_id {
        trace!("found link to certificate: {}", certificate_id);
        certificate_id
    } else {
        // check if there is a link to a public key
        let public_key_id = private_key
            .attributes()
            .get_link(LinkType::PublicKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest("No public key link found for the private key".to_owned())
            })?;
        trace!(
            "found link to public key: {}. Will get certificate link from there",
            public_key_id
        );
        find_link_in_public_key(
            LinkType::CertificateLink,
            &public_key_id,
            operation_type,
            kms,
            user,
            params,
        )
        .await?
    };

    // retrieve the certificate
    let cert_owm = retrieve_object_for_operation(
        &certificate_id.to_string(),
        operation_type,
        kms,
        user,
        params,
    )
    .await
    .with_context(|| {
        format!("could not retrieve the certificate: {certificate_id}, attached to the private key")
    })?;
    trace!(
        "Retrieved certificate: {} for private key: {}",
        cert_owm.id(),
        private_key.id()
    );
    Ok(cert_owm)
}

/// Retrieve the certificate associated to the given private key
pub(crate) async fn retrieve_private_key_for_certificate(
    certificate_uid_or_tags: &str,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> Result<ObjectWithMetadata, KmsError> {
    trace!(
        "Retrieving private key for certificate: certificate_uid_or_tags: {:?}",
        certificate_uid_or_tags
    );
    let owm = retrieve_object_for_operation(
        certificate_uid_or_tags,
        KmipOperation::GetAttributes,
        kms,
        user,
        params,
    )
    .await?;

    let private_key_id = owm.attributes().get_link(LinkType::PrivateKeyLink);

    let private_key_id = if let Some(private_key_id) = private_key_id {
        private_key_id
    } else {
        // check if there is a link to a public key
        let public_key_id = owm
            .attributes()
            .get_link(LinkType::PublicKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private or public key link found for the certificate".to_owned(),
                )
            })?;
        find_link_in_public_key(
            LinkType::PrivateKeyLink,
            &public_key_id,
            operation_type,
            kms,
            user,
            params,
        )
        .await?
    };
    // retrieve the private key
    retrieve_object_for_operation(
        &private_key_id.to_string(),
        operation_type,
        kms,
        user,
        params,
    )
    .await
    .with_context(|| {
        format!("could not retrieve the private key: {private_key_id} for the certificate")
    })
}

async fn find_link_in_public_key(
    link_type: LinkType,
    public_key_id: &LinkedObjectIdentifier,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> Result<LinkedObjectIdentifier, KmsError> {
    // TODO: retrieve only the attributes when #88 is fixed
    let public_key_owm = retrieve_object_for_operation(
        &public_key_id.to_string(),
        operation_type,
        kms,
        user,
        params,
    )
    .await?;
    let public_key_attributes = public_key_owm.attributes();
    // retrieve the private key linked to the public key
    public_key_attributes.get_link(link_type).ok_or_else(|| {
        KmsError::InvalidRequest(format!("No {link_type:?} found in the public key"))
    })
}
