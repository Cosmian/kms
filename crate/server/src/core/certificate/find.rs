use cosmian_kmip::kmip::{kmip_objects::Object, kmip_types::LinkType};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};

use crate::{
    core::KMS,
    database::{object_with_metadata::ObjectWithMetadata, retrieve_object_for_operation},
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
pub(crate) async fn retrieve_matching_private_key_and_certificate(
    private_key_id: Option<String>,
    certificate_id: Option<String>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<(ObjectWithMetadata, ObjectWithMetadata)> {
    if let (Some(private_key_id), Some(certificate_id)) = (&private_key_id, &certificate_id) {
        // Retrieve the certificate
        let certificate = retrieve_object_for_operation(
            certificate_id,
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await?;
        let private_key = retrieve_object_for_operation(
            private_key_id,
            ObjectOperationType::Certify,
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
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await?;
        let certificate = retrieve_certificate_for_private_key(
            &private_key.object,
            ObjectOperationType::Certify,
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
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await?;
        let private_key = retrieve_private_key_for_certificate(
            certificate_id,
            ObjectOperationType::Certify,
            kms,
            user,
            params,
        )
        .await?;
        return Ok((private_key, certificate))
    }

    kms_bail!(KmsError::InvalidRequest(
        "Either an issuer certificate id or an issuer private key id or both must be provided"
            .to_string(),
    ))
}

/// Retrieve the certificate associated to the given private key
pub(crate) async fn retrieve_certificate_for_private_key(
    private_key: &Object,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<ObjectWithMetadata, KmsError> {
    // recover the Certificate Link inside the Private Key
    let attributes = private_key.attributes().map_err(|_| {
        KmsError::InvalidRequest(
            "PKCS#12 export: no attributes found in the Private Key".to_string(),
        )
    })?;
    let certificate_id = attributes
        .get_link(LinkType::PKCS12CertificateLink)
        .or_else(|| attributes.get_link(LinkType::CertificateLink));

    let certificate_id = if let Some(certificate_id) = certificate_id {
        certificate_id
    } else {
        // check if there is a link to a public key
        let public_key_id = attributes
            .get_link(LinkType::PublicKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest("No public key link found for the private key".to_string())
            })?;
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
    let cert_owm =
        retrieve_object_for_operation(&certificate_id, operation_type, kms, user, params)
            .await
            .with_context(|| {
                format!(
                    "could not retrieve the certificate: {certificate_id}, attached to the \
                     private key"
                )
            })?;
    Ok(cert_owm)
}

/// Retrieve the certificate associated to the given private key
pub(crate) async fn retrieve_private_key_for_certificate(
    certificate_id: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<ObjectWithMetadata, KmsError> {
    let owm = retrieve_object_for_operation(
        certificate_id,
        ObjectOperationType::GetAttributes,
        kms,
        user,
        params,
    )
    .await?;

    let private_key_id = owm
        .attributes
        .get_link(LinkType::PKCS12CertificateLink)
        .or_else(|| owm.attributes.get_link(LinkType::CertificateLink));

    let private_key_id = if let Some(private_key_id) = private_key_id {
        private_key_id
    } else {
        // check if there is a link to a public key
        let public_key_id = owm
            .attributes
            .get_link(LinkType::PublicKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "No private or public key link found for the certificate".to_string(),
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
    retrieve_object_for_operation(&private_key_id, operation_type, kms, user, params)
        .await
        .with_context(|| {
            format!("could not retrieve the private key: {private_key_id} for the certificate")
        })
}

async fn find_link_in_public_key(
    link_type: LinkType,
    public_key_id: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<String, KmsError> {
    // TODO: retrieve only the attributes when #88 is fixed
    let public_key_owm =
        retrieve_object_for_operation(public_key_id, operation_type, kms, user, params).await?;
    let public_key_attributes = public_key_owm.object.attributes().with_context(|| {
        format!("could not retrieve the public key attributes: {public_key_id}")
    })?;
    // retrieve the private key linked to the public key
    public_key_attributes.get_link(link_type).ok_or_else(|| {
        KmsError::InvalidRequest(format!("No {link_type:?} found in the public key"))
    })
}
