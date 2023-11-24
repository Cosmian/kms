use cosmian_kmip::{
    kmip::{kmip_objects::Object, kmip_types::LinkType},
    result::KmipResultHelper,
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use openssl::x509::X509;
pub(crate) use tags::{
    add_attributes_to_certificate_tags, add_certificate_system_tags,
    add_certificate_tags_to_attributes,
};

// use self::ca_signing_key::CASigningKey;
use super::KMS;
use crate::{
    database::{object_with_metadata::ObjectWithMetadata, retrieve_object_for_operation},
    error::KmsError,
    kms_bail,
};

//TODO: the quick cert functionality needs to be completely revisited as it is not part of KMIP and converted to openssl
#[allow(dead_code)]
mod quick_cert;
mod tags;

//TODO: the validate functionality needs to be assigned to the Validate KMIP operation and converted to openssl
#[allow(dead_code)]
mod validate;

/// Retrieve the certificate associated to the given private key
pub(crate) async fn retrieve_certificate_for_private_key(
    private_key: &Object,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<(ObjectWithMetadata, X509), KmsError> {
    // recover the Certificate Link inside the Private Key
    let attributes = private_key.attributes().map_err(|_| {
        KmsError::InvalidRequest(
            "PKCS#12 export: no attributes found in the Private Key".to_string(),
        )
    })?;
    let certificate_id = attributes
        .get_link(LinkType::PKCS12CertificateLink)
        .or_else(|| attributes.get_link(LinkType::CertificateLink))
        .ok_or_else(|| {
            KmsError::InvalidRequest("No certificate link found for the private key".to_string())
        })?;

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
    // convert the certificate to openssl X509
    let certificate = X509::from_der(match &cert_owm.object {
        Object::Certificate {
            certificate_value, ..
        } => certificate_value,
        _ => kms_bail!("export: expected a certificate behind the private key certificate link"),
    })?;
    Ok((cert_owm, certificate))
}
