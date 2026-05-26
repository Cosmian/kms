use std::default::Default;

#[cfg(not(feature = "non-fips"))]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
#[cfg(not(feature = "non-fips"))]
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::fips::{
            FIPS_PRIVATE_ECC_MASK_ECDH, FIPS_PRIVATE_ECC_MASK_SIGN,
            FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_ECC_MASK_ECDH,
            FIPS_PUBLIC_ECC_MASK_SIGN, FIPS_PUBLIC_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_RSA_MASK,
        },
        kmip_types::CryptographicAlgorithm,
    },
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip,
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_objects::ObjectType,
        kmip_operations::CreateKeyPair,
        kmip_types::{CertificateRequestType, UniqueIdentifier},
    },
    cosmian_kms_crypto::openssl::{
        certificate_attributes_to_subject_name, kmip_certificate_to_openssl,
    },
};
use cosmian_logger::info;
use openssl::x509::X509Req;

use super::subject::{KeyPairData, Subject};
use crate::{
    core::{
        KMS,
        operations::create_key_pair::generate_key_pair,
        retrieve_object_utils::{retrieve_object_for_operation, user_has_permission},
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

#[cfg(not(feature = "non-fips"))]
fn cryptographic_usage_mask_private_key(
    cryptographic_algorithm: CryptographicAlgorithm,
) -> KResult<CryptographicUsageMask> {
    Ok(match cryptographic_algorithm {
        CryptographicAlgorithm::RSA => FIPS_PRIVATE_RSA_MASK,
        CryptographicAlgorithm::ECDH => FIPS_PRIVATE_ECC_MASK_ECDH,
        CryptographicAlgorithm::ECDSA
        | CryptographicAlgorithm::Ed25519
        | CryptographicAlgorithm::Ed448 => FIPS_PRIVATE_ECC_MASK_SIGN,
        CryptographicAlgorithm::EC => FIPS_PRIVATE_ECC_MASK_SIGN_ECDH,
        c => kms_bail!(KmsError::InvalidRequest(format!(
            "Cryptographic algorithm not supported for private key in FIPS mode: {c}"
        ))),
    })
}

#[cfg(not(feature = "non-fips"))]
fn cryptographic_usage_mask_public_key(
    cryptographic_algorithm: CryptographicAlgorithm,
) -> KResult<CryptographicUsageMask> {
    Ok(match cryptographic_algorithm {
        CryptographicAlgorithm::RSA => FIPS_PUBLIC_RSA_MASK,
        CryptographicAlgorithm::ECDH => FIPS_PUBLIC_ECC_MASK_ECDH,
        CryptographicAlgorithm::ECDSA
        | CryptographicAlgorithm::Ed25519
        | CryptographicAlgorithm::Ed448 => FIPS_PUBLIC_ECC_MASK_SIGN,
        CryptographicAlgorithm::EC => FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
        c => kms_bail!(KmsError::InvalidRequest(format!(
            "Cryptographic algorithm not supported for private key in FIPS mode: {c}"
        ))),
    })
}

/// Determine the subject of the issued certificate.
/// The subject can be recovered from different sources:
/// - a public key and a subject name
/// - a certificate
/// - a key pair and a subject name
/// - a CSR
pub(super) async fn get_subject(
    kms: &KMS,
    request: &cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Certify,
    user: &str,
    privileged_users: Option<Vec<String>>,
) -> KResult<Subject> {
    // Did the user provide a CSR?
    if let Some(pkcs10_bytes) = request.certificate_request_value.as_ref() {
        let x509_req = match &request
            .certificate_request_type
            .as_ref()
            .unwrap_or(&CertificateRequestType::PEM)
        {
            CertificateRequestType::PEM => X509Req::from_pem(pkcs10_bytes),
            CertificateRequestType::PKCS10 => X509Req::from_der(pkcs10_bytes),
            CertificateRequestType::CRMF => kms_bail!(KmsError::InvalidRequest(
                "Certificate Request Type CRMF not supported".to_owned()
            )),
        }?;
        let certificate_id = request
            .attributes
            .as_ref()
            .and_then(|attributes| attributes.unique_identifier.clone())
            .unwrap_or_default();
        // see if there is a link to a private key (in case of self-signed cert)
        return Ok(Subject::X509Req(certificate_id, x509_req));
    }

    // no CSR provided. Was the reference to an existing certificate or public key provided?
    let public_key = if let Some(request_id) = &request.unique_identifier {
        if let Ok(owm) = Box::pin(retrieve_object_for_operation(
            &request_id.to_string(),
            KmipOperation::Certify,
            kms,
            user,
        ))
        .await
        {
            let object_type = owm.object().object_type();
            match object_type {
                // If the user passed a certificate, attempt to renew it
                ObjectType::Certificate => {
                    let certificate_id = request
                        .attributes
                        .as_ref()
                        .and_then(|attributes| attributes.unique_identifier.clone())
                        .unwrap_or_else(|| request_id.clone());
                    return Ok(Subject::Certificate(
                        certificate_id,
                        kmip_certificate_to_openssl(owm.object())?,
                        owm.attributes().to_owned(),
                    ));
                }
                // If the user passed a public key, it is a new certificate signing this public key
                ObjectType::PublicKey => Some(owm),
                // Invalid request
                x => kms_bail!("Invalid Certify request for object type {x:?}"),
            }
        } else {
            return Err(KmsError::ItemNotFound(request_id.to_string()));
        }
    } else {
        None
    };

    // This is a request based on a Subject Name
    let attributes = request.attributes.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Certify from Subject: the attributes specifying the the subject name are missing"
                .to_owned(),
        )
    })?;
    let subject_name = certificate_attributes_to_subject_name(
        attributes.certificate_attributes.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest(
                "Certify from Subject: the subject name is not found in the attributes".to_owned(),
            )
        })?,
    )?;

    // If we have a public key, we can create a certificate from it
    if let Some(mut public_key) = public_key {
        // The public key may be stored in wrapped form (e.g. when using a KEK).
        // Unwrap it before using it for certificate creation.
        let unwrapped_object = kms
            .get_unwrapped(public_key.id(), public_key.object(), user)
            .await?;
        public_key.set_object(unwrapped_object);
        return Ok(Subject::PublicKeyAndSubjectName(
            attributes.unique_identifier.clone().unwrap_or_default(),
            public_key,
            subject_name,
        ));
    }

    // If we do not have a public key, we need to create a key pair

    // For creation of an object, check that user has create access-right
    // The `Create` right implicitly grants permission for Create, Import, and Register operations.
    if let Some(users) = privileged_users {
        let has_permission = user_has_permission(
            user,
            None,
            &cosmian_kmip::kmip_2_1::KmipOperation::Create,
            kms,
        )
        .await?;

        if !has_permission && !users.iter().any(|u| u == user) {
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right.".to_owned()
            ))
        }
    }

    let sk_uid = UniqueIdentifier::default();
    let pk_uid = UniqueIdentifier::default();
    // We expect the attributes to contain the cryptographic algorithm and parameters
    #[cfg(not(feature = "non-fips"))]
    let (private_attributes, public_attributes) = {
        let cryptographic_algorithm = attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "Keypair creation: the cryptographic algorithm is missing".to_owned(),
            )
        })?;
        let private_attributes = Attributes {
            cryptographic_usage_mask: Some(cryptographic_usage_mask_private_key(
                cryptographic_algorithm,
            )?),
            ..Default::default()
        };
        let public_attributes = Attributes {
            cryptographic_usage_mask: Some(cryptographic_usage_mask_public_key(
                cryptographic_algorithm,
            )?),
            ..Default::default()
        };
        (Some(private_attributes), Some(public_attributes))
    };
    #[cfg(feature = "non-fips")]
    let (private_attributes, public_attributes) = (None, None);
    let create_key_pair_request = CreateKeyPair {
        common_attributes: Some(attributes.to_owned()),
        private_key_attributes: private_attributes,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
        public_key_attributes: public_attributes,
    };
    info!("Creating key pair for certification - private key: {sk_uid}, public key: {pk_uid}");
    let key_pair = generate_key_pair(
        kms.vendor_id(),
        create_key_pair_request,
        &sk_uid.to_string(),
        &pk_uid.to_string(),
    )?;
    info!("Key pair created for certification");

    Ok(Subject::KeypairAndSubjectName(
        attributes.unique_identifier.clone().unwrap_or_default(),
        KeyPairData {
            private_key_id: sk_uid,
            private_key_object: key_pair.private_key().to_owned(),
            private_key_tags: key_pair
                .private_key()
                .attributes()?
                .get_tags(kms.vendor_id()),
            public_key_id: pk_uid,
            public_key_object: key_pair.public_key().to_owned(),
            public_key_tags: key_pair
                .public_key()
                .attributes()?
                .get_tags(kms.vendor_id()),
        },
        subject_name,
    ))
}
