#![allow(clippy::unwrap_used)]

use std::{fs, path, sync::Arc};

use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Import, Validate},
    kmip_types::{Attributes, CertificateType, UniqueIdentifier, ValidityIndicator},
};
use tracing::debug;

use crate::{
    config::ServerParams, core::KMS, error::KmsError, tests::test_utils::https_clap_config,
};

#[tokio::test]
pub(crate) async fn test_validate_with_certificates_bytes() -> Result<(), KmsError> {
    cosmian_logger::log_utils::log_init(None);
    let root_path = path::Path::new("src/tests/certificates/chain/ca.cert.der");
    let intermediate_path = path::Path::new("src/tests/certificates/chain/intermediate.cert.der");
    let leaf1_path = path::Path::new("src/tests/certificates/chain/leaf1.cert.der"); // invalid
    let leaf2_path = path::Path::new("src/tests/certificates/chain/leaf2.cert.der"); // valid
    let root_cert = fs::read(root_path)?;
    let intermediate_cert = fs::read(intermediate_path)?;
    let leaf1_cert = fs::read(leaf1_path)?;
    let leaf2_cert = fs::read(leaf2_path)?;

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    let request = Validate {
        certificate: Some([root_cert.clone()].to_vec()),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    debug!("OK: Validate root certificate");
    let request = Validate {
        certificate: Some([intermediate_cert.clone(), root_cert.clone()].to_vec()),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    debug!("OK: Validate root/intermediate certificates");
    let request = Validate {
        certificate: Some(
            [
                intermediate_cert.clone(),
                leaf1_cert.clone(),
                root_cert.clone(),
            ]
            .to_vec(),
        ),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());
    debug!("OK: Validate root/intermediate/leaf1 certificates - invalid (revoked)");
    let request = Validate {
        certificate: Some(
            [
                intermediate_cert.clone(),
                leaf2_cert.clone(),
                root_cert.clone(),
            ]
            .to_vec(),
        ),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    debug!("OK: Validate root/intermediate/leaf certificates - valid");
    let request = Validate {
        certificate: Some(
            [
                intermediate_cert.clone(),
                leaf2_cert.clone(),
                root_cert.clone(),
            ]
            .to_vec(),
        ),
        unique_identifier: None,
        validity_time: //Some(Asn1Time::days_from_now(3651).unwrap().to_owned()), // this is supposed to work but it does not.
        Some("4804152030Z".to_owned())
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());
    debug!("OK: Validate root/intermediate/leaf2 certificates - invalid");
    let request = Validate {
        certificate: Some([leaf2_cert.clone(), root_cert.clone()].to_vec()),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());
    debug!("OK: Validate root/leaf2 certificates - missing intermediate");

    Result::Ok(())
}

#[tokio::test]
pub(crate) async fn test_validate_with_certificates_ids() -> Result<(), KmsError> {
    cosmian_logger::log_utils::log_init(None);
    let root_path = path::Path::new("src/tests/certificates/chain/ca.cert.der");
    let intermediate_path = path::Path::new("src/tests/certificates/chain/intermediate.cert.der");
    let leaf1_path = path::Path::new("src/tests/certificates/chain/leaf1.cert.der"); // invalid
    let leaf2_path = path::Path::new("src/tests/certificates/chain/leaf2.cert.der"); // valid

    let root_cert = fs::read(root_path)?;
    let intermediate_cert = fs::read(intermediate_path)?;
    let leaf1_cert = fs::read(leaf1_path)?;
    let leaf2_cert = fs::read(leaf2_path)?;

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    // add certificates to kms
    // root
    let root_request = Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: ObjectType::Certificate,
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        },
        object: cosmian_kmip::kmip::kmip_objects::Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: root_cert.clone(),
        },
    };
    let res_root = kms.import(root_request, owner, None).await?;
    // intermediate
    let intermediate_request = Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: ObjectType::Certificate,
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        },
        object: cosmian_kmip::kmip::kmip_objects::Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: intermediate_cert.clone(),
        },
    };
    let res_intermediate = kms.import(intermediate_request, owner, None).await?;
    // leaf1
    let leaf1_request = Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: ObjectType::Certificate,
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        },
        object: cosmian_kmip::kmip::kmip_objects::Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: leaf1_cert.clone(),
        },
    };
    let res_leaf1 = kms.import(leaf1_request, owner, None).await?;
    // Only the root, it is valid by default
    let request = Validate {
        certificate: None,
        unique_identifier: Some([res_root.unique_identifier.clone()].to_vec()),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    debug!("OK: Validate root - valid");

    // Root and intermediate valid certificates. Good structure.
    let request = Validate {
        certificate: None,
        unique_identifier: Some(vec![
            res_intermediate.unique_identifier.clone(),
            res_root.unique_identifier.clone(),
        ]),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    debug!("OK: Validate root/intermediate certificates - valid");

    // Root and intermediate valid certificates. Leaf revoked. Test returns invalid.
    let request = Validate {
        certificate: None,
        unique_identifier: Some(vec![
            res_intermediate.unique_identifier.clone(),
            res_leaf1.unique_identifier.clone(),
            res_root.unique_identifier.clone(),
        ]),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());
    debug!("OK: Validate root/intermediate/leaf1 certificates - invalid (revoked)");

    // No certificate in chain
    let request = Validate {
        certificate: None,
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());

    // Root and intermediate valid certificates. Leaf valid. Test returns valid.
    let request = Validate {
        certificate: Some(vec![leaf2_cert.clone()]),
        unique_identifier: Some(vec![
            res_intermediate.unique_identifier.clone(),
            res_root.unique_identifier.clone(),
        ]),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    debug!("OK: Validate root/intermediate/leaf2 certificates - valid");

    // Root and intermediate valid certificates. Leaf valid. Test returns valid. Testing deduplicating unique identifiers.
    let request = Validate {
        certificate: Some(vec![leaf2_cert.clone()]),
        unique_identifier: Some(vec![
            res_root.unique_identifier.clone(),
            res_root.unique_identifier.clone(),
            res_intermediate.unique_identifier.clone(),
            res_intermediate.unique_identifier.clone(),
        ]),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    debug!("OK: Validate root/intermediate/leaf2 certificates - valid");

    // Root and intermediate valid certificates. Leaf valid. Date provided is future to the expiration of the certificates. Test returns invalid.
    let request = Validate {
        certificate: Some(vec![leaf2_cert.clone()]),
        unique_identifier: Some(
            vec![
                res_intermediate.unique_identifier.clone(),
                res_root.unique_identifier.clone(),
            ],
        ),
        validity_time: //Some(Asn1Time::days_from_now(3651).unwrap().to_owned()), // this is supposed to work but it does not.
        Some("4804152030Z".to_owned())
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());
    debug!(
        "OK: Validate root/intermediate/leaf2 certificates - invalid (won't be valid in the \
         future)"
    );

    // Root is a valid certificates. Leaf too. Missing intermediate certificate. Result Invalid.
    let request = Validate {
        certificate: Some(vec![leaf2_cert.clone()]),
        unique_identifier: Some(vec![res_root.unique_identifier.clone()]),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());

    debug!("OK: Validate root/leaf2 certificates - invalid (missing intermediate)");
    // Root certificate not provided. Intermediate and leaf are valid certificates. Return is Invalid.
    let request = Validate {
        certificate: Some([leaf2_cert.clone()].to_vec()),
        unique_identifier: Some([res_intermediate.unique_identifier.clone()].to_vec()),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await;
    assert!(res.is_err());
    debug!("OK: Validate root/leaf2 certificates - invalid (missing root)");

    Result::Ok(())
}

//same tests but certs imported in kms.
