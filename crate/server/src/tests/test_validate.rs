use std::{fs, path, sync::Arc};

use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Import, Validate},
    kmip_types::{Attributes, CertificateType, UniqueIdentifier, ValidityIndicator},
};

use crate::{
    config::ServerParams, error::KmsError, tests::test_utils::https_clap_config, KMSServer,
};

#[tokio::test]
pub async fn test() -> Result<(), KmsError> {
    let root_path = path::Path::new("src/tests/certificates/chain/ca.cert.der");
    let intermediate_path = path::Path::new("src/tests/certificates/chain/intermediate.cert.der");
    let leaf1_path = path::Path::new("src/tests/certificates/chain/leaf1.cert.der"); // invalid
    let leaf2_path = path::Path::new("src/tests/certificates/chain/leaf2.cert.der"); // valid
    let root_cert = fs::read(root_path)?;
    let intermediate_cert = fs::read(intermediate_path)?;
    let leaf1_cert = fs::read(leaf1_path)?;
    let leaf2_cert = fs::read(leaf2_path)?;

    let clap_config = https_clap_config();
    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(clap_config).await?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    let request = Validate {
        certificate: Some([root_cert.clone()].to_vec()),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    print!("\n\n ####### End first test! #######\n\n");
    let request = Validate {
        certificate: Some([intermediate_cert.clone(), root_cert.clone()].to_vec()),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    print!("\n\n ####### End second test! #######\n\n");
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
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Invalid);
    print!("\n\n ####### End third test! #######\n\n");
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
    print!("\n\n ####### End fourth test! #######\n\n");
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
        validity_time: //Some(Asn1Time::days_from_now(3651).unwrap().to_string()), // this is supposed to work but it does not.
        Some("4804152030Z".to_string())
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Invalid); // Test designed to be invalid
    print!("\n\n ####### End fifth test! #######\n\n");
    let request = Validate {
        certificate: Some([leaf2_cert.clone(), root_cert.clone()].to_vec()),
        unique_identifier: None,
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Invalid);
    print!("\n\n ####### End sixth test! #######\n\n");

    Result::Ok(())
}

#[tokio::test]
pub async fn test_kms() -> Result<(), KmsError> {
    let root_path = path::Path::new("src/tests/certificates/chain/ca.cert.der");
    let intermediate_path = path::Path::new("src/tests/certificates/chain/intermediate.cert.der");
    let leaf1_path = path::Path::new("src/tests/certificates/chain/leaf1.cert.der"); // invalid
    let leaf2_path = path::Path::new("src/tests/certificates/chain/leaf2.cert.der"); // valid

    let root_cert = fs::read(root_path)?;
    let intermediate_cert = fs::read(intermediate_path)?;
    let leaf1_cert = fs::read(leaf1_path)?;
    let leaf2_cert = fs::read(leaf2_path)?;

    let clap_config = https_clap_config();
    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(clap_config).await?).await?);
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
    //test
    let request = Validate {
        certificate: None,
        unique_identifier: Some([res_root.unique_identifier.clone()].to_vec()),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    print!("\n\n ####### End first test! #######\n\n");
    let request = Validate {
        certificate: None,
        unique_identifier: Some(
            [
                res_intermediate.unique_identifier.clone(),
                res_root.unique_identifier.clone(),
            ]
            .to_vec(),
        ),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    print!("\n\n ####### End second test! #######\n\n");
    let request = Validate {
        certificate: None,
        unique_identifier: Some(
            [
                res_intermediate.unique_identifier.clone(),
                res_leaf1.unique_identifier.clone(),
                res_root.unique_identifier.clone(),
            ]
            .to_vec(),
        ),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Invalid);
    print!("\n\n ####### End third test! #######\n\n");
    let request = Validate {
        certificate: Some([leaf2_cert.clone()].to_vec()),
        unique_identifier: Some(
            [
                res_intermediate.unique_identifier.clone(),
                res_root.unique_identifier.clone(),
            ]
            .to_vec(),
        ),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Valid);
    print!("\n\n ####### End fourth test! #######\n\n");
    let request = Validate {
        certificate: Some(
            [
                leaf2_cert.clone(),
            ]
            .to_vec(),
        ),
        unique_identifier: Some(
            [
                res_intermediate.unique_identifier.clone(),
                res_root.unique_identifier.clone(),
            ]
            .to_vec(),
        ),
        validity_time: //Some(Asn1Time::days_from_now(3651).unwrap().to_string()), // this is supposed to work but it does not.
        Some("4804152030Z".to_string())
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Invalid); // Test designed to be invalid
    print!("\n\n ####### End fifth test! #######\n\n");
    let request = Validate {
        certificate: Some([leaf2_cert.clone()].to_vec()),
        unique_identifier: Some([res_root.unique_identifier.clone()].to_vec()),
        validity_time: None,
    };
    let res = kms.validate(request, owner, None).await?;
    assert!(res.validity_indicator == ValidityIndicator::Invalid);
    print!("\n\n ####### End sixth test! #######\n\n");

    Result::Ok(())
}

//same tests but certs imported in kms.
