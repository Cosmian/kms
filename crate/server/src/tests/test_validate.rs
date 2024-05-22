use std::{fs, path, sync::Arc};

use cosmian_kmip::kmip::{kmip_operations::Validate, kmip_types::ValidityIndicator};

use crate::{
    config::ServerParams, error::KmsError, tests::test_utils::https_clap_config, KMSServer,
};

// Passing certificates test. No CRL in the certiicates.
#[tokio::test]
pub async fn test() -> Result<(), KmsError> {
    let root_path = path::Path::new("src/tests/certificates/chain/ca.cert.pem");
    let intermediate_path = path::Path::new("src/tests/certificates/chain/intermediate.cert.pem");
    let leaf1_path = path::Path::new("src/tests/certificates/chain/leaf1.cert.pem"); // invalid
    let leaf2_path = path::Path::new("src/tests/certificates/chain/leaf2.cert.pem"); // valid
    let root_cert = fs::read(root_path)?;
    let intermediate_cert = fs::read(intermediate_path)?;
    let leaf1_cert = fs::read(leaf1_path)?;
    let leaf2_cert = fs::read(leaf2_path)?;
    let root_string = String::from_utf8(root_cert.clone()).unwrap();
    let intermediate_string = String::from_utf8(intermediate_cert.clone()).unwrap();
    let leaf1_string = String::from_utf8(leaf1_cert.clone()).unwrap();
    let leaf2_string = String::from_utf8(leaf2_cert.clone()).unwrap();
    println!(
        "Root \n{}\n Intermediate \n {} \n Invalid leaf \n {} \n Valid leaf \n {}",
        root_string, intermediate_string, leaf1_string, leaf2_string
    );

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

    Result::Ok(())
}

// Passing certificates test. CRL in the certiicates.
// CRL has uri http.
// CRL has local uri

// Passing uids test. No CRL in the certiicates.

// Passing uiids test. CRL in the certiicates.
// CRL has uri http.
// CRL has local uri
