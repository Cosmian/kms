use std::path::PathBuf;

use cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::CertificateInputFormat;
use test_kms_server::TestsContext;
use uuid::Uuid;

use crate::{
    actions::certificates::import_certificate::ImportCertificateAction, error::result::KmsCliResult,
};

pub(crate) async fn import_root_and_intermediate(
    ctx: &TestsContext,
) -> KmsCliResult<(String, String, String)> {
    // import Root CA
    let root_ca_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from("../../../test_data/certificates/csr/ca.crt")),
            input_format: CertificateInputFormat::Pem,
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?
    .unwrap();

    // import Intermediate CA
    let intermediate_ca_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../../test_data/certificates/csr/intermediate.crt",
            )),
            input_format: CertificateInputFormat::Pem,
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            tags: vec!["root_ca".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?
    .unwrap();

    // import Intermediate p12
    let intermediate_ca_private_key_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../../test_data/certificates/csr/intermediate.p12",
            )),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            tags: vec!["intermediate_ca".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?
    .unwrap();

    Ok((
        root_ca_id,
        intermediate_ca_id,
        intermediate_ca_private_key_id,
    ))
}
