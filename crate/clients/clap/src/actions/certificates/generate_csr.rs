use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::{Deserialize, Serialize};

use crate::{
    actions::console,
    error::{KmsCliError, result::KmsCliResult},
};

#[derive(Serialize)]
struct CsrRequest<'a> {
    private_key_id: &'a str,
    subject_name: &'a str,
}

#[derive(Serialize, Deserialize)]
struct CsrResponse {
    csr_pem: String,
}

/// Generate a PKCS#10 certificate signing request (CSR) for a private key held by the KMS.
///
/// The CSR is signed on the server with the private key, which never leaves the KMS:
/// an HSM key can be non-extractable. Typical use: create a key pair on an online KMS
/// (`ckms rsa keys create --sensitive`), generate the CSR, have an offline root CA sign it
/// (`ckms certificates certify --certificate-signing-request ...`), then import the certificate.
///
/// The caller needs the `Sign` permission on the private key.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GenerateCsrAction {
    /// The unique identifier of the private key that signs the CSR.
    #[clap(long = "private-key-id", short = 'k', required = true)]
    pub(crate) private_key_id: String,

    /// The subject distinguished name, e.g. "C=FR, O=Acme, CN=Acme Sub CA".
    /// Escape a comma inside a value with a backslash.
    #[clap(long = "subject-name", short = 's', required = true)]
    pub(crate) subject_name: String,

    /// The output file for the PEM-encoded CSR.
    #[clap(long = "output-file", short = 'o', required = true)]
    pub(crate) output_file: PathBuf,
}

impl GenerateCsrAction {
    /// Generate the CSR by calling the REST endpoint.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let response: CsrResponse = kms_rest_client
            .post_no_ttlv(
                "/certificates/csr",
                Some(&CsrRequest {
                    private_key_id: &self.private_key_id,
                    subject_name: &self.subject_name,
                }),
            )
            .await?;
        if !response
            .csr_pem
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        {
            return Err(KmsCliError::Default(
                "the server did not return a PEM-encoded CSR".to_owned(),
            ));
        }
        std::fs::write(&self.output_file, response.csr_pem.as_bytes())?;
        console::Stdout::new(&format!(
            "CSR successfully generated and saved to {}",
            self.output_file.display()
        ))
        .write()?;
        Ok(())
    }
}
