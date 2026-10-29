use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    KmsClient, reexport::cosmian_kms_client_utils::certificate_utils::Algorithm,
};
use serde::{Deserialize, Serialize};

use crate::{
    actions::console,
    error::{KmsCliError, result::KmsCliResult},
};

#[derive(Serialize)]
struct CsrRequest<'a> {
    private_key_id: Option<&'a str>,
    subject_name: &'a str,
    algorithm: Option<String>,
    sensitive: bool,
}

#[derive(Serialize, Deserialize)]
struct CsrResponse {
    csr_pem: String,
    private_key_id: String,
    public_key_id: Option<String>,
}

/// Generate a PKCS#10 certificate signing request (CSR) for a private key held by the KMS.
///
/// The CSR is signed on the server with the private key, which never leaves the KMS:
/// an HSM key can be non-extractable. Typical use: create a key pair on an online KMS
/// (`ckms rsa keys create --sensitive`), generate the CSR, have an offline root CA sign it
/// (`ckms certificates certify --certificate-signing-request ...`), then import the certificate.
///
/// The caller needs the `Sign` permission on the private key.
///
/// With `--algorithm`, the key pair is generated first (same algorithms as `certificates certify
/// --generate-key-pair`; key encapsulation algorithms cannot sign). Give `--private-key-id
/// hsm::<slot>::<id> --sensitive` to generate it in the HSM, non-extractable.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GenerateCsrAction {
    /// The unique identifier of the private key that signs the CSR. With `--algorithm`, the
    /// identifier of the key pair to generate (`hsm::<slot>::<id>` generates it in the HSM);
    /// a random one is used when omitted.
    #[clap(
        long = "private-key-id",
        short = 'k',
        required_unless_present = "algorithm"
    )]
    pub(crate) private_key_id: Option<String>,

    /// Generate the key pair with this algorithm before signing the CSR with its private key.
    #[clap(long = "algorithm", short = 'a')]
    pub(crate) algorithm: Option<Algorithm>,

    /// Make the generated private key non-extractable (required for an HSM key).
    #[clap(long = "sensitive", requires = "algorithm", default_value = "false")]
    pub(crate) sensitive: bool,

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
                    private_key_id: self.private_key_id.as_deref(),
                    subject_name: &self.subject_name,
                    algorithm: self.algorithm.map(|a| {
                        a.to_possible_value()
                            .map_or_else(String::new, |v| v.get_name().to_owned())
                    }),
                    sensitive: self.sensitive,
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
        let saved = format!(
            "CSR successfully generated and saved to {}",
            self.output_file.display()
        );
        let message = match &response.public_key_id {
            Some(public_key_id) => format!(
                "{saved}\nKey pair generated. Private key id: {}\nPublic key id: {public_key_id}",
                response.private_key_id
            ),
            None => saved,
        };
        console::Stdout::new(&message).write()?;
        Ok(())
    }
}
