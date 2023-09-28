use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use clap::Parser;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::tee::forge_report_data;
use openssl::x509::X509;
use rand::Rng;
use ratls::verify::get_server_certificate;
use tee_attestation::verify_quote;
use tokio::task::spawn_blocking;
use url::Url;

use crate::{
    config::TeeConf,
    error::{result::CliResultHelper, CliError},
};

/// Query the enclave to check its trustworthiness
#[derive(Parser, Debug)]
pub struct TeeAction {
    /// The path to store exported files (quote, manifest, certificate, remote attestation, ...)
    #[clap(required = true)]
    export_path: PathBuf,
}

impl TeeAction {
    pub async fn process(
        &self,
        kms_rest_client: &KmsRestClient,
        tee_conf: TeeConf,
    ) -> Result<(), CliError> {
        // Create the export directory if it does not exist
        if !Path::new(&self.export_path).exists() {
            fs::create_dir_all(&self.export_path)?;
        }

        // Generate a nonce to make the quote unique. Use an arbitrary and non predictable string.
        let nonce = rand::thread_rng().gen::<[u8; 32]>();

        // Get the quote from the enclave
        let quote = kms_rest_client
            .get_attestation_report(&b64.encode(nonce))
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        // Save the quote
        let quote_raw_path = self.export_path.join("quote.raw"); // TODO: rename in .bin and write binary quote (note b64)
        fs::write(&quote_raw_path, &quote)?;
        println!("The base64 encoded quote has been saved at {quote_raw_path:?}");

        // Get the server certificate
        let server_url = Url::parse(&kms_rest_client.server_url)
            .map_err(|e| CliError::Default(format!("Can't parse URL: {e}")))?;
        let certificate = get_server_certificate(
            server_url
                .host_str()
                .ok_or_else(|| CliError::Default("Host not found in server url".to_string()))?,
            server_url.port().unwrap_or(443).into(),
        )
        .map_err(|e| CliError::Default(format!("Can't get KMS server certificate: {e}")))?; // TODO: do it when loading the conf
        let certificate = X509::from_der(&certificate)
            .map_err(|e| CliError::Default(format!("Can't convert certificate to DER: {e}")))?
            .to_pem()
            .map_err(|e| CliError::Default(format!("Can't convert certificate to PEM: {e}")))?;

        let report_data = forge_report_data(&nonce, &certificate)?;

        let quote = b64.decode(&quote)?;
        let tee_conf = tee_conf.try_into()?;
        match spawn_blocking(move || verify_quote(&quote, &report_data, tee_conf)).await {
            Ok(_) => println!("Verification succeed"),
            Err(e) => println!("Verification failed: {e:?}"),
        }

        Ok(())
    }
}
