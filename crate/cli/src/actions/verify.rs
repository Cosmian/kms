use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Parser;
use cosmian_kms_utils::tee::forge_report_data;
use der::{Decode, EncodePem};
use rand::Rng;
use ratls::verify::get_server_certificate;
use tee_attestation::{verify_quote, TeeMeasurement};
use tokio::task::spawn_blocking;

use crate::{
    config::{CliConf, TeeConf},
    error::{result::CliResultHelper, CliError},
};

/// Query the KMS to check its trustworthiness. Validate the TLS certificate to use in any further queries.
#[derive(Parser, Debug)]
pub struct TeeAction {
    /// The path to store working files (quote, certificate, ...)
    #[clap(default_value = "/tmp/kms")]
    export_path: PathBuf,
}

impl TeeAction {
    pub async fn process(&self, conf: &CliConf) -> Result<(), CliError> {
        // Create the export directory if it does not exist
        if !Path::new(&self.export_path).exists() {
            fs::create_dir_all(&self.export_path)?;
        }

        let server_url = conf.kms_server_url()?;

        // Get the KMS certificate
        let certificate = get_server_certificate(
            server_url
                .host_str()
                .ok_or_else(|| CliError::Default("Host not found in server url".to_string()))?,
            server_url.port().unwrap_or(443).into(),
        )
        .map_err(|e| CliError::Default(format!("Can't get KMS server certificate: {e}")))?;

        let certificate = x509_cert::Certificate::from_der(&certificate)
            .map_err(|e| {
                CliError::Conversion(format!("Cannot read DER content to X509. Error: {e:?}"))
            })?
            .to_pem(der::pem::LineEnding::LF)?;

        let cert_path = self.export_path.join("cert.pem");
        fs::write(&cert_path, &certificate)?;
        println!("The KMS PEM certificate has been saved at {cert_path:?}");

        // Let's use this certificate when querying the KMS to get the quote
        let mut local_conf = conf.clone();
        let verified_cert = Some(certificate.clone());
        if let Some(mut local_tee_conf) = local_conf.tee_conf {
            local_tee_conf.verified_cert = verified_cert;
            local_conf.tee_conf = Some(local_tee_conf);
        } else {
            local_conf.tee_conf = Some(TeeConf {
                verified_cert,
                ..Default::default()
            });
        }
        let kms_rest_client = local_conf.initialize_kms_client()?;

        // Generate a nonce to make the quote unique. Use an arbitrary and non predictable string.
        let nonce = rand::thread_rng().gen::<[u8; 32]>();

        let nonce_path = self.export_path.join("nonce.bin");
        fs::write(&nonce_path, nonce)?;
        println!("The random nonce has been saved at {nonce_path:?}");

        // Get the quote from the kms
        let quote = kms_rest_client
            .get_attestation_report(&nonce)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        // Save the quote
        let quote_raw_path = self.export_path.join("quote.bin");
        fs::write(&quote_raw_path, &quote)?;
        println!("The raw quote has been saved at {quote_raw_path:?}");

        // Let's verify the quote
        let report_data = forge_report_data(&nonce, certificate.as_bytes())?;

        let tee_conf = if let Some(tee_conf) = conf.tee_conf.clone() {
            tee_conf.try_into()?
        } else {
            TeeMeasurement::default()
        };

        match spawn_blocking(move || verify_quote(&quote, &report_data, tee_conf))
            .await
            .map_err(|e| CliError::Default(format!("Can't verify quote: {e}")))?
        {
            Ok(()) => println!("Verification succeed"),
            Err(e) => return Err(e.into()),
        }

        // Now, the user doesn't need to verify the quote each time it queries the KMS since it forces the certificate to be that one.
        local_conf.save()?;

        println!("You configuration file has been updated to secure the further calls to the KMS");

        Ok(())
    }
}
