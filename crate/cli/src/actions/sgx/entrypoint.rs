use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::StructOpt;
use colored::Colorize;
use cosmian_kms_client::KmsRestClient;
use eyre::Context;
use hex::encode;
use libsgx::{
    quote::{compute_mr_signer, from_bytes, hash, prepare_report_data, Quote},
    remote_attestation::azure::remote_attestation,
};
use rand::Rng;

/// Query the enclave to check its trustworthiness
#[derive(StructOpt, Debug)]
pub struct SgxAction {
    /// The path to store exported files (quote, manifest, certificate, remote attestation, ...)
    #[structopt(required = true, parse(from_os_str))]
    export_path: PathBuf,

    /// The value of the MR_ENCLAVE obtains by running the KMS docker on your local machine
    #[structopt(required = true, long = "mr-enclave")]
    mr_enclave: String,
}

impl SgxAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        // Create the export directory if it does not exist
        if !Path::new(&self.export_path).exists() {
            fs::create_dir_all(&self.export_path)?;
        }

        // Generate a nonce to make the quote unique. Use an arbitrary and non predictable string.
        let nonce = rand::thread_rng().gen::<[u8; 32]>();
        let nonce = hex::encode(nonce);

        // Get the quote from the enclave
        let quote = client_connector
            .get_quote(&nonce)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        // Save the quote
        let quote_raw_path = self.export_path.join("quote.raw");
        fs::write(&quote_raw_path, &quote)?;
        println!("The base64 encoded quote has been saved at {quote_raw_path:?}");

        // Convert the quote from bytes to struct
        let typed_quote = base64::decode(&quote)?;
        let typed_quote: &Quote = unsafe { from_bytes(&typed_quote) };

        // Save the structured quote
        let quote_struct_path = self.export_path.join("quote.struct");
        fs::write(&quote_struct_path, format!("{:#?}", &typed_quote))?;
        println!(
            "The quote (structured) has been saved at {:?}",
            quote_struct_path
        );

        // Get the certificate
        let certificates = client_connector
            .get_certificates()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        // Save the certificates
        if let Some(ssl) = &certificates.ssl {
            let cert_path = self.export_path.join("ssl.cert");
            fs::write(&cert_path, ssl)?;
            println!("The ssl certificate has been saved at {:?}", cert_path);
        }

        if let Some(enclave) = &certificates.enclave {
            let cert_path = self.export_path.join("enclave.pub");
            fs::write(&cert_path, enclave)?;
            println!("The enclave certificate has been saved at {:?}", cert_path);
        }

        // Get the manifest
        let manifest = client_connector
            .get_manifest()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        // Save the manifest
        let manifest_path = self.export_path.join("manifest.sgx");
        fs::write(&manifest_path, &manifest)?;
        println!("The sgx manifest has been saved at {:?}", manifest_path);

        // Proceed the remote attestation
        let user_report_data = prepare_report_data(certificates.ssl, nonce);

        let remote_attestation = remote_attestation(&quote, Some(&user_report_data)).await?;

        // Save the remote attestation
        let remote_attestation_path = self.export_path.join("remote_attestation");
        fs::write(
            &remote_attestation_path,
            format!("{:#?}", remote_attestation),
        )?;
        println!(
            "The remote attestation has been saved at {:?}",
            remote_attestation_path
        );

        println!("\nYou can check all these files manually.");

        println!("\nProceed some automatic checks:");
        println!("... Remote attestation checking {}", bool_to_color(true)); // It will raise before if it's not ok

        println!(
            "... MR enclave checking {}",
            bool_to_color(
                self.mr_enclave == remote_attestation.sgx_mrenclave
                    && encode(typed_quote.report_body.mr_enclave)
                        == remote_attestation.sgx_mrenclave
                    && encode(typed_quote.report_body.mr_enclave)
                        == remote_attestation.x_ms_sgx_mrenclave
            ),
        );

        println!(
            "... MR signer checking {} ",
            bool_to_color(
                compute_mr_signer(&certificates.enclave.ok_or_else(|| {
                    eyre::eyre!(
                        "The server didn't return the enclave public certificate".to_string()
                    )
                })?)?
                    == typed_quote.report_body.mr_signer
                    && encode(typed_quote.report_body.mr_signer) == remote_attestation.sgx_mrsigner
                    && encode(typed_quote.report_body.mr_signer)
                        == remote_attestation.x_ms_sgx_mrsigner
            ),
        );

        println!(
            "... Quote checking {} ",
            bool_to_color(
                encode(hash(&base64::decode(&quote)?))
                    == remote_attestation.maa_attestationcollateral.quotehash
            )
        );

        let now = SystemTime::now();
        println!(
            "... Date checking {} ",
            bool_to_color(
                now.duration_since(UNIX_EPOCH + Duration::from_secs(remote_attestation.iat))
                    .is_ok()
                    && (UNIX_EPOCH + Duration::from_secs(remote_attestation.exp))
                        .duration_since(now)
                        .is_ok()
            )
        );

        let report_data = base64_url::encode(&user_report_data);

        println!(
            "... Quote report data (manifest, kms certificates and nonce) checking {} ",
            bool_to_color(
                report_data == remote_attestation.maa_ehd
                    && report_data == remote_attestation.aas_ehd
                    && report_data == remote_attestation.x_ms_sgx_ehd
            )
        );

        Ok(())
    }
}

/// Print `Ok` in green and `Ko` in red based on the evaluation of a condition
fn bool_to_color(cond: bool) -> String {
    if cond {
        "Ok".green().to_string()
    } else {
        "Ko".red().to_string()
    }
}
