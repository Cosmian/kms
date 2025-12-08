use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    path::PathBuf,
};

use clap::ValueEnum;
use cosmian_kmip::{
    kmip_0::kmip_types::PaddingMethod,
    kmip_2_1::{
        kmip_operations::Sign,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    },
};
use cosmian_kms_client::{
    KmsClient, read_bytes_from_file, reexport::cosmian_kms_client_utils::rsa_utils::HashFn,
    write_bytes_to_file,
};
use serde::Deserialize;
use strum::EnumString;

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

#[derive(ValueEnum, Debug, Clone, Copy, EnumString, Deserialize)]
pub enum CDigitalSignatureAlgorithmRSA {
    RSASSAPSS,
}

#[derive(ValueEnum, Debug, Clone, Copy, EnumString, Deserialize)]
pub enum CDigitalSignatureAlgorithmEC {
    ECDSAWithSHA256,
    ECDSAWithSHA384,
    ECDSAWithSHA512,
}

impl CDigitalSignatureAlgorithmRSA {
    #[must_use]
    pub fn to_cryptographic_parameters(self) -> CryptographicParameters {
        match self {
            Self::RSASSAPSS => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: None,
                ..Default::default()
            },
        }
    }
}

impl Display for CDigitalSignatureAlgorithmRSA {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let s = match self {
            Self::RSASSAPSS => "rsassapss",
        };
        f.write_str(s)
    }
}

impl CDigitalSignatureAlgorithmEC {
    #[must_use]
    pub fn to_cryptographic_parameters(self) -> CryptographicParameters {
        match self {
            Self::ECDSAWithSHA256 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha256.into()),
                ..Default::default()
            },
            Self::ECDSAWithSHA384 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha384.into()),
                ..Default::default()
            },
            Self::ECDSAWithSHA512 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha512.into()),
                ..Default::default()
            },
        }
    }
}

impl Display for CDigitalSignatureAlgorithmEC {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let s = match self {
            Self::ECDSAWithSHA256 => "ecdsa-with-sha256",
            Self::ECDSAWithSHA384 => "ecdsa-with-sha384",
            Self::ECDSAWithSHA512 => "ecdsa-with-sha512",
        };
        f.write_str(s)
    }
}

pub(crate) async fn run_sign(
    kms_rest_client: KmsClient,
    input_file: PathBuf,
    key_id: Option<String>,
    tags: Option<Vec<String>>,
    cp: CryptographicParameters,
    output_file: Option<PathBuf>,
    digested: bool,
) -> KmsCliResult<()> {
    let data = read_bytes_from_file(&input_file)
        .with_context(|| "Cannot read bytes from the input file")?;

    let id = get_key_uid(key_id.as_ref(), tags.as_ref(), KEY_ID)?;

    let sign_request = if digested {
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(id)),
            cryptographic_parameters: Some(cp),
            data: None,
            digested_data: Some(data),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    } else {
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(id)),
            cryptographic_parameters: Some(cp),
            data: Some(data.into()),
            digested_data: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    };

    let response = kms_rest_client
        .sign(sign_request)
        .await
        .with_context(|| "Cannot execute the query on the KMS server")?;

    let signature = response.signature_data.context("The signature is empty")?;

    let output_path = output_file.unwrap_or_else(|| {
        let mut p = input_file.clone();
        p.set_extension("signed");
        p
    });

    write_bytes_to_file(&signature, &output_path)
        .with_context(|| "Cannot write the signature to the output file")?;

    let stdout = format!("Signature written to {}", output_path.display());
    let mut stdout = console::Stdout::new(&stdout);
    stdout.set_tags(tags.as_ref());
    stdout.write()?;

    Ok(())
}
