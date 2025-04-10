use std::ffi::OsString;

use clap::{
    Parser,
    error::{ContextKind, ContextValue, ErrorKind},
};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::{CryptographicAlgorithm, KeyFormatType},
    kmip_2_1::kmip_objects::ObjectType,
    reexport::cosmian_kms_client_utils::locate_utils::build_locate_request,
};
use strum::IntoEnumIterator;

use crate::{actions::console, error::result::CosmianResult};

/// Locate cryptographic objects inside the KMS
///
/// This command will return one id per line.
/// There will be no output if no object is found.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LocateObjectsAction {
    /// User tags or system tags to locate the object.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", verbatim_doc_comment)]
    tags: Option<Vec<String>>,

    /// Cryptographic algorithm (case insensitive)
    ///
    /// The list of algorithms is the one specified by KMIP 2.1 in addition to "Covercrypt".
    /// Possible values include "Covercrypt", "ECDH", "`ChaCha20Poly1305`", "AES", "Ed25519"
    ///
    /// Running the locate sub-command with a wrong value will list all the possible values.
    /// e.g. `cosmian kms locate --algorithm WRONG`
    #[clap(
        long = "algorithm",
        short = 'a',
        value_parser = CryptographicAlgorithmParser,
        verbatim_doc_comment
    )]
    cryptographic_algorithm: Option<CryptographicAlgorithm>,

    /// Cryptographic length (e.g. key size) in bits
    #[clap(long = "cryptographic-length", short = 'l')]
    cryptographic_length: Option<i32>,

    /// Key format type (case insensitive)
    ///
    /// The list is the one specified by KMIP 2.1
    /// in addition to the two Covercrypt formats: "`CoverCryptSecretKey`" and "`CoverCryptPublicKey`"
    /// Possible values also include: "RAW" and "PKCS8"
    /// Note: asymmetric keys are always stored in the "PKCS8" format; symmetric keys are always stored in the "Raw" format.
    ///
    /// Running the locate sub-command with a wrong value will list all the possible values.
    /// e.g. `cosmian kms locate --key-format-type WRONG`
    #[clap(long = "key-format-type", short = 'f',
        value_parser = KeyFormatTypeParser,verbatim_doc_comment)]
    key_format_type: Option<KeyFormatType>,

    /// Object type (case insensitive)
    ///
    /// The list is the one specified by KMIP 2.1
    /// Possible values are:
    /// * Certificate
    /// * `SymmetricKey`
    /// * `PublicKey`
    /// * `PrivateKey`
    /// * `SplitKey`
    /// * `SecretData`
    /// * `OpaqueObject`
    /// * `PGPKey`
    /// * `CertificateRequest`
    #[clap(long, short = 'o',
        value_parser = ObjectTypeParser,verbatim_doc_comment)]
    object_type: Option<ObjectType>,

    /// Locate an object which has a link to this public key id.
    #[clap(long, short = 'p')]
    public_key_id: Option<String>,

    /// Locate an object which has a link to this private key id.
    #[clap(long, short = 'k')]
    private_key_id: Option<String>,

    /// Locate an object which has a link to this certificate key id.
    #[clap(long = "certificate-id", short = 'c')]
    certificate_id: Option<String>,
}

impl LocateObjectsAction {
    /// Export a key from the KMS
    ///
    /// # Errors
    ///
    /// Returns an error if there is a problem communicating with the KMS or if the requested key cannot be located.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        let request = build_locate_request(
            self.tags.clone(),
            self.cryptographic_algorithm,
            self.cryptographic_length,
            self.key_format_type,
            self.object_type,
            self.public_key_id.as_deref(),
            self.private_key_id.as_deref(),
            self.certificate_id.as_deref(),
        )?;

        let response = kms_rest_client.locate(request).await?;
        if let Some(ids) = response.unique_identifiers {
            if ids.is_empty() {
                console::Stdout::new("No object found.").write()?;
            } else {
                let mut stdout = console::Stdout::new("List of unique identifiers:");
                stdout.set_unique_identifiers(&ids);
                stdout.write()?;
            }
        } else {
            console::Stdout::new("No object found.").write()?;
        }

        Ok(())
    }
}

/// Parse a string entered by the user into a `CryptographicAlgorithm`
#[derive(Clone)]
struct CryptographicAlgorithmParser;

impl clap::builder::TypedValueParser for CryptographicAlgorithmParser {
    type Value = CryptographicAlgorithm;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        CryptographicAlgorithm::iter()
            .find(|algo| {
                OsString::from(algo.to_string().to_lowercase()) == value.to_ascii_lowercase()
            })
            .ok_or_else(|| {
                let mut err = clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        ContextKind::InvalidArg,
                        ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    ContextKind::InvalidValue,
                    ContextValue::String(value.to_string_lossy().to_string()),
                );
                err.insert(
                    ContextKind::SuggestedValue,
                    ContextValue::Strings(
                        CryptographicAlgorithm::iter()
                            .map(|algo| algo.to_string())
                            .collect::<Vec<String>>(),
                    ),
                );
                err
            })
    }
}

/// Parse a string entered by the user into a `KeyFormatType`
#[derive(Clone)]
struct KeyFormatTypeParser;

impl clap::builder::TypedValueParser for KeyFormatTypeParser {
    type Value = KeyFormatType;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        KeyFormatType::iter()
            .find(|algo| {
                OsString::from(algo.to_string().to_lowercase()) == value.to_ascii_lowercase()
            })
            .ok_or_else(|| {
                let mut err = clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        ContextKind::InvalidArg,
                        ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    ContextKind::InvalidValue,
                    ContextValue::String(value.to_string_lossy().to_string()),
                );
                err.insert(
                    ContextKind::SuggestedValue,
                    ContextValue::Strings(
                        KeyFormatType::iter()
                            .map(|algo| algo.to_string())
                            .collect::<Vec<String>>(),
                    ),
                );
                err
            })
    }
}

/// Parse a string entered by the user into a `ObjectType`
#[derive(Clone)]
struct ObjectTypeParser;

impl clap::builder::TypedValueParser for ObjectTypeParser {
    type Value = ObjectType;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        ObjectType::iter()
            .find(|object_type| {
                OsString::from(object_type.to_string().to_lowercase()) == value.to_ascii_lowercase()
            })
            .ok_or_else(|| {
                let mut err = clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        ContextKind::InvalidArg,
                        ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    ContextKind::InvalidValue,
                    ContextValue::String(value.to_string_lossy().to_string()),
                );
                err.insert(
                    ContextKind::SuggestedValue,
                    ContextValue::Strings(
                        ObjectType::iter()
                            .map(|object_type| object_type.to_string())
                            .collect::<Vec<String>>(),
                    ),
                );
                err
            })
    }
}
