use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyValue},
    kmip_objects::Object,
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
};
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::shared::utils::{import_object, read_key_from_file},
    error::CliError,
};

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum KeyFormat {
    JsonTtlv,
    Pkcs8Pem,
    Pkcs8Der,
    Pkcs1Pem,
    Pkcs1Der,
    Sec1Pem,
    Sec1Der,
    RawBytes,
}

/// Import a key in the KMS.
///
/// The key must be in KMIP JSON TTLV format.
/// When no key unique id is specified, a random UUID v4 is generated.
///
/// The key can be wrapped when imported. Wrapping using:
///  - a password or a supplied key in base64 is done locally
///  - a symmetric key id is performed server-side
///
/// A password is first converted to a 256-bit key using Argon 2.
/// Wrapping is performed according to RFC 5649.
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportKeyAction {
    /// The KMIP JSON TTLV key file
    #[clap(required = true)]
    key_file: PathBuf,

    /// The unique id of the key; a random UUID v4 is generated if not specified
    #[clap(required = false)]
    key_id: Option<String>,

    /// Unwrap the object if it is wrapped before storing it
    #[clap(
        long = "unwrap",
        short = 'u',
        required = false,
        default_value = "false"
    )]
    unwrap: bool,

    /// Replace an existing key under the same id
    #[clap(
        required = false,
        long = "replace",
        short = 'r',
        default_value = "false"
    )]
    replace_existing: bool,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl ImportKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // read the key file
        let object = read_key_from_file(&self.key_file)?;
        let object_type = object.object_type();

        // import the key
        let unique_identifier = import_object(
            kms_rest_client,
            self.key_id.clone(),
            object,
            None,
            self.unwrap,
            self.replace_existing,
            &self.tags,
        )
        .await?;

        // print the response
        println!(
            "The key of type {:?} in file {:?} was imported with id: {}",
            &self.key_file, object_type, unique_identifier,
        );
        if !self.tags.is_empty() {
            println!("Tags:");
            for tag in &self.tags {
                println!("    - {tag}");
            }
        }

        Ok(())
    }
}

// pub fn parse_encoded_key(key_bytes: &[u8], format: KeyFormat) -> Result<Vec<Object>, CliError> {
//     match format {
//         KeyFormat::JsonTtlv => {
//             // Read the object from the bytes
//             let ttlv = serde_json::from_slice::<TTLV>(&key_bytes)
//                 .with_context(|| "failed parsing the object from the json file")?;
//             // Deserialize the object
//             let object: Object = from_ttlv(&ttlv)?;
//             Ok(vec![object])
//         }
//         KeyFormat::Pkcs8Pem => {
//             let spki = pkcs8::PrivateKeyInfo::from_pem(key_bytes)
//                 .with_context(|| "failed parsing the object from the pkcs8 pem file")?;

//             match spki.algorithm.oid.to_string().as_str() {
//                 "id-rsaEncryption" => {
//                     let mut attributes = None;
//                     let rsa_private_key = rsa::RsaPrivateKey::from_pkcs8_pem(
//                         String::from_utf8(key_bytes.to_vec())?.as_str(),
//                     )?;
//                     rsa_private_key.n();
//                     let key_value = KeyValue {
//                         key_material: KeyMaterial::TransparentRSAPrivateKey {
//                             modulus: rsa_private_key.n().to_owned().into(),
//                             private_exponent: Some(rsa_private_key.e().to_owned()),
//                             public_exponent: (),
//                             p: (),
//                             q: (),
//                             prime_exponent_p: (),
//                             prime_exponent_q: (),
//                             crt_coefficient: (),
//                         },
//                         attributes,
//                     };
//                     let private_object = create_private_key(
//                         spki.to_der()?.as_slice(),
//                         KeyFormatType::PKCS8,
//                         CryptographicAlgorithm::RSA,
//                         -1,
//                         None,
//                     )?;
//                     // if let Some(public_key) = spki.public_key {
//                     //     let public_object = create_public_key(
//                     //         public_key.to_der()?.as_slice(),
//                     //         KeyFormatType::PKCS8,
//                     //         CryptographicAlgorithm::RSA,
//                     //         -1,
//                     //         None,
//                     //     )?;
//                     // }
//                 }
//                 "id-ecPublicKey" => {
//                     todo!()
//                 }
//                 _ => return Err(CliError::Default("unsupported algorithm".to_owned())),
//             }
//         }
//         KeyFormat::Pkcs8Der => todo!(),
//         KeyFormat::Pkcs1Pem => todo!(),
//         KeyFormat::Pkcs1Der => todo!(),
//         KeyFormat::Sec1Pem => todo!(),
//         KeyFormat::Sec1Der => todo!(),
//         KeyFormat::RawBytes => {
//             //let key = create_symmetric_key(key_bytes, CryptographicAlgorithm::Aes)?;
//             todo!()
//         }
//     }
// }

fn create_private_key(
    bytes: &[u8],
    key_format_type: KeyFormatType,
    key_value: KeyValue,
    cryptographic_algorithm: CryptographicAlgorithm,
    cryptographic_length: i32,
    attributes: Option<Attributes>,
) -> Result<Object, CliError> {
    Ok(Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value,
            cryptographic_algorithm,
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}

fn create_public_key(
    bytes: &[u8],
    key_format_type: KeyFormatType,
    key_value: KeyValue,
    cryptographic_algorithm: CryptographicAlgorithm,
    cryptographic_length: i32,
    attributes: Option<Attributes>,
) -> Result<Object, CliError> {
    Ok(Object::PublicKey {
        key_block: KeyBlock {
            key_format_type,
            key_compression_type: None,
            key_value,
            cryptographic_algorithm,
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}
