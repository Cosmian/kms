use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::{Object, OpaqueObject},
    kmip_types::{OpaqueDataType, UniqueIdentifier},
    requests::import_object_request,
};
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::console,
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Create (register) an `OpaqueObject` by importing raw bytes.
///
/// The data can be provided inline with --data or via --file. If both are provided, --data wins.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct CreateOpaqueObjectAction {
    /// Optional file containing the opaque bytes to import.
    #[clap(long = "file", short = 'f')]
    pub file: Option<PathBuf>,

    /// Inline opaque data as a UTF-8 string. If provided, it's used instead of --file bytes.
    #[clap(long = "data", short = 'd')]
    pub data: Option<String>,

    /// Opaque data type (defaults to Vendor)
    #[clap(long = "type", default_value = "vendor")]
    pub opaque_type: OpaqueTypeArg,

    /// Optional object unique identifier to assign; otherwise server generates one
    #[clap(long = "id")]
    pub id: Option<String>,

    /// Tags to associate with the object. Repeat to add multiple tags
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub enum OpaqueTypeArg {
    Unknown,
    #[default]
    Vendor,
}

impl std::str::FromStr for OpaqueTypeArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "unknown" => Ok(Self::Unknown),
            "vendor" => Ok(Self::Vendor),
            other => Err(format!(
                "Invalid opaque type '{other}'. Use one of: unknown, vendor"
            )),
        }
    }
}

impl From<OpaqueTypeArg> for OpaqueDataType {
    fn from(value: OpaqueTypeArg) -> Self {
        match value {
            OpaqueTypeArg::Unknown => Self::Unknown,
            OpaqueTypeArg::Vendor => Self::Vendor,
        }
    }
}

impl CreateOpaqueObjectAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let bytes = if let Some(s) = &self.data {
            s.as_bytes().to_vec()
        } else if let Some(path) = &self.file {
            cosmian_kms_client::read_bytes_from_file(path)?
        } else {
            cli_bail!(
                "No data provided. Use --data or --file to specify the opaque object content."
            )
        };

        let object = Object::OpaqueObject(OpaqueObject {
            opaque_data_type: OpaqueDataType::from(self.opaque_type.clone()),
            opaque_data_value: bytes,
        });

        let req = import_object_request(self.id.clone(), object, None, false, false, &self.tags)?;
        let uid = kms_rest_client
            .import(req)
            .await
            .with_context(|| "failed importing the opaque object")?
            .unique_identifier;

        let mut stdout = console::Stdout::new("The opaque object was successfully imported.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&uid);
        stdout.write()?;

        Ok(uid)
    }
}
