use std::collections::HashMap;

use cosmian_kms_client::{
    kmip_2_1::{kmip_attributes::Attribute, kmip_types::UniqueIdentifier},
    reexport::cosmian_kms_access::access::{
        AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse,
    },
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    cli_bail,
    error::{KmsCliError, result::KmsCliResult},
};

pub const COSMIAN_KMS_CLI_FORMAT: &str = "COSMIAN_KMS_CLI_FORMAT";

#[derive(Debug)]
pub enum OutputFormat {
    Text,
    Json,
    Quiet,
}

impl TryFrom<&str> for OutputFormat {
    type Error = KmsCliError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            "quiet" => Ok(Self::Quiet),
            _ => {
                cli_bail!(
                    "Invalid output format: {value}. Supported values are: json, text, quiet"
                );
            }
        }
    }
}

#[derive(Serialize, Default)]
pub struct Stdout {
    str_out: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    unique_identifier: Option<UniqueIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unique_identifiers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_unique_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key_unique_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attribute: Option<Attribute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accesses: Option<Vec<UserAccessResponse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_rights_obtained: Option<Vec<AccessRightsObtainedResponse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_owned: Option<Vec<ObjectOwnedResponse>>,
}

impl Stdout {
    #[must_use]
    pub fn new(stdout: &str) -> Self {
        Self {
            str_out: stdout.to_owned(),
            ..Default::default()
        }
    }

    pub fn set_tags(&mut self, tags: Option<&Vec<String>>) {
        self.tags = tags.cloned();
    }

    pub fn set_unique_identifier(&mut self, unique_identifier: &UniqueIdentifier) {
        self.unique_identifier = Some(unique_identifier.to_owned());
    }

    pub fn set_unique_identifiers(&mut self, unique_identifiers: &[UniqueIdentifier]) {
        self.unique_identifiers = Some(
            unique_identifiers
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        );
    }

    pub fn set_key_pair_unique_identifier<T: Into<String>>(
        &mut self,
        private_key_unique_identifier: T,
        public_key_unique_identifier: T,
    ) {
        self.private_key_unique_identifier = Some(private_key_unique_identifier.into());
        self.public_key_unique_identifier = Some(public_key_unique_identifier.into());
    }

    pub fn set_attribute(&mut self, attribute: Attribute) {
        self.attribute = Some(attribute);
    }

    pub fn set_attributes(&mut self, attributes: HashMap<String, Value>) {
        self.attributes = Some(attributes);
    }

    pub fn set_accesses(&mut self, accesses: &[UserAccessResponse]) {
        self.accesses = Some(accesses.to_vec());
    }

    pub fn set_access_rights_obtained(
        &mut self,
        access_rights_obtained: &[AccessRightsObtainedResponse],
    ) {
        self.access_rights_obtained = Some(access_rights_obtained.to_vec());
    }

    pub fn set_object_owned(&mut self, object_owned: &[ObjectOwnedResponse]) {
        self.object_owned = Some(object_owned.to_vec());
    }

    /// Writes the output to the console.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue with writing to the console.
    #[expect(clippy::print_stdout)]
    pub fn write(&self) -> KmsCliResult<()> {
        // Check if the output format should be JSON
        let output_format = match std::env::var(COSMIAN_KMS_CLI_FORMAT) {
            Ok(output_format_var_env) => OutputFormat::try_from(output_format_var_env.as_ref())?,
            Err(_) => OutputFormat::Text,
        };

        match output_format {
            OutputFormat::Text => {
                // Print the output in text format
                if !self.str_out.is_empty() {
                    println!("{}", self.str_out);
                }

                // Print the unique identifier if present
                if let Some(id) = &self.unique_identifier {
                    println!("\tUnique identifier: {id}");
                }

                // Print the list of unique identifiers if present
                if let Some(ids) = &self.unique_identifiers {
                    for id in ids {
                        println!("{id}");
                    }
                }

                // Print the public key unique identifier if present
                if let Some(id) = &self.public_key_unique_identifier {
                    println!("\tPublic key unique identifier: {id}");
                }

                // Print the private key unique identifier if present
                if let Some(id) = &self.private_key_unique_identifier {
                    println!("\tPrivate key unique identifier: {id}");
                }

                // Print the attribute if present: attribute is a single element
                if let Some(attribute) = &self.attribute {
                    let json = serde_json::to_string_pretty(attribute)?;
                    println!("{json}");
                }

                // Print the attributes if present: attributes are a hashmap of key-value pairs
                if let Some(attributes) = &self.attributes {
                    let json = serde_json::to_string_pretty(attributes)?;
                    println!("{json}");
                }

                // Print the list of accesses if present
                if let Some(accesses) = &self.accesses {
                    for access in accesses {
                        println!(" - {}: {:?}", access.user_id, access.operations);
                    }
                }

                // Print the list of access rights obtained if present
                if let Some(access_rights_obtained) = &self.access_rights_obtained {
                    for access in access_rights_obtained {
                        println!("{access}");
                    }
                }

                // Print the list of objects owned if present
                if let Some(object_owned) = &self.object_owned {
                    for obj in object_owned {
                        println!("{obj}");
                    }
                }

                // Print the list of tags if present
                if let Some(t) = &self.tags {
                    if !t.is_empty() {
                        println!("\tTags:");
                        for tag in t {
                            println!("\t\t- {tag}");
                        }
                    }
                }
                println!(); // consecutive calls feel cluttered and become hard to read
            }
            OutputFormat::Json => {
                // Serialize the output as JSON and print it
                let console_stdout = serde_json::to_string_pretty(&self)?;
                println!("{console_stdout}");
            }
            OutputFormat::Quiet => {
                // Print nothing
            }
        }
        Ok(())
    }
}
