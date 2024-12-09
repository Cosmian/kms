use std::collections::HashMap;

use cosmian_kms_client::{
    kmip::kmip_types::{Attribute, UniqueIdentifier},
    reexport::cosmian_kms_access::access::{
        AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse,
    },
};
use serde::Serialize;
use serde_json::Value;

use crate::error::result::CliResult;

pub const KMS_CLI_FORMAT: &str = "KMS_CLI_FORMAT";
pub const CLI_DEFAULT_FORMAT: &str = "text";
pub const CLI_JSON_FORMAT: &str = "json";

#[derive(Serialize, Debug, Default)]
pub struct Stdout {
    stdout: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    unique_identifier: Option<String>,
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
            stdout: stdout.to_string(),
            ..Default::default()
        }
    }

    pub fn set_tags(&mut self, tags: Option<&Vec<String>>) {
        self.tags = tags.cloned();
    }

    pub fn set_unique_identifier<T: Into<String>>(&mut self, unique_identifier: T) {
        self.unique_identifier = Some(unique_identifier.into());
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

    pub fn set_accesses(&mut self, accesses: Vec<UserAccessResponse>) {
        self.accesses = Some(accesses);
    }

    pub fn set_access_rights_obtained(
        &mut self,
        access_rights_obtained: Vec<AccessRightsObtainedResponse>,
    ) {
        self.access_rights_obtained = Some(access_rights_obtained);
    }

    pub fn set_object_owned(&mut self, object_owned: Vec<ObjectOwnedResponse>) {
        self.object_owned = Some(object_owned);
    }

    /// Writes the output to the console.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue with writing to the console.
    #[allow(clippy::print_stdout)]
    pub fn write(&self) -> CliResult<()> {
        // Check if the output format should be JSON
        let json_format_from_env = std::env::var(KMS_CLI_FORMAT)
            .unwrap_or_else(|_| CLI_DEFAULT_FORMAT.to_string())
            .to_lowercase()
            == CLI_JSON_FORMAT;

        if json_format_from_env {
            // Serialize the output as JSON and print it
            let console_stdout = serde_json::to_string_pretty(&self)?;
            println!("{console_stdout}");
        } else {
            // Print the output in text format
            if !self.stdout.is_empty() {
                println!("{}", self.stdout);
            }

            // Print the unique identifier if present
            if let Some(id) = &self.unique_identifier {
                println!("\t  Unique identifier: {id}");
            }

            // Print the list of unique identifiers if present
            if let Some(ids) = &self.unique_identifiers {
                for id in ids {
                    println!("{id}");
                }
            }

            // Print the public key unique identifier if present
            if let Some(id) = &self.public_key_unique_identifier {
                println!("\t  Public key unique identifier: {id}");
            }

            // Print the private key unique identifier if present
            if let Some(id) = &self.private_key_unique_identifier {
                println!("\t  Private key unique identifier: {id}");
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
                    println!("\n  Tags:");
                    for tag in t {
                        println!("    - {tag}");
                    }
                }
            }
        }

        Ok(())
    }
}
