use std::collections::HashMap;

use cosmian_kms_client::{
    access::{AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse},
    kmip::kmip_types::UniqueIdentifier,
};
use serde::Serialize;
use serde_json::Value;

use crate::error::CliError;

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
    attributes: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accesses: Option<Vec<UserAccessResponse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_rights_obtained: Option<Vec<AccessRightsObtainedResponse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_owned: Option<Vec<ObjectOwnedResponse>>,
}

impl Stdout {
    //TODO: take ownership of args
    #[must_use]
    pub fn new(stdout: &str, tags: Option<&Vec<String>>) -> Stdout {
        Stdout {
            stdout: stdout.to_string(),
            tags: tags.cloned(),
            ..Default::default()
        }
    }

    pub fn set_unique_identifier<T: Into<String>>(&mut self, unique_identifier: T) {
        self.unique_identifier = Some(unique_identifier.into());
    }

    pub fn set_unique_identifiers(&mut self, unique_identifiers: Vec<UniqueIdentifier>) {
        self.unique_identifiers = Some(
            unique_identifiers
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        );
    }

    pub fn set_private_key_unique_identifier(&mut self, private_key_unique_identifier: &str) {
        self.private_key_unique_identifier = Some(private_key_unique_identifier.to_string());
    }

    pub fn set_public_key_unique_identifier(&mut self, public_key_unique_identifier: &str) {
        self.public_key_unique_identifier = Some(public_key_unique_identifier.to_string());
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

    pub fn write(&self) -> Result<(), CliError> {
        let json_format_from_env = std::env::var(KMS_CLI_FORMAT)
            .unwrap_or(CLI_DEFAULT_FORMAT.to_string())
            .to_lowercase()
            == CLI_JSON_FORMAT;

        if json_format_from_env {
            let console_stdout = serde_json::to_string_pretty(&self)?;
            println!("{console_stdout}");
        } else {
            if !self.stdout.is_empty() {
                println!("{}", self.stdout);
            }

            if let Some(id) = &self.unique_identifier {
                println!("\t  Unique identifier: {id}");
            }
            if let Some(ids) = &self.unique_identifiers {
                for id in ids {
                    // TODO: fix this
                    // println!("\t  Unique identifier: {id}");
                    println!("{id}");
                }
            }
            if let Some(id) = &self.public_key_unique_identifier {
                println!("\t  Public key unique identifier: {id}");
            }
            if let Some(id) = &self.private_key_unique_identifier {
                println!("\t  Private key unique identifier: {id}");
            }
            if let Some(attributes) = &self.attributes {
                let json = serde_json::to_string_pretty(attributes)?;
                println!("{json}");
            }
            if let Some(accesses) = &self.accesses {
                for access in accesses {
                    println!(" - {}: {:?}", access.user_id, access.operations);
                }
            }
            if let Some(access_rights_obtained) = &self.access_rights_obtained {
                for access in access_rights_obtained {
                    println!("{access}");
                }
            }
            if let Some(object_owned) = &self.object_owned {
                for obj in object_owned {
                    println!("{obj}");
                }
            }
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
