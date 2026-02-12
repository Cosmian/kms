use std::collections::HashMap;

use base64::Engine as _;
use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde_json::Value;

use crate::{
    actions::kms::{
        configurable_kem::{
            decaps::DecapsAction, encaps::EncapsAction, keygen::CreateKemKeyPairAction,
        },
        console,
    },
    error::result::KmsCliResult,
};

pub(crate) mod decaps;
pub(crate) mod encaps;
pub(crate) mod keygen;

#[derive(Parser)]
pub enum ConfigurableKemCommands {
    KeyGen(CreateKemKeyPairAction),
    Encrypt(EncapsAction),
    Decrypt(DecapsAction),
}

impl ConfigurableKemCommands {
    /// Process the configurable-KEM command and execute the corresponding
    /// action.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::KeyGen(action) => {
                drop(Box::pin(action.run(kms_rest_client)).await?);
            }
            Self::Encrypt(action) => {
                let (key, encapsulation) = Box::pin(action.run(kms_rest_client)).await?;

                let mut stdout = console::Stdout::new("Encapsulation successful.");
                let mut attributes = HashMap::new();
                attributes.insert(
                    "session_key".to_owned(),
                    Value::String(base64::engine::general_purpose::STANDARD.encode(&*key)),
                );
                attributes.insert(
                    "encapsulation".to_owned(),
                    Value::String(
                        base64::engine::general_purpose::STANDARD.encode(&*encapsulation),
                    ),
                );
                stdout.set_attributes(attributes);
                stdout.write()?;
            }
            Self::Decrypt(action) => {
                let key = Box::pin(action.run(kms_rest_client)).await?;

                let mut stdout = console::Stdout::new("Decapsulation successful.");
                let mut attributes = HashMap::new();
                attributes.insert(
                    "session_key".to_owned(),
                    Value::String(base64::engine::general_purpose::STANDARD.encode(&*key)),
                );
                stdout.set_attributes(attributes);
                stdout.write()?;
            }
        }
        Ok(())
    }
}
