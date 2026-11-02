use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::SecretDataType,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::{Object, ObjectType},
            requests::create_secret_data_kmip_object,
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

const SSH_RECORD_TAG: &str = "_ssh_api";
const SSH_RECORD_OWNER: &str = "cosmian-ssh-api-internal";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaConfiguration {
    pub(crate) key_uid: String,
    pub(crate) public_key: String,
    pub(crate) public_key_sha256: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RolePolicy {
    pub(crate) name: String,
    pub(crate) allowed_principals: Vec<String>,
    pub(crate) default_ttl_secs: u64,
    pub(crate) max_ttl_secs: u64,
}

pub(crate) async fn get_ca_configuration(kms: &KMS) -> KResult<CaConfiguration> {
    get_record(kms, "ca", "SSH CA configuration")
        .await?
        .ok_or_else(|| KmsError::ItemNotFound("SSH CA is not configured".to_owned()))
}

pub(crate) async fn save_ca_configuration(
    kms: &KMS,
    configuration: &CaConfiguration,
) -> KResult<()> {
    save_record(kms, "ca", configuration, "SSH CA configuration").await
}

pub(crate) async fn get_role(kms: &KMS, name: &str) -> KResult<RolePolicy> {
    let policy: RolePolicy = get_record(kms, &format!("role:{name}"), "SSH role")
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(format!("SSH role '{name}' does not exist")))?;
    if policy.name != name {
        return Err(KmsError::ServerError(
            "stored SSH role name does not match its record identifier".to_owned(),
        ));
    }
    Ok(policy)
}

pub(crate) async fn save_role(kms: &KMS, policy: &RolePolicy) -> KResult<()> {
    save_record(kms, &format!("role:{}", policy.name), policy, "SSH role").await
}

async fn get_record<T: DeserializeOwned>(
    kms: &KMS,
    record_key: &str,
    description: &str,
) -> KResult<Option<T>> {
    let uid = record_uid(record_key)?;
    let Some(owm) = kms.database.retrieve_object(&uid).await? else {
        return Ok(None);
    };
    if owm.owner() != SSH_RECORD_OWNER {
        return Err(KmsError::ServerError(format!(
            "{description} record has an unexpected owner"
        )));
    }
    if matches!(
        owm.state(),
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::State::Destroyed
            | cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::State::Destroyed_Compromised
    ) {
        return Err(KmsError::ServerError(format!(
            "{description} record is destroyed"
        )));
    }
    let tags = kms.database.retrieve_tags(&uid).await?;
    if owm.object().object_type() != ObjectType::SecretData || !tags.contains(SSH_RECORD_TAG) {
        return Err(KmsError::ServerError(format!(
            "{description} record has an unexpected object type or tag"
        )));
    }
    let Object::SecretData(secret) = owm.object() else {
        return Err(KmsError::ServerError(format!(
            "{description} record is not SecretData"
        )));
    };
    let bytes = secret
        .key_block
        .key_bytes()
        .map_err(|e| KmsError::ServerError(format!("reading {description} record: {e}")))?;
    serde_json::from_slice(bytes.as_ref())
        .map(Some)
        .map_err(|e| KmsError::ServerError(format!("decoding {description} record: {e}")))
}

async fn save_record<T: Serialize>(
    kms: &KMS,
    record_key: &str,
    value: &T,
    description: &str,
) -> KResult<()> {
    let uid = record_uid(record_key)?;
    let owner = UserId::from(SSH_RECORD_OWNER);
    let bytes = serde_json::to_vec(value)
        .map_err(|e| KmsError::ServerError(format!("encoding {description}: {e}")))?;
    let object = build_secret_object(kms.vendor_id(), &bytes)?;
    let attributes = object.attributes()?.clone();
    let tags = HashSet::from([SSH_RECORD_TAG.to_owned()]);
    let operation = match kms.database.retrieve_object(&uid).await? {
        Some(owm) => {
            if owm.owner() != SSH_RECORD_OWNER {
                return Err(KmsError::ServerError(format!(
                    "{description} record identifier is owned by a different principal"
                )));
            }
            let existing_tags = kms.database.retrieve_tags(&uid).await?;
            if owm.object().object_type() != ObjectType::SecretData
                || !existing_tags.contains(SSH_RECORD_TAG)
            {
                return Err(KmsError::ServerError(format!(
                    "{description} record identifier is occupied by a different object"
                )));
            }
            AtomicOperation::CompareAndSwapObject {
                uid,
                expected_object: Box::new(owm.object().clone()),
                object: Box::new(object),
                attributes,
                tags: Some(tags),
            }
        }
        None => AtomicOperation::Create((uid, owner.clone(), object, attributes, tags)),
    };
    kms.database.atomic(&owner, &[operation]).await?;
    Ok(())
}

fn build_secret_object(vendor_id: &str, bytes: &[u8]) -> KResult<Object> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::SecretData),
        ..Attributes::default()
    };
    attributes.set_tags(vendor_id, vec![SSH_RECORD_TAG.to_owned()])?;
    Ok(create_secret_data_kmip_object(
        vendor_id,
        bytes,
        SecretDataType::Password,
        &attributes,
    )?)
}

fn record_uid(record_key: &str) -> KResult<String> {
    let digest = Sha256::digest(format!("cosmian-kms-ssh-api-v1:{record_key}").as_bytes());
    Uuid::from_slice(digest.get(..16).ok_or_else(|| {
        KmsError::ServerError("failed to derive SSH configuration identifier".to_owned())
    })?)
    .map(|uuid| uuid.to_string())
    .map_err(|e| KmsError::ServerError(format!("deriving SSH configuration identifier: {e}")))
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Test assertions are the failure signal; database errors propagate.
mod tests {
    use super::*;

    #[tokio::test]
    async fn ssh_role_records_survive_kms_reinstantiation() -> KResult<()> {
        let mut config = crate::tests::test_utils::https_clap_config();
        let database_path = config.db.sqlite_path.clone();
        let first_kms = crate::tests::test_utils::test_kms_with_config(config).await?;
        let policy = RolePolicy {
            name: "developers".to_owned(),
            allowed_principals: vec!["alice".to_owned()],
            default_ttl_secs: 900,
            max_ttl_secs: 3_600,
        };
        save_role(&first_kms, &policy).await?;
        assert_eq!(get_role(&first_kms, "developers").await?, policy);
        drop(first_kms);

        config = crate::tests::test_utils::https_clap_config();
        config.db.sqlite_path = database_path;
        let second_kms = crate::tests::test_utils::test_kms_with_config(config).await?;
        assert_eq!(get_role(&second_kms, "developers").await?, policy);
        Ok(())
    }
}
