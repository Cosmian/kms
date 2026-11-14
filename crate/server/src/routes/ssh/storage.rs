use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{SecretDataType, State},
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::{Object, ObjectType},
            requests::create_secret_data_kmip_object,
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

const SSH_RECORD_TAG: &str = "_ssh_api";
/// HMAC domain of the SSH record UIDs, distinct from every other use of the internal UID key.
const SSH_RECORD_UID_DOMAIN: &[u8] = b"cosmian-kms-ssh-record-v2:";
/// Owner of the SSH CA/role records and internal signing authority of the configured CA key:
/// reserved so no externally-derived identity can claim it.
pub(crate) const SSH_RECORD_OWNER: &str = "cosmian-ssh-api-internal";

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
    pub(crate) allowed_users: Vec<String>,
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

/// The role `name`, or `None` when it does not exist.
pub(crate) async fn get_role(kms: &KMS, name: &str) -> KResult<Option<RolePolicy>> {
    let Some(policy) = get_record::<RolePolicy>(kms, &format!("role:{name}"), "SSH role").await?
    else {
        return Ok(None);
    };
    if policy.name != name {
        return Err(KmsError::ServerError(
            "stored SSH role name does not match its record identifier".to_owned(),
        ));
    }
    Ok(Some(policy))
}

pub(crate) async fn save_role(kms: &KMS, policy: &RolePolicy) -> KResult<()> {
    save_record(kms, &format!("role:{}", policy.name), policy, "SSH role").await
}

async fn get_record<T: DeserializeOwned>(
    kms: &KMS,
    record_key: &str,
    description: &str,
) -> KResult<Option<T>> {
    let uid = record_uid(kms.internal_uid_key().await?, record_key)?;
    let (owm, tags) = tokio::try_join!(
        kms.database.retrieve_object_uncached(&uid),
        kms.database.retrieve_tags(&uid)
    )?;
    let Some(owm) = owm else {
        return Ok(None);
    };
    if owm.owner() != SSH_RECORD_OWNER {
        return Err(KmsError::ServerError(format!(
            "{description} record has an unexpected owner"
        )));
    }
    if matches!(owm.state(), State::Destroyed | State::Destroyed_Compromised) {
        return Err(KmsError::ServerError(format!(
            "{description} record is destroyed"
        )));
    }
    let Object::SecretData(secret) = owm.object() else {
        return Err(KmsError::ServerError(format!(
            "{description} record is not SecretData"
        )));
    };
    if !tags.contains(SSH_RECORD_TAG) {
        return Err(KmsError::ServerError(format!(
            "{description} record has an unexpected tag"
        )));
    }
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
    let uid = record_uid(kms.internal_uid_key().await?, record_key)?;
    let owner = UserId::from(SSH_RECORD_OWNER);
    let bytes = serde_json::to_vec(value)
        .map_err(|e| KmsError::ServerError(format!("encoding {description}: {e}")))?;
    let object = build_secret_object(kms.vendor_id(), &bytes)?;
    let attributes = object.attributes()?.clone();
    let tags = HashSet::from([SSH_RECORD_TAG.to_owned()]);
    let (existing, existing_tags) = tokio::try_join!(
        kms.database.retrieve_object_uncached(&uid),
        kms.database.retrieve_tags(&uid)
    )?;
    let operation = match existing {
        Some(owm) => {
            if owm.owner() != SSH_RECORD_OWNER {
                return Err(KmsError::ServerError(format!(
                    "{description} record identifier is owned by a different principal"
                )));
            }
            if owm.object().object_type() != ObjectType::SecretData
                || !existing_tags.contains(SSH_RECORD_TAG)
            {
                return Err(KmsError::ServerError(format!(
                    "{description} record identifier is occupied by a different object"
                )));
            }
            let expected_version = owm.version().ok_or_else(|| {
                KmsError::ServerError(format!("{description} record has no version"))
            })?;
            AtomicOperation::CompareAndSwapObject {
                uid,
                expected_version,
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

/// UID of the SSH record `record_key`: HMAC-SHA256 under the server-internal UID key, truncated
/// to a UUID. KMIP clients cannot compute it, so they cannot occupy a record UID beforehand.
fn record_uid(key: &[u8], record_key: &str) -> KResult<String> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(SSH_RECORD_UID_DOMAIN)?;
    signer.update(record_key.as_bytes())?;
    let mac = signer.sign_to_vec()?;
    Uuid::from_slice(mac.get(..16).ok_or_else(|| {
        KmsError::ServerError("failed to derive SSH configuration identifier".to_owned())
    })?)
    .map(|uuid| uuid.to_string())
    .map_err(|e| KmsError::ServerError(format!("deriving SSH configuration identifier: {e}")))
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use super::*;

    fn policy() -> RolePolicy {
        RolePolicy {
            name: "developers".to_owned(),
            allowed_principals: vec!["alice".to_owned()],
            allowed_users: vec!["alice".to_owned(), "bob".to_owned()],
            default_ttl_secs: 900,
            max_ttl_secs: 3_600,
        }
    }

    #[tokio::test]
    async fn ssh_role_records_survive_kms_reinstantiation() -> KResult<()> {
        let mut config = crate::tests::test_utils::https_clap_config();
        let database_path = config.db.sqlite_path.clone();
        let first_kms = crate::tests::test_utils::test_kms_with_config(config).await?;
        save_role(&first_kms, &policy()).await?;
        assert_eq!(get_role(&first_kms, "developers").await?, Some(policy()));
        // A second save is a compare-and-swap on the stored version.
        let updated = RolePolicy {
            max_ttl_secs: 7_200,
            ..policy()
        };
        save_role(&first_kms, &updated).await?;
        assert_eq!(get_role(&first_kms, "developers").await?, Some(updated));
        assert_eq!(get_role(&first_kms, "missing").await?, None);
        drop(first_kms);

        config = crate::tests::test_utils::https_clap_config();
        config.db.sqlite_path = database_path;
        let second_kms = crate::tests::test_utils::test_kms_with_config(config).await?;
        assert_eq!(
            get_role(&second_kms, "developers")
                .await?
                .map(|p| p.max_ttl_secs),
            Some(7_200)
        );
        Ok(())
    }

    #[test]
    fn record_uid_is_keyed_and_domain_separated() -> KResult<()> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let uid = record_uid(&[1; 32], "ca")?;
        assert_eq!(uid, record_uid(&[1; 32], "ca")?, "stable for one key");
        assert_ne!(uid, record_uid(&[2; 32], "ca")?, "depends on the key");
        assert_ne!(
            uid,
            record_uid(&[1; 32], "role:ca")?,
            "depends on the record"
        );
        Ok(())
    }

    /// A KMIP client that occupies the former public, unkeyed record UID (or any UID it can
    /// compute) cannot deny the SSH configuration anymore.
    #[tokio::test]
    async fn preclaimed_public_record_uid_does_not_block_configuration() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let digest = openssl::sha::sha256(b"cosmian-kms-ssh-api-v1:role:developers");
        let public_uid = Uuid::from_slice(
            digest
                .get(..16)
                .ok_or_else(|| KmsError::ServerError("digest shorter than a UUID".to_owned()))?,
        )
        .map_err(|e| KmsError::ServerError(e.to_string()))?
        .to_string();
        let mallory = UserId::from("mallory");
        let object = build_secret_object(kms.vendor_id(), b"{}")?;
        let attributes = object.attributes()?.clone();
        kms.database
            .atomic(
                &mallory,
                &[AtomicOperation::Create((
                    public_uid,
                    mallory.clone(),
                    object,
                    attributes,
                    HashSet::from([SSH_RECORD_TAG.to_owned()]),
                ))],
            )
            .await?;

        save_role(&kms, &policy()).await?;
        assert_eq!(get_role(&kms, "developers").await?, Some(policy()));
        Ok(())
    }
}
