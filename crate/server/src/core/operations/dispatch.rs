use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_2_1::kmip_operations::{
            Certify, Create, CreateKeyPair, Decrypt, DeleteAttribute, Destroy, Encrypt, Export,
            Get, GetAttributes, Hash, Import, Locate, MAC, Operation, Query, ReKey, ReKeyKeyPair,
            Revoke, SetAttribute, Validate,
        },
        ttlv::{TTLV, from_ttlv},
    },
    cosmian_kms_interfaces::SessionParams,
};
use tracing::debug;

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

/// Dispatch operation depending on the TTLV tag
pub(crate) async fn dispatch(
    kms: &KMS,
    ttlv: TTLV,
    user: &str,
    database_params: Option<Arc<dyn SessionParams>>,
) -> KResult<Operation> {
    Ok(match ttlv.tag.as_str() {
        "Certify" => {
            let req = from_ttlv::<Certify>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms
                .certify(req, user, database_params, privileged_users)
                .await?;
            Operation::CertifyResponse(resp)
        }
        "Create" => {
            let req = from_ttlv::<Create>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms
                .create(req, user, database_params, privileged_users)
                .await?;
            Operation::CreateResponse(resp)
        }
        "CreateKeyPair" => {
            let req = from_ttlv::<CreateKeyPair>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms
                .create_key_pair(req, user, database_params, privileged_users)
                .await?;
            Operation::CreateKeyPairResponse(resp)
        }
        "Decrypt" => {
            let req = from_ttlv::<Decrypt>(ttlv)?;
            let resp = kms.decrypt(req, user, database_params).await?;
            Operation::DecryptResponse(resp)
        }
        "DeleteAttribute" => {
            let req = from_ttlv::<DeleteAttribute>(ttlv)?;
            let resp = kms.delete_attribute(req, user, database_params).await?;
            Operation::DeleteAttributeResponse(resp)
        }
        "Destroy" => {
            let req = from_ttlv::<Destroy>(ttlv)?;
            let resp = kms.destroy(req, user, database_params).await?;
            Operation::DestroyResponse(resp)
        }
        "Encrypt" => {
            let req = from_ttlv::<Encrypt>(ttlv)?;
            let resp = kms.encrypt(req, user, database_params).await?;
            Operation::EncryptResponse(resp)
        }
        "Export" => {
            let req = from_ttlv::<Export>(ttlv)?;
            let resp = kms.export(req, user, database_params).await?;
            Operation::ExportResponse(resp)
        }
        "Get" => {
            let req = from_ttlv::<Get>(ttlv)?;
            let resp = kms.get(req, user, database_params).await?;
            Operation::GetResponse(resp)
        }
        "GetAttributes" => {
            let req = from_ttlv::<GetAttributes>(ttlv)?;
            let resp = kms.get_attributes(req, user, database_params).await?;
            Operation::GetAttributesResponse(resp)
        }

        "Hash" => {
            let req = from_ttlv::<Hash>(ttlv)?;
            let resp = kms.hash(req, user, database_params).await?;
            Operation::HashResponse(resp)
        }
        "Mac" => {
            let req = from_ttlv::<MAC>(ttlv)?;
            let resp = kms.mac(req, user, database_params).await?;
            Operation::MACResponse(resp)
        }
        "Import" => {
            let req = from_ttlv::<Import>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms
                .import(req, user, database_params, privileged_users)
                .await?;
            Operation::ImportResponse(resp)
        }
        "Locate" => {
            let req = from_ttlv::<Locate>(ttlv)?;
            let resp = kms.locate(req, user, database_params).await?;
            Operation::LocateResponse(resp)
        }
        "MAC" => {
            let req = from_ttlv::<MAC>(ttlv)?;
            let resp = kms.mac(req, user, database_params).await?;
            Operation::MACResponse(resp)
        }
        "Query" => {
            let req = from_ttlv::<Query>(ttlv)?;
            let resp = kms.query(req).await?;
            Operation::QueryResponse(resp)
        }
        "ReKey" => {
            let req = from_ttlv::<ReKey>(ttlv)?;
            let resp = kms.rekey(req, user, database_params).await?;
            Operation::ReKeyResponse(resp)
        }
        "ReKeyKeyPair" => {
            let req = from_ttlv::<ReKeyKeyPair>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();

            let resp = kms
                .rekey_keypair(req, user, database_params, privileged_users)
                .await?;
            Operation::ReKeyKeyPairResponse(resp)
        }
        "Revoke" => {
            let req = from_ttlv::<Revoke>(ttlv)?;
            let resp = kms.revoke(req, user, database_params).await?;
            Operation::RevokeResponse(resp)
        }
        "SetAttribute" => {
            debug!("SetAttribute TTLV {ttlv:#?}");
            let req = from_ttlv::<SetAttribute>(ttlv)?;
            debug!("SetAttribute: {req:?}");
            let resp = kms.set_attribute(req, user, database_params).await?;
            Operation::SetAttributeResponse(resp)
        }
        "Validate" => {
            let req = from_ttlv::<Validate>(ttlv)?;
            let resp = kms.validate(req, user, database_params).await?;
            Operation::ValidateResponse(resp)
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    })
}
