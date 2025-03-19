use std::sync::Arc;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::{
        Certify, Create, CreateKeyPair, Decrypt, DeleteAttribute, Destroy, Encrypt, Export, Get,
        GetAttributes, Hash, Import, Locate, Mac, Operation, ReKey, ReKeyKeyPair, Revoke,
        SetAttribute, Validate,
    },
    ttlv::{TTLV, deserializer::TryFromTtlv},
};
use cosmian_kms_interfaces::SessionParams;

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

/// Dispatch operation depending on the TTLV tag
pub(crate) async fn dispatch(
    kms: &KMS,
    ttlv: &TTLV,
    user: &str,
    database_params: Option<Arc<dyn SessionParams>>,
) -> KResult<Operation> {
    Ok(match ttlv.tag.as_str() {
        "Certify" => {
            let req = Certify::try_from_ttlv(ttlv)?;
            let resp = kms.certify(req, user, database_params).await?;
            Operation::CertifyResponse(resp)
        }
        "Create" => {
            let req = Create::try_from_ttlv(ttlv)?;
            #[allow(clippy::large_futures)]
            let resp = kms.create(req, user, database_params).await?;
            Operation::CreateResponse(resp)
        }
        "CreateKeyPair" => {
            let req = CreateKeyPair::try_from_ttlv(ttlv)?;
            let resp = kms.create_key_pair(req, user, database_params).await?;
            Operation::CreateKeyPairResponse(resp)
        }
        "Decrypt" => {
            let req = Decrypt::try_from_ttlv(ttlv)?;
            let resp = kms.decrypt(req, user, database_params).await?;
            Operation::DecryptResponse(resp)
        }
        "Destroy" => {
            let req = Destroy::try_from_ttlv(ttlv)?;
            let resp = kms.destroy(req, user, database_params).await?;
            Operation::DestroyResponse(resp)
        }
        "Encrypt" => {
            let req = Encrypt::try_from_ttlv(ttlv)?;
            let resp = kms.encrypt(req, user, database_params).await?;
            Operation::EncryptResponse(resp)
        }
        "Export" => {
            let req = Export::try_from_ttlv(ttlv)?;
            let resp = kms.export(req, user, database_params).await?;
            Operation::ExportResponse(resp)
        }
        "Get" => {
            let req = Get::try_from_ttlv(ttlv)?;
            let resp = kms.get(req, user, database_params).await?;
            Operation::GetResponse(resp)
        }
        "GetAttributes" => {
            let req = GetAttributes::try_from_ttlv(ttlv)?;
            let resp = kms.get_attributes(req, user, database_params).await?;
            Operation::GetAttributesResponse(resp)
        }
        "Hash" => {
            let req = Hash::try_from_ttlv(ttlv)?;
            let resp = kms.hash(req, user, database_params).await?;
            Operation::HashResponse(resp)
        }
        "Mac" => {
            let req = Mac::try_from_ttlv(ttlv)?;
            let resp = kms.mac(req, user, database_params).await?;
            Operation::MacResponse(resp)
        }
        "SetAttribute" => {
            let req = SetAttribute::try_from_ttlv(ttlv)?;
            let resp = kms.set_attribute(req, user, database_params).await?;
            Operation::SetAttributeResponse(resp)
        }
        "DeleteAttribute" => {
            let req = DeleteAttribute::try_from_ttlv(ttlv)?;
            let resp = kms.delete_attribute(req, user, database_params).await?;
            Operation::DeleteAttributeResponse(resp)
        }
        "Import" => {
            let req = Import::try_from_ttlv(ttlv)?;
            let resp = kms.import(req, user, database_params).await?;
            Operation::ImportResponse(resp)
        }
        "Locate" => {
            let req = Locate::try_from_ttlv(ttlv)?;
            let resp = kms.locate(req, user, database_params).await?;
            Operation::LocateResponse(resp)
        }
        "ReKey" => {
            let req = ReKey::try_from_ttlv(ttlv)?;
            let resp = kms.rekey(req, user, database_params).await?;
            Operation::ReKeyResponse(resp)
        }
        "ReKeyKeyPair" => {
            let req = ReKeyKeyPair::try_from_ttlv(ttlv)?;
            #[allow(clippy::large_futures)]
            let resp = kms.rekey_keypair(req, user, database_params).await?;
            Operation::ReKeyKeyPairResponse(resp)
        }
        "Revoke" => {
            let req = Revoke::try_from_ttlv(ttlv)?;
            let resp = kms.revoke(req, user, database_params).await?;
            Operation::RevokeResponse(resp)
        }
        "Validate" => {
            let req = Validate::try_from_ttlv(ttlv)?;
            let resp = kms.validate(req, user, database_params).await?;
            Operation::ValidateResponse(resp)
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    })
}
