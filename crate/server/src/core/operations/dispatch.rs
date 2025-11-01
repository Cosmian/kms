use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_operations::DiscoverVersions,
        kmip_2_1::kmip_operations::{
            Activate, AddAttribute, Certify, Check, Create, CreateKeyPair, Decrypt,
            DeleteAttribute, DeriveKey, Destroy, Encrypt, Export, Get, GetAttributeList,
            GetAttributes, Hash, Import, Locate, MAC, MACVerify, ModifyAttribute, Operation, Query,
            RNGRetrieve, RNGSeed, ReKey, ReKeyKeyPair, Register, Revoke, SetAttribute, Sign,
            SignatureVerify, Validate,
        },
        ttlv::{TTLV, from_ttlv},
    },
    cosmian_kms_interfaces::SessionParams,
};
use cosmian_logger::debug;

use crate::{
    core::{
        KMS,
        operations::{
            get_attribute_list::get_attribute_list, mac::mac_verify,
            modify_attribute::modify_attribute, query::query as query_op,
        },
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Dispatch operation depending on the TTLV tag
pub(crate) async fn dispatch(
    kms: &KMS,
    ttlv: TTLV,
    user: &str,
    database_params: Option<Arc<dyn SessionParams>>,
) -> KResult<Operation> {
    Ok(match ttlv.tag.as_str() {
        "Activate" => {
            let req = from_ttlv::<Activate>(ttlv)?;
            let resp = kms.activate(req, user, database_params).await?;
            Operation::ActivateResponse(resp)
        }
        "AddAttribute" => {
            let req = from_ttlv::<AddAttribute>(ttlv)?;
            let resp = kms.add_attribute(req, user, database_params).await?;
            Operation::AddAttributeResponse(resp)
        }
        "Certify" => {
            let req = from_ttlv::<Certify>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms
                .certify(req, user, database_params, privileged_users)
                .await?;
            Operation::CertifyResponse(resp)
        }
        "Check" => {
            let req = from_ttlv::<Check>(ttlv)?;
            let resp =
                crate::core::operations::check::check(kms, req, user, database_params).await?;
            Operation::CheckResponse(resp)
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
        "DeriveKey" => {
            let req = from_ttlv::<DeriveKey>(ttlv)?;
            let resp = Box::pin(kms.derive_key(req, user, database_params)).await?;
            Operation::DeriveKeyResponse(resp)
        }
        "Destroy" => {
            let req = from_ttlv::<Destroy>(ttlv)?;
            let resp = kms.destroy(req, user, database_params).await?;
            Operation::DestroyResponse(resp)
        }
        "DiscoverVersions" => {
            let req = from_ttlv::<DiscoverVersions>(ttlv)?;
            let resp = kms.discover_versions(req, user, database_params).await;
            Operation::DiscoverVersionsResponse(resp)
        }
        "Encrypt" => {
            let req = from_ttlv::<Encrypt>(ttlv)?;
            let resp = kms.encrypt(req, user, database_params).await?;
            Operation::EncryptResponse(resp)
        }
        "Export" => {
            let req = from_ttlv::<Export>(ttlv)?;
            let resp = kms.export(req, user, database_params).await?;
            Operation::ExportResponse(Box::new(resp))
        }
        "Get" => {
            let req = from_ttlv::<Get>(ttlv)?;
            let resp = kms.get(req, user, database_params).await?;
            Operation::GetResponse(resp)
        }
        "GetAttributeList" => {
            let req = from_ttlv::<GetAttributeList>(ttlv)?;
            let resp = get_attribute_list(kms, req, user, database_params).await?;
            Operation::GetAttributeListResponse(resp)
        }
        "GetAttributes" => {
            let req = from_ttlv::<GetAttributes>(ttlv)?;
            let resp = kms.get_attributes(req, user, database_params).await?;
            Operation::GetAttributesResponse(Box::new(resp))
        }
        "Hash" => {
            let req = from_ttlv::<Hash>(ttlv)?;
            let resp = kms.hash(req, user, database_params).await?;
            Operation::HashResponse(resp)
        }
        "RNGRetrieve" => {
            let req = from_ttlv::<RNGRetrieve>(ttlv)?;
            let resp = kms.rng_retrieve(req, user, database_params).await?;
            Operation::RNGRetrieveResponse(resp)
        }
        "RNGSeed" => {
            let req = from_ttlv::<RNGSeed>(ttlv)?;
            let resp = kms.rng_seed(req, user, database_params).await?;
            Operation::RNGSeedResponse(resp)
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
        "Mac" | "MAC" => {
            let req = from_ttlv::<MAC>(ttlv)?;
            let resp = kms.mac(req, user, database_params).await?;
            Operation::MACResponse(resp)
        }
        "MACVerify" => {
            let req = from_ttlv::<MACVerify>(ttlv)?;
            let resp = mac_verify(kms, req, user, database_params).await?;
            Operation::MACVerifyResponse(resp)
        }
        "Query" => {
            let req = from_ttlv::<Query>(ttlv)?;
            // Use operation-level query to keep parity with message.rs
            let resp = query_op(req).await?;
            Operation::QueryResponse(Box::new(resp))
        }
        "ModifyAttribute" => {
            let req = from_ttlv::<ModifyAttribute>(ttlv)?;
            let resp = modify_attribute(kms, req, user, database_params).await?;
            Operation::ModifyAttributeResponse(resp)
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
        "Register" => {
            let req = from_ttlv::<Register>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms
                .register(req, user, database_params, privileged_users)
                .await?;
            Operation::RegisterResponse(resp)
        }
        "Revoke" => {
            let req = from_ttlv::<Revoke>(ttlv)?;
            let resp = kms.revoke(req, user, database_params).await?;
            Operation::RevokeResponse(resp)
        }
        "SetAttribute" => {
            debug!("SetAttribute TTLV {ttlv:#?}");
            let req = from_ttlv::<SetAttribute>(ttlv)?;
            debug!("SetAttribute request received");
            let resp = kms.set_attribute(req, user, database_params).await?;
            Operation::SetAttributeResponse(resp)
        }
        "Sign" => {
            let req = from_ttlv::<Sign>(ttlv)?;
            let resp = kms.sign(req, user, database_params).await?;
            Operation::SignResponse(resp)
        }
        "SignatureVerify" => {
            let req = from_ttlv::<SignatureVerify>(ttlv)?;
            let resp = kms.signature_verify(req, user, database_params).await?;
            Operation::SignatureVerifyResponse(resp)
        }
        "Validate" => {
            let req = from_ttlv::<Validate>(ttlv)?;
            let resp = kms.validate(req, user, database_params).await?;
            Operation::ValidateResponse(resp)
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    })
}
