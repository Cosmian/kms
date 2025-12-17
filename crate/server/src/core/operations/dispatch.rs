use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_operations::DiscoverVersions,
    kmip_2_1::kmip_operations::{
        Activate, AddAttribute, Certify, Check, Create, CreateKeyPair, Decrypt, DeleteAttribute,
        DeriveKey, Destroy, Encrypt, Export, Get, GetAttributeList, GetAttributes, Hash, Import,
        Locate, MAC, MACVerify, ModifyAttribute, Operation, Query, RNGRetrieve, RNGSeed, ReKey,
        ReKeyKeyPair, Register, Revoke, SetAttribute, Sign, SignatureVerify, Validate,
    },
    ttlv::{TTLV, from_ttlv},
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
pub(crate) async fn dispatch(kms: &KMS, ttlv: TTLV, user: &str) -> KResult<Operation> {
    let operation_tag = ttlv.tag.clone();
    let start_time = std::time::Instant::now();

    let result = dispatch_inner(kms, ttlv, user, &operation_tag).await;

    // Record metrics if enabled
    if let Some(ref metrics) = kms.metrics {
        let duration = start_time.elapsed().as_secs_f64();
        metrics.record_kmip_operation(&operation_tag, user);
        metrics.record_kmip_operation_duration(&operation_tag, duration);

        // Record error if operation failed
        if result.is_err() {
            metrics.record_error(&operation_tag);
        }

        // Active keys metric refresh moved to standalone background task
    }

    result
}

async fn dispatch_inner(
    kms: &KMS,
    ttlv: TTLV,
    user: &str,
    operation_tag: &str,
) -> KResult<Operation> {
    Ok(match operation_tag {
        "Activate" => {
            let req = from_ttlv::<Activate>(ttlv)?;
            let resp = kms.activate(req, user).await?;
            Operation::ActivateResponse(resp)
        }
        "AddAttribute" => {
            let req = from_ttlv::<AddAttribute>(ttlv)?;
            let resp = kms.add_attribute(req, user).await?;
            Operation::AddAttributeResponse(resp)
        }
        "Certify" => {
            let req = from_ttlv::<Certify>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms.certify(req, user, privileged_users).await?;
            Operation::CertifyResponse(resp)
        }
        "Check" => {
            let req = from_ttlv::<Check>(ttlv)?;
            let resp = crate::core::operations::check::check(kms, req, user).await?;
            Operation::CheckResponse(resp)
        }
        "Create" => {
            let req = from_ttlv::<Create>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms.create(req, user, privileged_users).await?;
            Operation::CreateResponse(resp)
        }
        "CreateKeyPair" => {
            let req = from_ttlv::<CreateKeyPair>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms.create_key_pair(req, user, privileged_users).await?;
            Operation::CreateKeyPairResponse(resp)
        }
        "Decrypt" => {
            let req = from_ttlv::<Decrypt>(ttlv)?;
            let resp = kms.decrypt(req, user).await?;
            Operation::DecryptResponse(resp)
        }
        "DeleteAttribute" => {
            let req = from_ttlv::<DeleteAttribute>(ttlv)?;
            let resp = kms.delete_attribute(req, user).await?;
            Operation::DeleteAttributeResponse(resp)
        }
        "DeriveKey" => {
            let req = from_ttlv::<DeriveKey>(ttlv)?;
            let resp = Box::pin(kms.derive_key(req, user)).await?;
            Operation::DeriveKeyResponse(resp)
        }
        "Destroy" => {
            let req = from_ttlv::<Destroy>(ttlv)?;
            let resp = kms.destroy(req, user).await?;
            Operation::DestroyResponse(resp)
        }
        "DiscoverVersions" => {
            let req = from_ttlv::<DiscoverVersions>(ttlv)?;
            let resp = kms.discover_versions(req, user).await;
            Operation::DiscoverVersionsResponse(resp)
        }
        "Encrypt" => {
            let req = from_ttlv::<Encrypt>(ttlv)?;
            let resp = kms.encrypt(req, user).await?;
            Operation::EncryptResponse(resp)
        }
        "Export" => {
            let req = from_ttlv::<Export>(ttlv)?;
            let resp = kms.export(req, user).await?;
            Operation::ExportResponse(Box::new(resp))
        }
        "Get" => {
            let req = from_ttlv::<Get>(ttlv)?;
            let resp = kms.get(req, user).await?;
            Operation::GetResponse(resp)
        }
        "GetAttributeList" => {
            let req = from_ttlv::<GetAttributeList>(ttlv)?;
            let resp = Box::pin(get_attribute_list(kms, req, user)).await?;
            Operation::GetAttributeListResponse(resp)
        }
        "GetAttributes" => {
            let req = from_ttlv::<GetAttributes>(ttlv)?;
            let resp = kms.get_attributes(req, user).await?;
            Operation::GetAttributesResponse(Box::new(resp))
        }
        "Hash" => {
            let req = from_ttlv::<Hash>(ttlv)?;
            let resp = kms.hash(req, user).await?;
            Operation::HashResponse(resp)
        }
        "RNGRetrieve" => {
            let req = from_ttlv::<RNGRetrieve>(ttlv)?;
            let resp = kms.rng_retrieve(req, user).await?;
            Operation::RNGRetrieveResponse(resp)
        }
        "RNGSeed" => {
            let req = from_ttlv::<RNGSeed>(ttlv)?;
            let resp = kms.rng_seed(req, user).await?;
            Operation::RNGSeedResponse(resp)
        }
        "Import" => {
            let req = from_ttlv::<Import>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms.import(req, user, privileged_users).await?;
            Operation::ImportResponse(resp)
        }
        "Locate" => {
            let req = from_ttlv::<Locate>(ttlv)?;
            let resp = kms.locate(req, user).await?;
            Operation::LocateResponse(resp)
        }
        "Mac" | "MAC" => {
            let req = from_ttlv::<MAC>(ttlv)?;
            let resp = kms.mac(req, user).await?;
            Operation::MACResponse(resp)
        }
        "MACVerify" => {
            let req = from_ttlv::<MACVerify>(ttlv)?;
            let resp = Box::pin(mac_verify(kms, req, user)).await?;
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
            let resp = modify_attribute(kms, req, user).await?;
            Operation::ModifyAttributeResponse(resp)
        }
        "ReKey" => {
            let req = from_ttlv::<ReKey>(ttlv)?;
            let resp = kms.rekey(req, user).await?;
            Operation::ReKeyResponse(resp)
        }
        "ReKeyKeyPair" => {
            let req = from_ttlv::<ReKeyKeyPair>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();

            let resp = kms.rekey_keypair(req, user, privileged_users).await?;
            Operation::ReKeyKeyPairResponse(resp)
        }
        "Register" => {
            let req = from_ttlv::<Register>(ttlv)?;
            let privileged_users = kms.params.privileged_users.clone();
            let resp = kms.register(req, user, privileged_users).await?;
            Operation::RegisterResponse(resp)
        }
        "Revoke" => {
            let req = from_ttlv::<Revoke>(ttlv)?;
            let resp = kms.revoke(req, user).await?;
            Operation::RevokeResponse(resp)
        }
        "SetAttribute" => {
            debug!("SetAttribute TTLV {ttlv:#?}");
            let req = from_ttlv::<SetAttribute>(ttlv)?;
            debug!("SetAttribute request received");
            let resp = kms.set_attribute(req, user).await?;
            Operation::SetAttributeResponse(resp)
        }
        "Sign" => {
            let req = from_ttlv::<Sign>(ttlv)?;
            let resp = kms.sign(req, user).await?;
            Operation::SignResponse(resp)
        }
        "SignatureVerify" => {
            let req = from_ttlv::<SignatureVerify>(ttlv)?;
            let resp = kms.signature_verify(req, user).await?;
            Operation::SignatureVerifyResponse(resp)
        }
        "Validate" => {
            let req = from_ttlv::<Validate>(ttlv)?;
            let resp = kms.validate(req, user).await?;
            Operation::ValidateResponse(resp)
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    })
}
