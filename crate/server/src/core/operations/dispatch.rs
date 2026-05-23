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
            algorithm_policy::enforce_kmip_algorithm_policy_for_operation,
            get_attribute_list::get_attribute_list, mac::mac_verify, query::query as query_op,
        },
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Generate a match arm that deserializes TTLV, calls `kms.$method(req, user)`, and wraps in
/// `Operation::$Response`.
macro_rules! op {
    ($ttlv:expr, $kms:expr, $user:expr, $Req:ty, $method:ident, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let resp = $kms.$method(req, $user).await?;
        Operation::$Resp(resp)
    }};
    // Variant for operations that also need privileged_users
    (priv $ttlv:expr, $kms:expr, $user:expr, $Req:ty, $method:ident, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let privileged_users = $kms.params.privileged_users.clone();
        let resp = $kms.$method(req, $user, privileged_users).await?;
        Operation::$Resp(resp)
    }};
    // Variant for operations returning a boxed response
    (boxed $ttlv:expr, $kms:expr, $user:expr, $Req:ty, $method:ident, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let resp = $kms.$method(req, $user).await?;
        Operation::$Resp(Box::new(resp))
    }};
    // Variant for operations that need Box::pin (deep recursion)
    (pin $ttlv:expr, $kms:expr, $user:expr, $Req:ty, $method:ident, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let resp = Box::pin($kms.$method(req, $user)).await?;
        Operation::$Resp(resp)
    }};
}

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
    }

    result
}

async fn dispatch_inner(
    kms: &KMS,
    ttlv: TTLV,
    user: &str,
    operation_tag: &str,
) -> KResult<Operation> {
    // For operations where the request carries algorithm choices, validate them
    // before executing any cryptographic action.
    enforce_kmip_algorithm_policy_for_operation(&kms.params, operation_tag, &ttlv)?;

    Ok(match operation_tag {
        "Activate" => op!(ttlv, kms, user, Activate, activate, ActivateResponse),
        "AddAttribute" => op!(
            ttlv,
            kms,
            user,
            AddAttribute,
            add_attribute,
            AddAttributeResponse
        ),
        "Certify" => op!(priv ttlv, kms, user, Certify, certify, CertifyResponse),
        "Check" => {
            let req = from_ttlv::<Check>(ttlv)?;
            let resp = crate::core::operations::check::check(kms, req, user).await?;
            Operation::CheckResponse(resp)
        }
        "Create" => op!(priv ttlv, kms, user, Create, create, CreateResponse),
        "CreateKeyPair" => {
            op!(priv ttlv, kms, user, CreateKeyPair, create_key_pair, CreateKeyPairResponse)
        }
        "Decrypt" => op!(ttlv, kms, user, Decrypt, decrypt, DecryptResponse),
        "DeleteAttribute" => {
            op!(
                ttlv,
                kms,
                user,
                DeleteAttribute,
                delete_attribute,
                DeleteAttributeResponse
            )
        }
        "DeriveKey" => op!(pin ttlv, kms, user, DeriveKey, derive_key, DeriveKeyResponse),
        "Destroy" => op!(ttlv, kms, user, Destroy, destroy, DestroyResponse),
        "DiscoverVersions" => {
            let req = from_ttlv::<DiscoverVersions>(ttlv)?;
            let resp = kms.discover_versions(req, user).await;
            Operation::DiscoverVersionsResponse(resp)
        }
        "Encrypt" => op!(ttlv, kms, user, Encrypt, encrypt, EncryptResponse),
        "Export" => op!(boxed ttlv, kms, user, Export, export, ExportResponse),
        "Get" => op!(ttlv, kms, user, Get, get, GetResponse),
        "GetAttributeList" => {
            let req = from_ttlv::<GetAttributeList>(ttlv)?;
            let resp = Box::pin(get_attribute_list(kms, req, user)).await?;
            Operation::GetAttributeListResponse(resp)
        }
        "GetAttributes" => {
            op!(boxed ttlv, kms, user, GetAttributes, get_attributes, GetAttributesResponse)
        }
        "Hash" => op!(ttlv, kms, user, Hash, hash, HashResponse),
        "RNGRetrieve" => op!(
            ttlv,
            kms,
            user,
            RNGRetrieve,
            rng_retrieve,
            RNGRetrieveResponse
        ),
        "RNGSeed" => op!(ttlv, kms, user, RNGSeed, rng_seed, RNGSeedResponse),
        "Import" => op!(priv ttlv, kms, user, Import, import, ImportResponse),
        "Locate" => op!(ttlv, kms, user, Locate, locate, LocateResponse),
        "Mac" | "MAC" => op!(ttlv, kms, user, MAC, mac, MACResponse),
        "MACVerify" => {
            let req = from_ttlv::<MACVerify>(ttlv)?;
            let resp = Box::pin(mac_verify(kms, req, user)).await?;
            Operation::MACVerifyResponse(resp)
        }
        "Query" => {
            let req = from_ttlv::<Query>(ttlv)?;
            let resp = query_op(req, kms.vendor_id()).await?;
            Operation::QueryResponse(Box::new(resp))
        }
        "ModifyAttribute" => {
            op!(
                ttlv,
                kms,
                user,
                ModifyAttribute,
                modify_attribute,
                ModifyAttributeResponse
            )
        }
        "ReKey" => op!(ttlv, kms, user, ReKey, rekey, ReKeyResponse),
        "ReKeyKeyPair" => {
            op!(priv ttlv, kms, user, ReKeyKeyPair, rekey_keypair, ReKeyKeyPairResponse)
        }
        "Register" => op!(priv ttlv, kms, user, Register, register, RegisterResponse),
        "Revoke" => op!(ttlv, kms, user, Revoke, revoke, RevokeResponse),
        "SetAttribute" => {
            debug!("SetAttribute TTLV {ttlv:#?}");
            let req = from_ttlv::<SetAttribute>(ttlv)?;
            debug!("SetAttribute request received");
            let resp = kms.set_attribute(req, user).await?;
            Operation::SetAttributeResponse(resp)
        }
        "Sign" => op!(ttlv, kms, user, Sign, sign, SignResponse),
        "SignatureVerify" => {
            op!(
                ttlv,
                kms,
                user,
                SignatureVerify,
                signature_verify,
                SignatureVerifyResponse
            )
        }
        "Validate" => op!(ttlv, kms, user, Validate, validate, ValidateResponse),
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    })
}
