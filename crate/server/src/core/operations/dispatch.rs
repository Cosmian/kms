use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_operations::DiscoverVersions,
    kmip_2_1::kmip_operations::{
        Activate, AddAttribute, Certify, Check, Create, CreateKeyPair, Decrypt, DeleteAttribute,
        DeriveKey, Destroy, Encrypt, Export, Get, GetAttributeList, GetAttributes, Hash, Import,
        Locate, MAC, MACVerify, ModifyAttribute, Operation, Query, RNGRetrieve, RNGSeed, ReCertify,
        ReKey, ReKeyKeyPair, Register, Revoke, SetAttribute, Sign, SignatureVerify, Validate,
    },
    ttlv::{TTLV, from_ttlv},
};

use crate::{
    core::{
        KMS,
        operations::{
            algorithm_policy::enforce_kmip_algorithm_policy_for_operation,
            attributes::get_attribute_list, check, mac::mac_verify, query::query as query_op,
        },
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
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
    // Variant for free functions: fn(kms, req, user) -> Result<Resp>
    (fn $ttlv:expr, $kms:expr, $user:expr, $Req:ty, $func:expr, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let resp = $func($kms, req, $user).await?;
        Operation::$Resp(resp)
    }};
    // Variant for free functions with Box::pin
    (pin_fn $ttlv:expr, $kms:expr, $user:expr, $Req:ty, $func:expr, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let resp = Box::pin($func($kms, req, $user)).await?;
        Operation::$Resp(resp)
    }};
    // Variant for infallible KMS methods (no `?`)
    (infallible $ttlv:expr, $kms:expr, $user:expr, $Req:ty, $method:ident, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let resp = $kms.$method(req, $user).await;
        Operation::$Resp(resp)
    }};
    // Variant for free functions: fn(req, extra) -> Result<Resp> with boxed response
    (query $ttlv:expr, $kms:expr, $Req:ty, $func:expr, $Resp:ident) => {{
        let req = from_ttlv::<$Req>($ttlv)?;
        let resp = $func(req, $kms.vendor_id()).await?;
        Operation::$Resp(Box::new(resp))
    }};
}

/// Dispatch operation depending on the TTLV tag
pub(crate) async fn dispatch(kms: &KMS, ttlv: TTLV, user: &UserId) -> KResult<Operation> {
    let operation_tag = ttlv.tag.clone();

    if let Some(ref metrics) = kms.metrics {
        let start = std::time::Instant::now();
        let result = dispatch_inner(kms, ttlv, user, &operation_tag).await;
        let duration = start.elapsed().as_secs_f64();
        metrics.record_kmip_operation(&operation_tag, user);
        metrics.record_kmip_operation_duration(&operation_tag, duration);
        if result.is_err() {
            metrics.record_error(&operation_tag);
        }
        result
    } else {
        dispatch_inner(kms, ttlv, user, &operation_tag).await
    }
}

async fn dispatch_inner(
    kms: &KMS,
    ttlv: TTLV,
    user: &UserId,
    operation_tag: &str,
) -> KResult<Operation> {
    // For operations where the request carries algorithm choices, validate them
    // before executing any cryptographic action.  Skip entirely when no policy
    // is configured — avoids a function call + match on every dispatch.
    if kms.params.kmip_policy.policy_id.is_some() {
        enforce_kmip_algorithm_policy_for_operation(&kms.params, operation_tag, &ttlv)?;
    }

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
        "Certify" => op!(ttlv, kms, user, Certify, certify, CertifyResponse),
        "Check" => {
            op!(fn ttlv, kms, user, Check, check, CheckResponse)
        }
        "Create" => op!(ttlv, kms, user, Create, create, CreateResponse),
        "CreateKeyPair" => {
            op!(
                ttlv,
                kms,
                user,
                CreateKeyPair,
                create_key_pair,
                CreateKeyPairResponse
            )
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
            op!(infallible ttlv, kms, user, DiscoverVersions, discover_versions, DiscoverVersionsResponse)
        }
        "Encrypt" => op!(ttlv, kms, user, Encrypt, encrypt, EncryptResponse),
        "Export" => op!(boxed ttlv, kms, user, Export, export, ExportResponse),
        "Get" => op!(ttlv, kms, user, Get, get, GetResponse),
        "GetAttributeList" => {
            op!(pin_fn ttlv, kms, user, GetAttributeList, get_attribute_list, GetAttributeListResponse)
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
        "Import" => op!(ttlv, kms, user, Import, import, ImportResponse),
        "Locate" => op!(ttlv, kms, user, Locate, locate, LocateResponse),
        "Mac" | "MAC" => op!(ttlv, kms, user, MAC, mac, MACResponse),
        "MACVerify" => {
            op!(pin_fn ttlv, kms, user, MACVerify, mac_verify, MACVerifyResponse)
        }
        "Query" => op!(query ttlv, kms, Query, query_op, QueryResponse),
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
            op!(
                ttlv,
                kms,
                user,
                ReKeyKeyPair,
                rekey_keypair,
                ReKeyKeyPairResponse
            )
        }
        "ReCertify" => {
            op!(ttlv, kms, user, ReCertify, recertify, ReCertifyResponse)
        }
        "Register" => op!(ttlv, kms, user, Register, register, RegisterResponse),
        "Revoke" => op!(ttlv, kms, user, Revoke, revoke, RevokeResponse),
        "SetAttribute" => op!(
            ttlv,
            kms,
            user,
            SetAttribute,
            set_attribute,
            SetAttributeResponse
        ),
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
