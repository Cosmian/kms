use cosmian_kms_access::access::{CryptoOfficerConfig, Role};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_operations::DiscoverVersions,
    kmip_2_1::{
        KmipOperation,
        kmip_operations::{
            Activate, AddAttribute, Certify, Check, Create, CreateKeyPair, CreateSplitKey, Decrypt,
            DeleteAttribute, DeriveKey, Destroy, Encrypt, Export, Get, GetAttributeList,
            GetAttributes, Hash, Import, JoinSplitKey, Locate, MAC, MACVerify, ModifyAttribute,
            Operation, Query, RNGRetrieve, RNGSeed, ReCertify, ReKey, ReKeyKeyPair, Register,
            Revoke, SetAttribute, Sign, SignatureVerify, Validate,
        },
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

/// Enforce role-based access control before dispatching a KMIP operation.
///
/// ## Design
///
/// This function enforces [`Role::allowed_operations()`] for all roles.
/// Two enforcement layers work together:
///
/// 1. **Dispatch-level (this function)**: blocks requests whose operation is not in the
///    role's `allowed_operations()` set. This prevents, e.g., an `Operator` from calling
///    `Get`/`Export` (key output is a Crypto Officer service per ISO/IEC 19790 §7.4).
///
/// 2. **Handler-level ownership/grant checks** (`retrieve_object_for_operation`,
///    `user_has_permission`): even if dispatch allows the operation (e.g., `Get` for a
///    `CryptoOfficer`), the user must still own the object or hold an explicit per-object
///    grant (unless `CryptoOfficer` is active, which grants ownership bypass).
///
/// Lifecycle operations without a [`KmipOperation`] mapping (`CreateKeyPair`, `Register`,
/// `ReKeyKeyPair`, `CreateSplitKey`) are additionally blocked for `Operator` users unless
/// they hold an explicit `Create` grant.
///
/// Users not listed in any role default to `Operator` when role enforcement is active
/// (fail-secure per NIST SP 800-57 Part 2 Rev 1 §4.8).
///
/// # Errors
/// Returns [`KmsError::Unauthorized`] when the user's role does not permit the requested
/// operation.
pub(crate) async fn check_role_permission(
    kms: &KMS,
    user: &str,
    operation_tag: &str,
    crypto_officer: &CryptoOfficerConfig,
) -> KResult<()> {
    // If no role lists are configured, skip role enforcement entirely.
    if !crypto_officer.is_configured() {
        return Ok(());
    }

    // Ceremony candidate exemption: users in crypto_officer.users can perform
    // Create, Import, CreateSplitKey, and JoinSplitKey even before completing
    // the ceremony. This breaks the vicious circle where they need to create
    // a master key and split it to complete the ceremony, but can't create
    // anything without being CO first.
    // Security: only ceremony candidates (not arbitrary Operators) are exempt,
    // and only for operations that are prerequisites for ceremony completion.
    // Full CO privileges (ownership bypass) still require ceremony completion.
    let is_ceremony_candidate = crypto_officer.require_ceremony
        && crypto_officer.users.iter().any(|u| u == user)
        && KmipOperation::is_ceremony_prerequisite_tag(operation_tag);

    if is_ceremony_candidate {
        return Ok(());
    }

    let mut effective_role = crypto_officer
        .role_for(user)
        // Fail-secure: unenrolled users default to Operator when roles are configured
        .unwrap_or(Role::Operator);

    // When the Crypto Officer ceremony is required, role_for() cannot determine CO status
    // from config alone. Check the database for a completed ceremony activation.
    if effective_role != Role::CryptoOfficer
        && crypto_officer.require_ceremony
        && crypto_officer.users.iter().any(|u| u == user)
    {
        match kms.database.is_crypto_officer_activated_by(user).await {
            Ok(true) => effective_role = Role::CryptoOfficer,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    "ceremony check DB error for user {user}: {e}; \
                     falling back to Operator role"
                );
            }
        }
    }

    match effective_role {
        Role::CryptoOfficer => {
            // CryptoOfficer: enforce allowed_operations(). Ownership bypass is handled
            // at handler level (retrieve_object_utils.rs / locate.rs).
            if let Some(kmip_op) = KmipOperation::from_tag(operation_tag) {
                let allowed = Role::CryptoOfficer.allowed_operations();
                if !allowed.contains(&kmip_op) {
                    kms_bail!(KmsError::Unauthorized(format!(
                        "User `{user}` (role: CryptoOfficer) is not authorized to perform \
                         operation `{operation_tag}` (not in CryptoOfficer allowed operations)"
                    )))
                }
                return Ok(());
            }
            // Lifecycle operations without a KmipOperation mapping
            // (CreateKeyPair, Register, ReKeyKeyPair, CreateSplitKey, JoinSplitKey):
            // route through enforce_create_permission, which handles default_username,
            // CO-user membership, ceremony-candidate exemption, and explicit Create grants.
            // COs always satisfy this gate (they are listed in crypto_officer.users),
            // making this equivalent to an unconditional allow — but the explicit call
            // ensures consistent audit and error paths instead of a silent fall-through.
            if KmipOperation::is_restricted_lifecycle_tag(operation_tag)
                || operation_tag == "JoinSplitKey"
            {
                return kms.enforce_create_permission(&UserId::from(user)).await;
            }
            Ok(())
        }
        Role::Operator => {
            // Enforce allowed_operations() for Operator at dispatch.
            if let Some(kmip_op) = KmipOperation::from_tag(operation_tag) {
                let allowed = Role::Operator.allowed_operations();
                if !allowed.contains(&kmip_op) {
                    // Lifecycle operations (Create, Import): delegate to enforce_create_permission
                    // which correctly handles default_username, CO-user membership, and explicit grants.
                    if matches!(kmip_op, KmipOperation::Create | KmipOperation::Import) {
                        return kms.enforce_create_permission(&UserId::from(user)).await;
                    }
                    // Per-object operations (Get, Export, Activate, Revoke, Destroy, etc.)
                    // are not blocked at dispatch — they rely on handler-level ownership/grant checks.
                    return Ok(());
                }
                return Ok(());
            }

            // Lifecycle operations without KmipOperation mapping (CreateKeyPair, Register,
            // ReKeyKeyPair, CreateSplitKey): delegate to enforce_create_permission which
            // handles default_username, CO-user membership, and explicit grants.
            if KmipOperation::is_restricted_lifecycle_tag(operation_tag) {
                return kms.enforce_create_permission(&UserId::from(user)).await;
            }
            Ok(())
        }
    }
}

/// Dispatch operation depending on the TTLV tag
pub(crate) async fn dispatch(kms: &KMS, ttlv: TTLV, user: &UserId) -> KResult<Operation> {
    let operation_tag = ttlv.tag.clone();

    if let Some(ref metrics) = kms.metrics {
        let start = std::time::Instant::now();
        let result = Box::pin(dispatch_inner(kms, ttlv, user, &operation_tag)).await;
        let duration = start.elapsed().as_secs_f64();
        metrics.record_kmip_operation(&operation_tag, user);
        metrics.record_kmip_operation_duration(&operation_tag, duration);
        if result.is_err() {
            metrics.record_error(&operation_tag);
        }
        result
    } else {
        Box::pin(dispatch_inner(kms, ttlv, user, &operation_tag)).await
    }
}

async fn dispatch_inner(
    kms: &KMS,
    ttlv: TTLV,
    user: &UserId,
    operation_tag: &str,
) -> KResult<Operation> {
    // Enforce role-based access control before any other check.
    check_role_permission(kms, user, operation_tag, &kms.params.crypto_officer).await?;

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
        "CreateSplitKey" => {
            op!(
                ttlv,
                kms,
                user,
                CreateSplitKey,
                create_split_key,
                CreateSplitKeyResponse
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
        "JoinSplitKey" => {
            op!(
                ttlv,
                kms,
                user,
                JoinSplitKey,
                join_split_key,
                JoinSplitKeyResponse
            )
        }
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
