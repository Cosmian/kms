use std::str::FromStr;

use cosmian_kms_access::access::{CryptoOfficerConfig, Role, RoleDecision};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_operations::DiscoverVersions,
    kmip_2_1::{
        kmip_operations::{
            Activate, AddAttribute, Certify, Check, Create, CreateKeyPair, CreateSplitKey, Decrypt,
            DeleteAttribute, DeriveKey, Destroy, Encrypt, Export, Get, GetAttributeList,
            GetAttributes, GetConstraints, Hash, Import, Interop, JoinSplitKey, Locate, Log, Login,
            Logout, MAC, MACVerify, ModifyAttribute, Operation, PKCS11, Ping, PingResponse, Query,
            RNGRetrieve, RNGSeed, ReCertify, ReKey, ReKeyKeyPair, Register, Revoke, SetAttribute,
            SetConstraints, Sign, SignatureVerify, Validate,
        },
        kmip_types::OperationEnumeration,
    },
    ttlv::{TTLV, from_ttlv},
};

use crate::{
    core::{
        KMS,
        operations::{
            algorithm_policy::enforce_kmip_algorithm_policy_for_operation,
            attributes::get_attribute_list, check, mac::mac_verify,
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
}

/// Enforce role-based access control before dispatching a KMIP operation.
///
/// ## Design
///
/// Two enforcement layers work together:
///
/// 1. **Dispatch-level (this function)**: applies [`Role::decide`], which is exhaustive over
///    [`OperationEnumeration`], so no KMIP operation is allowed by omission. This refuses, e.g.,
///    `RNGSeed` for an `Operator` and requires the Create right for object-creating operations.
///
/// 2. **Handler-level ownership/grant checks** (`retrieve_object_for_operation`,
///    `user_has_permission`): even if dispatch allows the operation (e.g., `Get`), the user
///    must still own the object or hold an explicit per-object grant (unless `CryptoOfficer` is
///    active, which grants ownership bypass).
///
/// Users not listed in any role default to `Operator` when role enforcement is active
/// (fail-secure per NIST SP 800-57 Part 2 Rev 1 §4.8). Ceremony candidates may run
/// [`CryptoOfficerConfig::is_ceremony_prerequisite`] operations before activation.
///
/// # Errors
/// Returns [`KmsError::Unauthorized`] when the user's role does not permit the requested
/// operation.
pub(crate) async fn check_role_permission(
    kms: &KMS,
    user: &str,
    operation: OperationEnumeration,
    crypto_officer: &CryptoOfficerConfig,
) -> KResult<()> {
    // PKCS11 controls the server's shared HSM library and requires an explicit Crypto Officer.
    // (SetConstraints does not: the OASIS vectors, e.g. TC-MD-24-21, call it on a server without
    // roles; it is refused to Operators once roles are configured.)
    if operation == OperationEnumeration::PKCS11 && !crypto_officer.is_configured() {
        kms_bail!(KmsError::Unauthorized(
            "PKCS11 requires a configured Crypto Officer".to_owned()
        ));
    }

    // If no role lists are configured, skip role enforcement entirely.
    if !crypto_officer.is_configured() {
        return Ok(());
    }

    // Ceremony candidate exemption: users in crypto_officer.users can perform Create, Import,
    // SetAttribute, CreateSplitKey, and JoinSplitKey even before completing the ceremony. This
    // breaks the vicious circle where they need to create, mark, and split a master key before
    // they can complete the ceremony.
    // Security: only ceremony candidates (not arbitrary Operators) are exempt, and handler-level
    // ownership and per-object grants still apply. Full CO privileges (ownership bypass) still
    // require ceremony completion.
    let is_ceremony_candidate = crypto_officer.require_ceremony
        && crypto_officer.users.iter().any(|u| u == user)
        && CryptoOfficerConfig::is_ceremony_prerequisite(operation);

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

    match effective_role.decide(operation) {
        RoleDecision::Allow => Ok(()),
        RoleDecision::RequireCreatePermission => {
            kms.enforce_create_permission(&UserId::from(user)).await
        }
        RoleDecision::Deny => kms_bail!(KmsError::Unauthorized(format!(
            "User `{user}` (role: {effective_role:?}) is not authorized to perform operation \
             `{operation}`"
        ))),
    }
}

/// Dispatch operation depending on the TTLV tag
pub(crate) async fn dispatch(kms: &KMS, ttlv: TTLV, user: &UserId) -> KResult<Operation> {
    if let Some(ref metrics) = kms.metrics {
        let start = std::time::Instant::now();
        let operation_tag = ttlv.tag.clone();
        let result = Box::pin(dispatch_inner(kms, ttlv, user, &operation_tag)).await;
        let duration = start.elapsed().as_secs_f64();
        metrics.record_kmip_operation(&operation_tag, user);
        metrics.record_kmip_operation_duration(&operation_tag, duration);
        if result.is_err() {
            metrics.record_error(&operation_tag);
        }
        result
    } else {
        let operation_tag = ttlv.tag.clone();
        Box::pin(dispatch_inner(kms, ttlv, user, &operation_tag)).await
    }
}

/// Parse the root TTLV tag into the KMIP operation it names.
///
/// # Errors
/// [`KmsError::RouteNotFound`] when the tag is not a KMIP operation.
fn parse_operation(tag: &str) -> KResult<OperationEnumeration> {
    match tag {
        // TTLV clients send both spellings; the enumeration variant is `MAC`.
        "Mac" => Ok(OperationEnumeration::MAC),
        tag => OperationEnumeration::from_str(tag)
            .map_err(|_e| KmsError::RouteNotFound(format!("Operation: {tag}"))),
    }
}

async fn dispatch_inner(
    kms: &KMS,
    ttlv: TTLV,
    user: &UserId,
    operation_tag: &str,
) -> KResult<Operation> {
    use OperationEnumeration as Op;

    // Parse the wire tag once: the role check, the algorithm policy and the dispatch table
    // below all key on the KMIP operation enumeration.
    let operation = parse_operation(operation_tag)?;
    // Enforce role-based access control before any other check.
    check_role_permission(kms, user, operation, &kms.params.crypto_officer).await?;

    // For operations where the request carries algorithm choices, validate them
    // before executing any cryptographic action.  Skip entirely when no policy
    // is configured — avoids a function call + match on every dispatch.
    if kms.params.kmip_policy.policy_id.is_some() {
        enforce_kmip_algorithm_policy_for_operation(&kms.params, operation, &ttlv)?;
    }

    Ok(match operation {
        Op::Activate => op!(ttlv, kms, user, Activate, activate, ActivateResponse),
        Op::AddAttribute => op!(
            ttlv,
            kms,
            user,
            AddAttribute,
            add_attribute,
            AddAttributeResponse
        ),
        Op::Certify => op!(ttlv, kms, user, Certify, certify, CertifyResponse),
        Op::Check => {
            op!(fn ttlv, kms, user, Check, check, CheckResponse)
        }
        Op::Create => op!(ttlv, kms, user, Create, create, CreateResponse),
        Op::CreateKeyPair => {
            op!(
                ttlv,
                kms,
                user,
                CreateKeyPair,
                create_key_pair,
                CreateKeyPairResponse
            )
        }
        Op::CreateSplitKey => {
            op!(
                ttlv,
                kms,
                user,
                CreateSplitKey,
                create_split_key,
                CreateSplitKeyResponse
            )
        }
        Op::Decrypt => op!(ttlv, kms, user, Decrypt, decrypt, DecryptResponse),
        Op::DeleteAttribute => {
            op!(
                ttlv,
                kms,
                user,
                DeleteAttribute,
                delete_attribute,
                DeleteAttributeResponse
            )
        }
        Op::DeriveKey => op!(pin ttlv, kms, user, DeriveKey, derive_key, DeriveKeyResponse),
        Op::Destroy => op!(ttlv, kms, user, Destroy, destroy, DestroyResponse),
        Op::DiscoverVersions => {
            op!(infallible ttlv, kms, user, DiscoverVersions, discover_versions, DiscoverVersionsResponse)
        }
        Op::Encrypt => op!(ttlv, kms, user, Encrypt, encrypt, EncryptResponse),
        Op::Export => op!(boxed ttlv, kms, user, Export, export, ExportResponse),
        Op::Get => op!(ttlv, kms, user, Get, get, GetResponse),
        Op::GetAttributeList => {
            op!(pin_fn ttlv, kms, user, GetAttributeList, get_attribute_list, GetAttributeListResponse)
        }
        Op::GetAttributes => {
            op!(boxed ttlv, kms, user, GetAttributes, get_attributes, GetAttributesResponse)
        }
        Op::Hash => op!(ttlv, kms, user, Hash, hash, HashResponse),
        Op::RNGRetrieve => op!(
            ttlv,
            kms,
            user,
            RNGRetrieve,
            rng_retrieve,
            RNGRetrieveResponse
        ),
        Op::RNGSeed => op!(ttlv, kms, user, RNGSeed, rng_seed, RNGSeedResponse),
        Op::Import => op!(ttlv, kms, user, Import, import, ImportResponse),
        Op::Interop => {
            drop(from_ttlv::<Interop>(ttlv)?);
            super::message::process_interop_operation()?
        }
        Op::JoinSplitKey => {
            op!(
                ttlv,
                kms,
                user,
                JoinSplitKey,
                join_split_key,
                JoinSplitKeyResponse
            )
        }
        Op::Locate => op!(ttlv, kms, user, Locate, locate, LocateResponse),
        Op::Log => super::message::process_log_operation(from_ttlv::<Log>(ttlv)?, user)?,
        Op::Login => {
            Operation::LoginResponse(super::login::login(kms, &from_ttlv::<Login>(ttlv)?, user)?)
        }
        Op::Logout => Operation::LogoutResponse(super::login::logout(
            kms,
            &from_ttlv::<Logout>(ttlv)?,
            user,
        )?),
        Op::SetConstraints => Operation::SetConstraintsResponse(
            super::constraints::set_constraints(kms, from_ttlv::<SetConstraints>(ttlv)?, user)?,
        ),
        Op::GetConstraints => {
            // The payload is empty: decoding only validates it.
            from_ttlv::<GetConstraints>(ttlv)?;
            Operation::GetConstraintsResponse(super::constraints::get_constraints(kms))
        }
        Op::Ping => {
            // The payload is empty: decoding only validates it.
            from_ttlv::<Ping>(ttlv)?;
            Operation::PingResponse(PingResponse)
        }
        Op::MAC => op!(ttlv, kms, user, MAC, mac, MACResponse),
        Op::MACVerify => {
            op!(pin_fn ttlv, kms, user, MACVerify, mac_verify, MACVerifyResponse)
        }
        Op::PKCS11 => op!(ttlv, kms, user, PKCS11, pkcs11, PKCS11Response),
        Op::Query => {
            Operation::QueryResponse(Box::new(kms.query(from_ttlv::<Query>(ttlv)?).await?))
        }
        Op::ModifyAttribute => {
            op!(
                ttlv,
                kms,
                user,
                ModifyAttribute,
                modify_attribute,
                ModifyAttributeResponse
            )
        }
        Op::ReKey => op!(ttlv, kms, user, ReKey, rekey, ReKeyResponse),
        Op::ReKeyKeyPair => {
            op!(
                ttlv,
                kms,
                user,
                ReKeyKeyPair,
                rekey_keypair,
                ReKeyKeyPairResponse
            )
        }
        Op::ReCertify => {
            op!(ttlv, kms, user, ReCertify, recertify, ReCertifyResponse)
        }
        Op::Register => op!(ttlv, kms, user, Register, register, RegisterResponse),
        Op::Revoke => op!(ttlv, kms, user, Revoke, revoke, RevokeResponse),
        Op::SetAttribute => op!(
            ttlv,
            kms,
            user,
            SetAttribute,
            set_attribute,
            SetAttributeResponse
        ),
        Op::Sign => op!(ttlv, kms, user, Sign, sign, SignResponse),
        Op::SignatureVerify => {
            op!(
                ttlv,
                kms,
                user,
                SignatureVerify,
                signature_verify,
                SignatureVerifyResponse
            )
        }
        Op::Validate => op!(ttlv, kms, user, Validate, validate, ValidateResponse),
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    })
}

#[cfg(test)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::ttlv::to_ttlv;

    use super::*;
    use crate::tests::test_utils::{https_clap_config, test_kms, test_kms_with_config};

    #[test]
    fn parse_operation_accepts_both_mac_spellings_and_rejects_unknown_tags() {
        assert!(matches!(
            parse_operation("MAC"),
            Ok(OperationEnumeration::MAC)
        ));
        assert!(matches!(
            parse_operation("Mac"),
            Ok(OperationEnumeration::MAC)
        ));
        assert!(matches!(
            parse_operation("RNGSeed"),
            Ok(OperationEnumeration::RNGSeed)
        ));
        for tag in ["", "mac", "NoSuchOperation"] {
            assert!(
                matches!(parse_operation(tag), Err(KmsError::RouteNotFound(_))),
                "{tag:?}"
            );
        }
    }

    #[tokio::test]
    async fn dispatches_a_bare_log_request() -> KResult<()> {
        let kms = test_kms().await?;
        let response = dispatch(
            &kms,
            to_ttlv(&Log {
                log_message: Some("conformance test".to_owned()),
            })?,
            &UserId::from("dispatch-log@example.com"),
        )
        .await?;

        if !matches!(response, Operation::LogResponse(_)) {
            return Err(KmsError::Default(
                "expected a LogResponse for a bare Log request".to_owned(),
            ));
        }
        Ok(())
    }

    /// KMIP 2.1 §6.1.36: Ping answers with an empty `PingResponse` (runs in FIPS builds too).
    #[tokio::test]
    async fn dispatches_a_ping_request() -> KResult<()> {
        let kms = test_kms().await?;
        let response = dispatch(
            &kms,
            to_ttlv(&Ping)?,
            &UserId::from("dispatch-ping@example.com"),
        )
        .await?;
        if response != Operation::PingResponse(PingResponse) {
            return Err(KmsError::Default(
                "expected a PingResponse for a Ping request".to_owned(),
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn operator_can_manage_the_lifecycle_of_its_objects() -> KResult<()> {
        let mut config = https_clap_config();
        config.roles.crypto_officer_users = Some(vec!["officer@example.com".to_owned()]);
        let kms = test_kms_with_config(config).await?;
        for operation in [
            OperationEnumeration::Activate,
            OperationEnumeration::Revoke,
            OperationEnumeration::Destroy,
            OperationEnumeration::ReKey,
            OperationEnumeration::DeriveKey,
            OperationEnumeration::Certify,
            OperationEnumeration::ModifyAttribute,
            OperationEnumeration::JoinSplitKey,
        ] {
            check_role_permission(
                &kms,
                "operator@example.com",
                operation,
                &kms.params.crypto_officer,
            )
            .await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn operator_cannot_invoke_administrative_operations() -> KResult<()> {
        let mut config = https_clap_config();
        config.roles.crypto_officer_users = Some(vec!["officer@example.com".to_owned()]);
        let kms = test_kms_with_config(config).await?;
        let operator = UserId::from("operator@example.com");

        for operation in [
            OperationEnumeration::PKCS11,
            OperationEnumeration::SetConstraints,
            OperationEnumeration::RNGSeed,
        ] {
            let result = check_role_permission(
                &kms,
                operator.as_str(),
                operation,
                &kms.params.crypto_officer,
            )
            .await;
            if !matches!(result, Err(KmsError::Unauthorized(_))) {
                return Err(KmsError::Default(format!(
                    "Operator was permitted to invoke {operation}"
                )));
            }
        }

        check_role_permission(
            &kms,
            operator.as_str(),
            OperationEnumeration::Query,
            &kms.params.crypto_officer,
        )
        .await
    }

    #[tokio::test]
    async fn pkcs11_requires_a_configured_crypto_officer() -> KResult<()> {
        let kms = test_kms().await?;
        let result = check_role_permission(
            &kms,
            "unconfigured@example.com",
            OperationEnumeration::PKCS11,
            &kms.params.crypto_officer,
        )
        .await;

        if !matches!(result, Err(KmsError::Unauthorized(_))) {
            return Err(KmsError::Default(
                "PKCS11 was permitted without a configured Crypto Officer".to_owned(),
            ));
        }
        Ok(())
    }
}
