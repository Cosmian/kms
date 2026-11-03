//! CRL generation operation.
//!
//! Generates an X.509 v2 CRL for a given CA certificate, listing all
//! certificates that have been revoked (state Deactivated or Compromised),
//! whose `CertificateLink` attribute points to the issuer and that the issuer
//! actually issued (see [`find_ca_issued_certificates`]).

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock, atomic::Ordering},
    time::Instant,
};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReasonCode, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::{Certificate, Object, ObjectType},
            kmip_types::{LinkType, LinkedObjectIdentifier},
        },
    },
    cosmian_kms_crypto::openssl::crl::{CrlReasonCode, RevokedEntry, build_crl},
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, trace, warn};
use openssl::{
    bn::BigNum,
    x509::{X509, X509Crl},
};
use time::OffsetDateTime;

use crate::{
    core::{
        KMS, ObjectHandle,
        certificate::{
            find_ca_issued_certificates,
            oracle_signing::{placeholder_signing_key, sign_crl_with_oracle},
        },
        operations::certify::{IssuerKey, load_issuer_key},
        retrieve_object_utils::retrieve_object_for_operation,
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// In-memory cache of the most recently generated CRL per issuer.
///
/// The public CRL endpoint (`GET /public/certificates/{id}/crl`) reads from
/// this cache so it can serve pre-signed bytes without requiring any
/// authentication or access to key material.
///
/// The cache is populated every time the authenticated endpoint calls
/// `generate_crl()`. It is lost on server restart; once the CA owner
/// re-generates a CRL (or the first post-startup `Revoke` triggers
/// auto-regeneration) the public endpoint becomes available again.
///
/// Map: `issuer_certificate_id` → `(der_bytes, generated_at, next_update_iso8601, cached_at)`
type CrlCacheInner = HashMap<String, (Vec<u8>, Instant, String, Instant)>;

/// How long a node may serve its in-memory CRL copy before re-reading the DB.
///
/// The DB `crls` table is shared by all nodes of a cluster, while this cache is
/// per-process: without a bound, a node that did not regenerate the CRL itself kept
/// serving its stale copy (missing new revocations, even past its nextUpdate).
const CRL_MEMORY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
static GENERATED_CRL_CACHE: LazyLock<tokio::sync::RwLock<CrlCacheInner>> =
    LazyLock::new(|| tokio::sync::RwLock::new(HashMap::new()));

/// Retrieve the most recently cached CRL DER bytes for an issuer.
///
/// Called by the public CRL endpoint (`GET /public/certificates/{issuer_id}/crl`).
///
/// **Cache strategy** (two-level):
/// 1. In-memory `GENERATED_CRL_CACHE` — fast path, populated on every `generate_crl` call.
/// 2. Database `crls` table — warm the cache on cold start (server restart) so the CDP
///    endpoint can immediately serve the last signed CRL without requiring a manual
///    `generate-crl` call.
///
/// Returns `None` only when no CRL has ever been generated for this issuer (neither
/// in the current process nor persisted to the DB).
///
/// Returns `Some((der_bytes, generated_at_instant, next_update_iso8601))`.
pub(crate) async fn get_cached_crl(
    issuer_id: &str,
    kms: &KMS,
) -> Option<(Vec<u8>, Instant, String)> {
    // 1. Fast path: recent in-memory cache hit.
    let cached = GENERATED_CRL_CACHE.read().await.get(issuer_id).cloned();
    if let Some((der, generated_at, next_update, cached_at)) = &cached {
        if cached_at.elapsed() < CRL_MEMORY_CACHE_TTL {
            return Some((der.clone(), *generated_at, next_update.clone()));
        }
    }

    // 2. Cold start or stale entry: (re)load from the DB `crls` table, which another
    //    node may have updated.
    let db_result = kms.database.get_crl(issuer_id).await;
    match db_result {
        Ok(Some((der, next_update))) => {
            // Keep the original `generated_at` when the DB still holds the same CRL,
            // otherwise use Instant::now() as a conservative Last-Modified approximation.
            let generated_at = cached
                .as_ref()
                .filter(|(cached_der, ..)| *cached_der == der)
                .map_or_else(Instant::now, |(_, generated_at, ..)| *generated_at);
            GENERATED_CRL_CACHE.write().await.insert(
                issuer_id.to_owned(),
                (
                    der.clone(),
                    generated_at,
                    next_update.clone(),
                    Instant::now(),
                ),
            );
            Some((der, generated_at, next_update))
        }
        Ok(None) => None,
        Err(e) => {
            // DB error: fall back to the (stale) in-memory copy, else 404 rather than 500.
            cosmian_logger::warn!(
                issuer_id = issuer_id,
                "Failed to load CRL from database for issuer '{issuer_id}': {e}"
            );
            cached.map(|(der, generated_at, next_update, _)| (der, generated_at, next_update))
        }
    }
}

/// Who asks for a CRL: an authenticated user, or the server itself (post-Revoke / refresh
/// cron). Both are access-checked on the signing key; they differ only in who is checked and
/// in how the issuer certificate is read.
#[derive(Clone, Copy)]
pub(crate) enum CrlRequester<'a> {
    User(&'a UserId),
    Server,
}

/// Regenerate the CRL of `issuer_certificate_id` on behalf of the server.
///
/// Used by automatic regeneration (post-Revoke and the refresh cron). Those run as
/// identities — the revoking leaf owner, or `default_username` — that usually have no access
/// to the CA, so regeneration failed silently and the published CRL went stale or expired.
/// The issuer certificate is public and read directly; the signing key is authorized as the
/// issuer certificate's owner, never as the caller, so a copy of someone else's CA certificate
/// cannot be used to make the server sign with that CA's key.
pub(crate) async fn regenerate_crl(kms: &KMS, issuer_certificate_id: &str) -> KResult<X509Crl> {
    Box::pin(generate_crl(
        kms,
        issuer_certificate_id,
        None,
        CrlRequester::Server,
    ))
    .await
}

/// Retrieve the issuer certificate: ACL-checked for a user, read directly (but not destroyed)
/// for the server, since a certificate is public information.
async fn retrieve_issuer_certificate(
    kms: &KMS,
    uid: &str,
    requester: CrlRequester<'_>,
) -> KResult<Arc<ObjectWithMetadata>> {
    match requester {
        CrlRequester::User(user) => {
            retrieve_object_for_operation(ObjectHandle::Uid(uid), KmipOperation::Get, kms, user)
                .await
        }
        CrlRequester::Server => kms
            .database
            .retrieve_object_arc(uid)
            .await?
            .filter(|owm| !matches!(owm.state(), State::Destroyed | State::Destroyed_Compromised))
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!("CRL generation: object '{uid}' not found"))
            }),
    }
}

/// Generate a CRL for the given issuer certificate.
///
/// # Arguments
/// * `kms` — KMS instance
/// * `issuer_certificate_id` — UID of the CA certificate
/// * `validity_days` — Optional override for the CRL validity period (default: 7 days)
/// * `requester` — Authenticated user performing the operation, or the server itself
///
/// # Returns
/// The signed `X509Crl` (can be serialized to DER or PEM by the caller).
///
/// # Authorization
///
/// CRL content is **public information** by definition (RFC 5280 §3): any relying
/// party must be able to verify whether a certificate has been revoked.  There is no
/// private data in a CRL.  Accordingly, no special role (Crypto Officer or otherwise)
/// is required to generate one — any authenticated user who can read the CA
/// certificate may request its CRL.
///
/// `find_all` is used internally to collect revoked certificates across all owners.
/// This is correct and intentional: a CA's CRL must list *every* revoked certificate
/// it issued, regardless of who owns the DB record.
pub(crate) async fn generate_crl(
    kms: &KMS,
    issuer_certificate_id: &str,
    validity_days: Option<u32>,
    requester: CrlRequester<'_>,
) -> KResult<X509Crl> {
    debug!(
        "Generating CRL for issuer certificate: {}",
        issuer_certificate_id
    );

    let issuer_owm = retrieve_issuer_certificate(kms, issuer_certificate_id, requester)
        .await
        .context("CRL generation: retrieving issuer certificate")?;

    let issuer_cert_der = match issuer_owm.object() {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => certificate_value.as_slice(),
        _ => {
            kms_bail!(KmsError::InvalidRequest(format!(
                "Object '{issuer_certificate_id}' is not a certificate"
            )));
        }
    };

    let issuer_x509 = X509::from_der(issuer_cert_der).map_err(|e| {
        KmsError::InvalidRequest(format!("Failed to parse issuer certificate DER: {e}"))
    })?;

    // Enforce RFC 5280 §4.2.1.3: if the issuer certificate carries a keyUsage extension,
    // the cRLSign bit MUST be set.  OpenSSL's X509_CRL_sign() does not check this itself —
    // it is the application's responsibility.  A CA without cRLSign produces a CRL that
    // RFC-conforming relying parties will reject during path validation.
    {
        use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};
        let Ok((_, parsed)) = X509Certificate::from_der(issuer_cert_der) else {
            kms_bail!(KmsError::InvalidRequest(format!(
                "Failed to parse issuer certificate '{issuer_certificate_id}' for keyUsage check"
            )));
        };
        if let Some(ku) = parsed.iter_extensions().find_map(|ext| {
            if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                Some(ku)
            } else {
                None
            }
        }) {
            if !ku.crl_sign() {
                kms_bail!(KmsError::InvalidRequest(format!(
                    "Issuer certificate '{issuer_certificate_id}' does not have the \
                     cRLSign bit set in its keyUsage extension (RFC 5280 §4.2.1.3). \
                     CRL signing requires this bit."
                )));
            }
        }
    }

    // 2. Retrieve the issuer private key (via PrivateKeyLink on the certificate)
    let issuer_private_key_id = issuer_owm
        .attributes()
        .get_link(LinkType::PrivateKeyLink)
        .ok_or_else(|| {
            KmsError::InvalidRequest(format!(
                "Issuer certificate '{issuer_certificate_id}' has no PrivateKeyLink attribute"
            ))
        })?
        .to_string();

    // The signing key is always access-checked: as the requesting user, or, for a
    // server-triggered CRL, as the issuer certificate's owner. The `PrivateKeyLink` of an
    // imported certificate is user-controlled, so the server must never sign on its behalf
    // with a key that its owner cannot use (this also applies to `hsm::` keys).
    // HSM grants are per operation and the oracle never exports the key: signing needs the
    // `Certify` grant (as for issuing certificates), not `Get`/`Export`. Database keys keep `Get`.
    let key_user = match requester {
        CrlRequester::User(user) => user,
        CrlRequester::Server => issuer_owm.owner_id(),
    };
    let key_operation = if ObjectHandle::from(issuer_private_key_id.as_str()).is_hsm() {
        KmipOperation::Certify
    } else {
        KmipOperation::Get
    };
    let issuer_key_owm = retrieve_object_for_operation(
        ObjectHandle::Uid(&issuer_private_key_id),
        key_operation,
        kms,
        key_user,
    )
    .await
    .context("CRL generation: retrieving issuer private key")?;

    // HSM keys are never loaded: the HSM signs through the crypto oracle. Database keys may be
    // wrapped at rest (server `key_encryption_key` or a user KEK); `retrieve_object_for_operation`
    // only unwraps for `default_unwrap_types`.
    let issuer_key = Box::pin(load_issuer_key(
        kms,
        &issuer_key_owm,
        issuer_x509.public_key()?,
        key_user,
    ))
    .await
    .context("CRL generation: loading issuer private key")?;

    // 3. Find all certificates signed by this issuer that are revoked
    let revoked_entries =
        Box::pin(find_revoked_certificates(kms, &issuer_owm, &issuer_x509)).await?;

    trace!(
        "Found {} revoked certificate(s) for issuer '{}'",
        revoked_entries.len(),
        issuer_certificate_id
    );

    // 4. Assign a monotonically increasing CRL number (RFC 5280 §5.2.3).
    // The counter is seeded at startup from max(unix_timestamp, db_max + 1) to
    // ensure CRL Numbers are strictly greater than any previously issued number
    // across server restarts.  fetch_add ensures uniqueness within a single run.
    let crl_number = kms.crl_counter.fetch_add(1, Ordering::Relaxed);

    // 5. Build and sign the CRL
    // Priority: explicit caller override → server-configured default (`crl_default_validity_days`).
    let validity = validity_days
        .unwrap_or(kms.params.crl_default_validity_days)
        .max(1); // guard against misconfiguration producing a 0-day CRL
    let crl = match &issuer_key {
        IssuerKey::Local(key) => {
            build_crl(&issuer_x509, key, &revoked_entries, crl_number, validity)
                .map_err(|e| KmsError::ServerError(format!("Failed to build CRL: {e}")))?
        }
        IssuerKey::Oracle(key) => {
            // HSM key: build with a throwaway key, then have the HSM sign the real TBS bytes.
            let placeholder = placeholder_signing_key()?;
            let draft = build_crl(
                &issuer_x509,
                &placeholder,
                &revoked_entries,
                crl_number,
                validity,
            )
            .map_err(|e| KmsError::ServerError(format!("Failed to build CRL: {e}")))?;
            Box::pin(sign_crl_with_oracle(kms, key, &draft)).await?
        }
    };

    debug!(
        "CRL generated successfully for issuer '{}': {} entries, validity {} days",
        issuer_certificate_id,
        revoked_entries.len(),
        validity
    );

    // Cache the DER bytes so the public endpoint can serve them without key access.
    let crl_der = crl
        .to_der()
        .map_err(|e| KmsError::ServerError(format!("Failed to DER-encode CRL for cache: {e}")))?;

    // Compute next_update timestamp for DB storage (validity_days from now).
    let generated_at = OffsetDateTime::now_utc();
    let next_update = generated_at + time::Duration::days(i64::from(validity));
    let generated_at_str = generated_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| {
            KmsError::ServerError(format!("Failed to format CRL generated_at timestamp: {e}"))
        })?;
    let next_update_str = next_update
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| {
            KmsError::ServerError(format!("Failed to format CRL next_update timestamp: {e}"))
        })?;

    // Persist to DB so the public CDP endpoint survives server restarts.
    if let Err(e) = kms
        .database
        .upsert_crl(
            issuer_certificate_id,
            &crl_der,
            crl_number,
            &generated_at_str,
            &next_update_str,
        )
        .await
    {
        // DB errors must not fail CRL generation — the in-memory cache still works.
        warn!(
            issuer_id = issuer_certificate_id,
            "Failed to persist CRL to database for issuer '{issuer_certificate_id}': {e}"
        );
    }

    {
        let mut cache = GENERATED_CRL_CACHE.write().await;
        cache.insert(
            issuer_certificate_id.to_owned(),
            (crl_der, Instant::now(), next_update_str, Instant::now()),
        );
    }

    Ok(crl)
}

/// `true` when a certificate in `state` with these `attributes` is revoked: listed on the CRL,
/// `revoked` for OCSP. A certificate destroyed without ever being revoked is not revoked.
pub(crate) const fn is_revoked(state: State, attributes: &Attributes) -> bool {
    match state {
        State::Deactivated | State::Compromised | State::Destroyed_Compromised => true,
        State::Destroyed => attributes.revocation_reason.is_some(),
        State::Active | State::PreActive => false,
    }
}

/// Find all certificates issued by `issuer` that are in a revoked state, one entry per serial.
///
/// Uses `find_all` (bypasses user ownership filters) so that the CRL contains every
/// revoked certificate regardless of which user owns it in the KMS database; only the
/// certificates the issuer really issued count (see [`find_ca_issued_certificates`]).
///
/// Returns a list of `RevokedEntry` structs ready for CRL generation.
async fn find_revoked_certificates(
    kms: &KMS,
    issuer: &ObjectWithMetadata,
    issuer_x509: &X509,
) -> KResult<Vec<RevokedEntry>> {
    // First the serials of the revoked certificates linked to the issuer, then every record of
    // these serials: an authoritative active record outweighs a revoked copy.
    // Destroyed certificates must stay listed (RFC 5280 §3.3: until they expire):
    // Destroy keeps the issuer link and revocation details for exactly this purpose.
    let mut search_attrs = Attributes {
        object_type: Some(ObjectType::Certificate),
        ..Attributes::default()
    };
    search_attrs.set_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(issuer.id().to_owned()),
    );
    let mut serials = HashSet::new();
    for state in [
        State::Deactivated,
        State::Compromised,
        State::Destroyed,
        State::Destroyed_Compromised,
    ] {
        let results = kms
            .database
            .find_all(Some(&search_attrs), Some(state), kms.vendor_id())
            .await
            .context("CRL generation: searching for revoked certificates")?;
        for (uid, _state, attributes) in results {
            if !is_revoked(state, &attributes) {
                continue;
            }
            let Some(owm) = kms.database.retrieve_object_arc(&uid).await? else {
                continue;
            };
            let Object::Certificate(Certificate {
                certificate_value, ..
            }) = owm.object()
            else {
                continue;
            };
            if let Ok(serial) = X509::from_der(certificate_value)
                .and_then(|x509| x509.serial_number().to_bn())
                .and_then(|bn| bn.to_hex_str().map(|hex| hex.to_ascii_uppercase()))
            {
                serials.insert(serial);
            }
        }
    }

    let mut entries = Vec::new();
    for (serial, records) in Box::pin(find_ca_issued_certificates(
        kms,
        issuer,
        issuer_x509,
        &serials,
    ))
    .await?
    {
        // One entry per serial: the earliest revocation among the records that count.
        let Some((_, _, attributes)) = records
            .iter()
            .filter(|(_, state, attributes)| is_revoked(*state, attributes))
            .min_by_key(|(_, _, attributes)| attributes.deactivation_date)
        else {
            continue;
        };
        let serial_number = BigNum::from_hex_str(&serial)
            .map_err(|e| {
                KmsError::ServerError(format!("Failed to decode serial number {serial}: {e}"))
            })?
            .to_vec();
        entries.push(RevokedEntry {
            serial_number,
            // Determine revocation date (deactivation_date from attributes)
            revocation_date: attributes
                .deactivation_date
                .unwrap_or_else(OffsetDateTime::now_utc),
            // Map KMIP RevocationReasonCode to CRL reason code
            reason_code: attributes
                .revocation_reason
                .as_ref()
                .map(|r| kmip_reason_to_crl_reason(r.revocation_reason_code)),
            // Invalidity date = compromise_occurrence_date (RFC 5280 §5.3.2)
            invalidity_date: attributes.compromise_occurrence_date,
        });
    }

    Ok(entries)
}

/// Map a KMIP `RevocationReasonCode` to the corresponding RFC 5280 CRL reason code.
///
/// The three extension codes (`CertificateHold`, `RemoveFromCRL`, `AaCompromise`) are
/// KMIP vendor extensions (values in the `8XXXXXXX` range) that correspond to the RFC 5280
/// §5.3.1 reason values 6, 8, and 10 respectively.
///
/// **`RemoveFromCRL` (8) is intentionally mapped to `Unspecified`.**
/// RFC 5280 §5.3.1 requires that `removeFromCRL` "may only appear in delta CRLs".
/// The KMS generates only complete (non-delta) CRLs; including reason code 8 in a
/// complete CRL would violate that requirement.  `RemoveFromCRL` indicates a
/// "remove from hold" event which has no meaningful representation in a complete CRL
/// (hold state is not tracked between complete CRL issuances). Using `Unspecified`
/// causes the `reasonCode` extension to be omitted entirely per §5.3.1 ("SHOULD be
/// absent instead of using the unspecified (0) reasonCode value").
pub(crate) const fn kmip_reason_to_crl_reason(reason: RevocationReasonCode) -> CrlReasonCode {
    match reason {
        // RFC 5280 §5.3.1: removeFromCRL (8) MUST only appear in delta CRLs.
        // The KMS generates only complete CRLs; map to Unspecified so the reasonCode
        // extension is omitted rather than emitting a standard-violating value.
        RevocationReasonCode::Unspecified | RevocationReasonCode::RemoveFromCRL => {
            CrlReasonCode::Unspecified
        }
        RevocationReasonCode::KeyCompromise => CrlReasonCode::KeyCompromise,
        RevocationReasonCode::CACompromise => CrlReasonCode::CaCompromise,
        RevocationReasonCode::AffiliationChanged => CrlReasonCode::AffiliationChanged,
        RevocationReasonCode::Superseded => CrlReasonCode::Superseded,
        RevocationReasonCode::CessationOfOperation => CrlReasonCode::CessationOfOperation,
        RevocationReasonCode::PrivilegeWithdrawn => CrlReasonCode::PrivilegeWithdrawn,
        // RFC 5280 §5.3.1 codes absent from the KMIP standard set, mapped via extensions.
        RevocationReasonCode::CertificateHold => CrlReasonCode::CertificateHold,
        RevocationReasonCode::AaCompromise => CrlReasonCode::AaCompromise,
    }
}
