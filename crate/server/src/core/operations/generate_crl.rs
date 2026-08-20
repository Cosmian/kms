//! CRL generation operation.
//!
//! Generates an X.509 v2 CRL for a given CA certificate, listing all
//! certificates that have been revoked (state Deactivated or Compromised)
//! and whose `CertificateLink` attribute points to the issuer.

use std::{
    collections::HashMap,
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReasonCode, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::{Certificate, Object, ObjectType},
            kmip_types::{Link, LinkType, LinkedObjectIdentifier},
        },
    },
    cosmian_kms_crypto::openssl::{
        crl::{CrlReasonCode, RevokedEntry, build_crl},
        kmip_private_key_to_openssl,
    },
};
use cosmian_logger::{debug, error, trace, warn};
use openssl::x509::{X509, X509Crl};
use time::OffsetDateTime;

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
/// Map: `issuer_certificate_id` → `(der_bytes, generated_at, next_update_iso8601)`
type CrlCacheInner = HashMap<String, (Vec<u8>, Instant, String)>;
static GENERATED_CRL_CACHE: LazyLock<tokio::sync::RwLock<CrlCacheInner>> =
    LazyLock::new(|| tokio::sync::RwLock::new(HashMap::new()));

/// Monotonically increasing CRL sequence counter.
///
/// Initialized to the current unix timestamp on first use so that CRL Numbers
/// remain unique across server restarts (RFC 5280 §5.2.3 requires monotonic
/// increase). The `fetch_add` guarantees uniqueness even when two CRLs are
/// generated within the same second.
static CRL_SEQUENCE_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| {
    let base = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(1);
    AtomicU64::new(base)
});

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
    // 1. Fast path: in-memory cache hit.
    let cached = GENERATED_CRL_CACHE.read().await.get(issuer_id).cloned();
    if let Some(entry) = cached {
        return Some(entry);
    }

    // 2. Cold-start: try loading from the DB `crls` table.
    let db_result = kms.database.get_crl(issuer_id).await;
    match db_result {
        Ok(Some((der, next_update))) => {
            // Warm the in-memory cache; use Instant::now() as a conservative
            // `generated_at` approximation for the Last-Modified header.
            let entry = (der.clone(), Instant::now(), next_update);
            GENERATED_CRL_CACHE
                .write()
                .await
                .insert(issuer_id.to_owned(), entry.clone());
            Some(entry)
        }
        Ok(None) => None,
        Err(e) => {
            // DB error: log and return None so the endpoint returns 404 rather than 500.
            cosmian_logger::warn!(
                issuer_id = issuer_id,
                "Failed to load CRL from database for issuer '{issuer_id}': {e}"
            );
            None
        }
    }
}

use crate::{
    core::{KMS, ObjectHandle, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};
/// Generate a CRL for the given issuer certificate.
///
/// # Arguments
/// * `kms` — KMS instance
/// * `issuer_certificate_id` — UID of the CA certificate
/// * `validity_days` — Optional override for the CRL validity period (default: 7 days)
/// * `user` — Authenticated user performing the operation
///
/// # Returns
/// The signed `X509Crl` (can be serialized to DER or PEM by the caller).
///
/// # Authorization
///
/// When `crypto_officer_users` is configured, only an active Crypto Officer may
/// generate a CRL.  This is required because CRL generation must enumerate **all**
/// revoked certificates regardless of ownership (`find_all` bypasses user filters).
/// The CO access is logged at ERROR level for the audit trail.
pub(crate) async fn generate_crl(
    kms: &KMS,
    issuer_certificate_id: &str,
    validity_days: Option<u32>,
    user: &UserId,
) -> KResult<X509Crl> {
    debug!(
        "Generating CRL for issuer certificate: {}",
        issuer_certificate_id
    );

    // Guard: when CO users are configured, only an active CO may call this.
    // CRL generation uses find_all (no user filter) — the CO role is the
    // documented gating condition for that bypass (same as Locate with CO).
    if !kms.params.crypto_officer.users.is_empty() && !kms.is_crypto_officer(user).await? {
        return Err(KmsError::Unauthorized(format!(
            "Generating a CRL requires the Crypto Officer role. \
             User '{user}' is not an active Crypto Officer."
        )));
    }
    if !kms.params.crypto_officer.users.is_empty() {
        // Audit log — CO bypass is a high-value security event.
        error!(
            target: "audit",
            user = %user,
            issuer_id = issuer_certificate_id,
            "CRYPTO_OFFICER_ACCESS: crypto officer generating CRL (find_all bypass)",
        );
    }

    // 1. Retrieve the issuer certificate
    let issuer_owm = retrieve_object_for_operation(
        ObjectHandle::Uid(issuer_certificate_id),
        KmipOperation::Get,
        kms,
        user,
    )
    .await
    .context("CRL generation: retrieving issuer certificate")?;

    let issuer_cert_der = match issuer_owm.object() {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => certificate_value.clone(),
        _ => {
            kms_bail!(KmsError::InvalidRequest(format!(
                "Object '{issuer_certificate_id}' is not a certificate"
            )));
        }
    };

    let issuer_x509 = X509::from_der(&issuer_cert_der).map_err(|e| {
        KmsError::InvalidRequest(format!("Failed to parse issuer certificate DER: {e}"))
    })?;

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

    let issuer_key_owm = retrieve_object_for_operation(
        ObjectHandle::Uid(&issuer_private_key_id),
        KmipOperation::Get,
        kms,
        user,
    )
    .await
    .context("CRL generation: retrieving issuer private key")?;

    let issuer_pkey = kmip_private_key_to_openssl(issuer_key_owm.object()).map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to convert issuer private key to OpenSSL: {e}"
        ))
    })?;

    // 3. Find all certificates signed by this issuer that are revoked
    let revoked_entries = Box::pin(find_revoked_certificates(kms, issuer_certificate_id)).await?;

    trace!(
        "Found {} revoked certificate(s) for issuer '{}'",
        revoked_entries.len(),
        issuer_certificate_id
    );

    // 4. Assign a monotonically increasing CRL number (RFC 5280 §5.2.3).
    // Using an atomic counter seeded from the unix timestamp avoids duplicate
    // CRL Numbers when two CRLs are generated within the same second.
    let crl_number = CRL_SEQUENCE_COUNTER.fetch_add(1, Ordering::Relaxed);

    // 5. Build and sign the CRL
    // Priority: explicit caller override → server-configured default (`crl_default_validity_days`).
    let validity = validity_days
        .unwrap_or(kms.params.crl_default_validity_days)
        .max(1); // guard against misconfiguration producing a 0-day CRL
    let crl = build_crl(
        &issuer_x509,
        &issuer_pkey,
        &revoked_entries,
        crl_number,
        validity,
    )
    .map_err(|e| KmsError::ServerError(format!("Failed to build CRL: {e}")))?;

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
        .unwrap_or_default();
    let next_update_str = next_update
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

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
            (crl_der, Instant::now(), next_update_str),
        );
    }

    Ok(crl)
}

/// Find all certificates issued by `issuer_certificate_id` that are in a revoked state.
///
/// Uses `find_all` (bypasses user ownership filters) so that the CRL contains every
/// revoked certificate regardless of which user owns it in the KMS database.  The
/// caller is responsible for ensuring the requesting user holds the Crypto Officer role
/// before invoking this function (enforced by `generate_crl`).
///
/// Returns a list of `RevokedEntry` structs ready for CRL generation.
async fn find_revoked_certificates(
    kms: &KMS,
    issuer_certificate_id: &str,
) -> KResult<Vec<RevokedEntry>> {
    let mut entries = Vec::new();

    // Search for certificates with CertificateLink pointing to this issuer
    // in both Deactivated and Compromised states.
    for state in [State::Deactivated, State::Compromised] {
        let search_attrs = Attributes {
            object_type: Some(ObjectType::Certificate),
            link: Some(vec![Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    issuer_certificate_id.to_owned(),
                ),
            }]),
            ..Attributes::default()
        };

        // Use find_all to bypass user ownership filters — the CRL must include
        // every revoked certificate issued by this CA, regardless of who owns it.
        let results = kms
            .database
            .find_all(Some(&search_attrs), Some(state), kms.vendor_id())
            .await
            .context("CRL generation: searching for revoked certificates")?;

        for (uid, _state, attributes) in results {
            // Retrieve the actual certificate to extract serial number
            let Some(owm) = kms.database.retrieve_object(&uid).await? else {
                continue;
            };

            let Object::Certificate(Certificate {
                certificate_value: cert_der,
                ..
            }) = owm.object()
            else {
                continue;
            };

            let x509 = match X509::from_der(cert_der) {
                Ok(x509) => x509,
                Err(e) => {
                    trace!("Skipping certificate '{}': cannot parse DER: {e}", uid);
                    continue;
                }
            };

            // Extract serial number as big-endian bytes
            let serial_bytes = x509
                .serial_number()
                .to_bn()
                .map_err(|e| {
                    KmsError::ServerError(format!(
                        "Failed to extract serial number from certificate '{uid}': {e}"
                    ))
                })?
                .to_vec();

            // Determine revocation date (deactivation_date from attributes)
            let revocation_date = attributes
                .deactivation_date
                .unwrap_or_else(OffsetDateTime::now_utc);

            // Map KMIP RevocationReasonCode to CRL reason code
            let reason_code = attributes
                .revocation_reason
                .as_ref()
                .map(|r| kmip_reason_to_crl_reason(r.revocation_reason_code));

            // Invalidity date = compromise_occurrence_date (RFC 5280 §5.3.2)
            let invalidity_date = attributes.compromise_occurrence_date;

            entries.push(RevokedEntry {
                serial_number: serial_bytes,
                revocation_date,
                reason_code,
                invalidity_date,
            });
        }
    }

    Ok(entries)
}

/// Map a KMIP `RevocationReasonCode` to the corresponding RFC 5280 CRL reason code.
///
/// The three extension codes (`CertificateHold`, `RemoveFromCRL`, `AaCompromise`) are
/// KMIP vendor extensions (values in the `8XXXXXXX` range) that map to the RFC 5280
/// §5.3.1 reason values 6, 8, and 10 respectively.
const fn kmip_reason_to_crl_reason(reason: RevocationReasonCode) -> CrlReasonCode {
    match reason {
        RevocationReasonCode::Unspecified => CrlReasonCode::Unspecified,
        RevocationReasonCode::KeyCompromise => CrlReasonCode::KeyCompromise,
        RevocationReasonCode::CACompromise => CrlReasonCode::CaCompromise,
        RevocationReasonCode::AffiliationChanged => CrlReasonCode::AffiliationChanged,
        RevocationReasonCode::Superseded => CrlReasonCode::Superseded,
        RevocationReasonCode::CessationOfOperation => CrlReasonCode::CessationOfOperation,
        RevocationReasonCode::PrivilegeWithdrawn => CrlReasonCode::PrivilegeWithdrawn,
        // RFC 5280 §5.3.1 codes absent from the KMIP standard set, mapped via extensions.
        RevocationReasonCode::CertificateHold => CrlReasonCode::CertificateHold,
        RevocationReasonCode::RemoveFromCRL => CrlReasonCode::RemoveFromCRL,
        RevocationReasonCode::AaCompromise => CrlReasonCode::AaCompromise,
    }
}
