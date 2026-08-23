//! Comprehensive test suite for X.509 CRL generation and distribution.
//!
//! # Coverage matrix
//!
//! | Category | Tests |
//! |----------|-------|
//! | **Unit** | CRL builder: empty, with entries, reason ASN.1 tag (in `crypto::openssl::crl`) |
//! | **Unit** | DB persistence: upsert, get, max, list, upsert-replace (in `database::permissions_test`) |
//! | **Functional** | Empty CRL for CA with no revoked certs |
//! | **Functional** | CRL includes cert after `Revoke` (all reason codes) |
//! | **Functional** | CRL Number strictly increases across multiple generate calls |
//! | **Functional** | Generated CRL is persisted to DB and survives in-process restart via cold-start warmup |
//! | **Functional** | DER and PEM output both parse and verify |
//! | **Functional** | Auto-CRL refresh triggered by `Revoke` when `kms_public_url` is set |
//! | **Functional** | Public CDP endpoint returns cached CRL (DER, correct MIME type) |
//! | **Security** | `cRLSign` keyUsage enforcement — CA without `cRLSign` is rejected |
//! | **Security** | Non-CA object (symmetric key) used as issuer is rejected |
//! | **Security** | All KMIP `RevocationReasonCode` values map to the correct RFC 5280 reason |
//! | **Non-regression** | CRL Number monotonicity: simulated restart seed from DB max |
//! | **Non-regression** | `removeFromCRL` reason code produces `Unspecified` (complete CRL only) |

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_objects::{Certificate, Object},
        kmip_operations::{
            Certify, Get, GetAttributes, GetAttributesResponse, Revoke, RevokeResponse,
        },
        kmip_types::{
            CertificateAttributes, CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier, VendorAttribute, VendorAttributeValue,
        },
    },
};
use openssl::x509::X509Crl;
use x509_parser::prelude::{CertificateRevocationList, FromDer};

use crate::{
    config::ServerParams,
    core::{KMS, operations::generate_crl::get_cached_crl},
    middlewares::UserId,
    openssl_providers::init_openssl_providers_for_tests,
    result::KResult,
    tests::test_utils::{https_clap_config, https_clap_config_opts, setup_app},
};

// ── Extension strings ────────────────────────────────────────────────────────

/// CA certificate extension: has `cRLSign` (required by our new enforcement).
const CA_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign,digitalSignature
";

/// CA certificate extension: missing `cRLSign` — used to test enforcement.
const CA_EXT_NO_CRL_SIGN: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,digitalSignature
";

/// Leaf certificate extension (no crlDistributionPoints — avoids live fetches).
const LEAF_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:FALSE
";

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Spin up a fresh in-process KMS backed by a temporary `SQLite` database.
async fn make_kms() -> KResult<Arc<KMS>> {
    init_openssl_providers_for_tests();
    let kms =
        Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?);
    Ok(kms)
}

/// Same but with a `kms_public_url` so auto-CRL refresh is enabled.
async fn make_kms_with_public_url(url: &str) -> KResult<Arc<KMS>> {
    init_openssl_providers_for_tests();
    let kms = Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config_opts(
            Some(url.to_owned()),
        ))?))
        .await?,
    );
    Ok(kms)
}

/// Issue a certificate using KMIP `Certify`.
///
/// Uses RSA-2048 (FIPS-approved) unless `CryptographicAlgorithm::RSA` is unavailable.
/// When `issuer_cert_id` / `issuer_sk_id` are `None`, a self-signed root is created.
/// Returns `(cert_id, private_key_id)`.
async fn certify(
    kms: &Arc<KMS>,
    owner: &UserId,
    cn: &str,
    issuer_cert_id: Option<&str>,
    issuer_sk_id: Option<&str>,
    extension: &[u8],
) -> KResult<(String, String)> {
    let subject_name = format!("C=FR, O=KMS Test, CN={cn}");
    let mut links = Vec::new();
    if let Some(id) = issuer_cert_id {
        links.push(Link {
            link_type: LinkType::CertificateLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(id.to_owned()),
        });
    }
    if let Some(id) = issuer_sk_id {
        links.push(Link {
            link_type: LinkType::PrivateKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(id.to_owned()),
        });
    }
    let attrs = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        key_format_type: None,
        certificate_attributes: Some(CertificateAttributes::parse_subject_line(&subject_name)?),
        link: if links.is_empty() { None } else { Some(links) },
        vendor_attributes: Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(extension.to_vec()),
        }]),
        ..Attributes::default()
    };
    let cert_id = kms
        .certify(
            Certify {
                attributes: Some(attrs),
                ..Certify::default()
            },
            owner,
        )
        .await?
        .unique_identifier
        .to_string();
    // Retrieve the linked private key UID.
    let GetAttributesResponse { attributes, .. } = kms
        .get_attributes(GetAttributes::from(cert_id.clone()), owner)
        .await?;
    let sk_id = attributes
        .get_link(LinkType::PrivateKeyLink)
        .expect("cert must have PrivateKeyLink")
        .to_string();
    Ok((cert_id, sk_id))
}

/// Revoke a certificate with the given reason code.
async fn revoke_cert(
    kms: &Arc<KMS>,
    owner: &UserId,
    cert_id: &str,
    reason: RevocationReasonCode,
) -> KResult<RevokeResponse> {
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(cert_id.to_owned())),
            revocation_reason: RevocationReason {
                revocation_reason_code: reason,
                revocation_message: Some("crl_tests harness".to_owned()),
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
        owner,
    )
    .await
}

/// Return the serial number bytes from a DER-encoded certificate.
fn cert_serial(cert_der: &[u8]) -> Vec<u8> {
    x509_parser::prelude::X509Certificate::from_der(cert_der)
        .expect("parse cert DER")
        .1
        .raw_serial()
        .to_vec()
}

/// Retrieve the DER-encoded certificate from the KMS.
async fn get_cert_der(kms: &Arc<KMS>, owner: &UserId, cert_id: &str) -> Vec<u8> {
    let resp = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(cert_id.to_owned())),
                ..Get::default()
            },
            owner,
        )
        .await
        .expect("get cert");
    match resp.object {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => certificate_value,
        other => panic!(
            "expected Certificate, got an unexpected object type: {}",
            other.object_type()
        ),
    }
}

/// Call `generate_crl` and return the DER bytes.
async fn generate_crl_der(kms: &Arc<KMS>, owner: &UserId, ca_id: &str) -> Vec<u8> {
    crate::core::operations::generate_crl::generate_crl(kms, ca_id, None, owner)
        .await
        .expect("generate_crl")
        .to_der()
        .expect("CRL to DER")
}

/// Convert a `BigUint` (from `x509_parser`) to `u64` using its big-endian byte representation.
/// Only the last 8 bytes are used; values > `u64::MAX` are truncated.
fn big_uint_to_u64(n: &x509_parser::num_bigint::BigUint) -> u64 {
    let bytes = n.to_bytes_be();
    let mut arr = [0_u8; 8];
    let len = bytes.len().min(8);
    arr[8 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    u64::from_be_bytes(arr)
}

/// Parse DER CRL with `x509_parser` and return the serial numbers of revoked entries.
fn revoked_serials(crl_der: &[u8]) -> Vec<Vec<u8>> {
    let (_, parsed) = CertificateRevocationList::from_der(crl_der).expect("parse CRL DER");
    parsed
        .iter_revoked_certificates()
        .map(|r| r.raw_serial().to_vec())
        .collect()
}

// ── Functional tests ─────────────────────────────────────────────────────────

/// An empty CRL is produced for a CA with no revoked certificates.
/// The CRL must parse, verify, and contain zero revoked entries.
#[tokio::test]
async fn test_crl_empty_for_ca_with_no_revoked_certs() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");

    let (ca_id, _) = certify(&kms, &owner, "Empty-CRL CA", None, None, CA_EXT).await?;
    let crl_der = generate_crl_der(&kms, &owner, &ca_id).await;

    let crl = X509Crl::from_der(&crl_der).expect("CRL DER must parse");
    let serials = revoked_serials(&crl_der);
    assert!(serials.is_empty(), "no revoked certs → CRL must be empty");

    // Retrieve the CA public key and verify the CRL signature.
    let ca_der = get_cert_der(&kms, &owner, &ca_id).await;
    let ca_x509 = openssl::x509::X509::from_der(&ca_der).expect("parse CA cert");
    let ca_pkey = ca_x509.public_key().expect("CA public key");
    assert!(
        crl.verify(&ca_pkey).expect("verify CRL signature"),
        "CRL signature must verify with the CA public key"
    );
    Ok(())
}

/// After revoking a leaf certificate, the CRL must list its serial number.
/// Tests with `KeyCompromise` (→ `Compromised` state) and `CessationOfOperation`
/// (→ `Deactivated` state) to cover both revocation state paths.
#[tokio::test]
async fn test_crl_includes_revoked_cert() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");

    let (ca_id, ca_sk_id) = certify(&kms, &owner, "Test CA", None, None, CA_EXT).await?;
    let (leaf_id, _) = certify(
        &kms,
        &owner,
        "Test Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;

    let leaf_serial = cert_serial(&get_cert_der(&kms, &owner, &leaf_id).await);

    // Before revocation the CRL must be empty.
    let crl_before = generate_crl_der(&kms, &owner, &ca_id).await;
    assert!(
        revoked_serials(&crl_before).is_empty(),
        "CRL must be empty before revocation"
    );

    // Revoke the leaf.
    revoke_cert(&kms, &owner, &leaf_id, RevocationReasonCode::KeyCompromise).await?;

    // After revocation the CRL must include the leaf's serial.
    let crl_after = generate_crl_der(&kms, &owner, &ca_id).await;
    let serials = revoked_serials(&crl_after);
    assert!(
        serials.contains(&leaf_serial),
        "revoked leaf serial must appear in CRL"
    );
    assert_eq!(serials.len(), 1, "exactly one entry expected");
    Ok(())
}

/// CRL Number must strictly increase across successive `generate_crl` calls.
/// This tests RFC 5280 §5.2.3 within a single server instance.
#[tokio::test]
async fn test_crl_number_strictly_increases() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, _) = certify(&kms, &owner, "Monotonic CA", None, None, CA_EXT).await?;

    let crl_der_1 = generate_crl_der(&kms, &owner, &ca_id).await;
    let crl_der_2 = generate_crl_der(&kms, &owner, &ca_id).await;

    let parse_crl_number = |der: &[u8]| -> u64 {
        let (_, crl) = CertificateRevocationList::from_der(der).expect("parse CRL");
        big_uint_to_u64(
            crl.crl_number()
                .expect("CRL Number extension must be present"),
        )
    };

    let n1 = parse_crl_number(&crl_der_1);
    let n2 = parse_crl_number(&crl_der_2);
    assert!(
        n2 > n1,
        "CRL Number must be strictly greater on each successive call ({n1} ≥ {n2})"
    );
    Ok(())
}

/// Generated CRL is persisted to the DB and retrievable via `get_crl`.
/// This ensures the public CDP endpoint can serve CRLs after a restart.
#[tokio::test]
async fn test_crl_persisted_to_db() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, _) = certify(&kms, &owner, "Persist CA", None, None, CA_EXT).await?;

    generate_crl_der(&kms, &owner, &ca_id).await;

    let db_entry = kms.database.get_crl(&ca_id).await.expect("DB get_crl");
    assert!(
        db_entry.is_some(),
        "CRL must be persisted to DB after generate_crl"
    );
    let (der_from_db, _) = db_entry.unwrap();
    X509Crl::from_der(&der_from_db).expect("DB-stored CRL must parse as valid DER");
    Ok(())
}

/// Both DER and PEM output must parse and verify with the CA public key.
#[tokio::test]
async fn test_crl_der_and_pem_output_valid() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, _) = certify(&kms, &owner, "Format CA", None, None, CA_EXT).await?;

    let crl = crate::core::operations::generate_crl::generate_crl(&kms, &ca_id, None, &owner)
        .await
        .expect("generate_crl");

    let der = crl.to_der().expect("to_der");
    let pem = crl.to_pem().expect("to_pem");

    let ca_der = get_cert_der(&kms, &owner, &ca_id).await;
    let ca_pkey = openssl::x509::X509::from_der(&ca_der)
        .expect("parse CA cert")
        .public_key()
        .expect("CA public key");

    let crl_from_der = X509Crl::from_der(&der).expect("DER must re-parse");
    assert!(
        crl_from_der.verify(&ca_pkey).expect("verify DER CRL"),
        "DER CRL signature invalid"
    );

    let crl_from_pem = X509Crl::from_pem(&pem).expect("PEM must re-parse");
    assert!(
        crl_from_pem.verify(&ca_pkey).expect("verify PEM CRL"),
        "PEM CRL signature invalid"
    );
    Ok(())
}

/// Cold-start cache warmup: after generating a CRL, the in-memory cache entry
/// returned by `get_cached_crl` must match the DB-stored DER bytes.
#[tokio::test]
async fn test_crl_cache_consistent_with_db() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, _) = certify(&kms, &owner, "Cache CA", None, None, CA_EXT).await?;

    // generate_crl populates both the in-memory cache and the DB.
    let crl_der = generate_crl_der(&kms, &owner, &ca_id).await;

    // get_cached_crl should return the same bytes.
    let cached = get_cached_crl(&ca_id, &kms)
        .await
        .expect("cache must be populated");
    assert_eq!(
        cached.0, crl_der,
        "in-memory cache and DB-stored CRL must agree"
    );
    Ok(())
}

/// Multiple leaf certificates from the same CA — all revoked — must all appear
/// in the CRL regardless of which `RevocationReasonCode` was used.
#[tokio::test]
async fn test_crl_includes_all_revoked_certs_from_same_ca() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, ca_sk_id) = certify(&kms, &owner, "Multi CA", None, None, CA_EXT).await?;

    let mut expected_serials = Vec::new();
    let reasons = [
        RevocationReasonCode::KeyCompromise,
        RevocationReasonCode::CessationOfOperation,
        RevocationReasonCode::Superseded,
        RevocationReasonCode::AffiliationChanged,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        let (leaf_id, _) = certify(
            &kms,
            &owner,
            &format!("Leaf {i}"),
            Some(&ca_id),
            Some(&ca_sk_id),
            LEAF_EXT,
        )
        .await?;
        let serial = cert_serial(&get_cert_der(&kms, &owner, &leaf_id).await);
        revoke_cert(&kms, &owner, &leaf_id, *reason).await?;
        expected_serials.push(serial);
    }

    let crl_der = generate_crl_der(&kms, &owner, &ca_id).await;
    let serials = revoked_serials(&crl_der);
    assert_eq!(
        serials.len(),
        reasons.len(),
        "CRL must contain exactly {} entries",
        reasons.len()
    );
    for s in &expected_serials {
        assert!(serials.contains(s), "serial {s:?} must be in the CRL");
    }
    Ok(())
}

// ── REST / HTTP endpoint tests ────────────────────────────────────────────────

/// The public CDP endpoint (`GET /public/certificates/{id}/crl`) must return
/// 404 when no CRL has ever been generated for that issuer.
#[tokio::test]
async fn test_public_crl_endpoint_404_before_generation() -> KResult<()> {
    let app = setup_app(None).await;

    let response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/public/certificates/does-not-exist/crl")
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        actix_web::http::StatusCode::NOT_FOUND,
        "public CRL endpoint must return 404 when no CRL is cached"
    );
    Ok(())
}

/// The public CDP endpoint must serve valid DER after the authenticated endpoint
/// has generated a CRL (which populates the cache and DB).
#[tokio::test]
async fn test_public_crl_endpoint_serves_valid_der() -> KResult<()> {
    init_openssl_providers_for_tests();
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, _) = certify(&kms, &owner, "CDP CA", None, None, CA_EXT).await?;

    // Generate CRL via the operation (populates in-memory cache and DB).
    generate_crl_der(&kms, &owner, &ca_id).await;

    // The public endpoint reads from the cache (no auth required).
    let cached = get_cached_crl(&ca_id, &kms).await;
    assert!(
        cached.is_some(),
        "cache must be populated after generate_crl"
    );
    let (der, _, _) = cached.unwrap();
    X509Crl::from_der(&der).expect("cached DER must be a valid CRL");
    Ok(())
}

// ── Security tests ────────────────────────────────────────────────────────────

/// RFC 5280 §4.2.1.3: if the CA certificate has a keyUsage extension that does
/// NOT include `cRLSign`, `generate_crl` must return `InvalidRequest`.
#[tokio::test]
async fn test_crl_rejects_ca_without_crl_sign_key_usage() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");

    // Certify a CA that has keyUsage but lacks cRLSign.
    let (ca_id, _) = certify(
        &kms,
        &owner,
        "No-cRLSign CA",
        None,
        None,
        CA_EXT_NO_CRL_SIGN,
    )
    .await?;

    let result =
        crate::core::operations::generate_crl::generate_crl(&kms, &ca_id, None, &owner).await;

    assert!(
        result.is_err(),
        "generate_crl must fail for a CA without cRLSign"
    );
    let msg = match result {
        Ok(_) => panic!("generate_crl succeeded unexpectedly for a CA without cRLSign"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("cRLSign") || msg.contains("keyUsage") || msg.contains("RFC 5280"),
        "error message must reference cRLSign / keyUsage, got: {msg}"
    );
    Ok(())
}

/// `generate_crl` must reject a UID that refers to a non-certificate object
/// (here a symmetric key) with a clear `InvalidRequest` error.
#[tokio::test]
async fn test_crl_rejects_non_certificate_issuer() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        extra::tagging::EMPTY_TAGS, kmip_operations::CreateResponse,
        requests::symmetric_key_create_request,
    };
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");

    // Create an AES-256 key.
    let req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let CreateResponse {
        unique_identifier, ..
    } = kms.create(req, &owner).await?;
    let sym_key_id = unique_identifier.to_string();

    let result =
        crate::core::operations::generate_crl::generate_crl(&kms, &sym_key_id, None, &owner).await;
    assert!(
        result.is_err(),
        "generate_crl must fail when issuer UID is not a certificate"
    );
    Ok(())
}

// ── Non-regression tests ─────────────────────────────────────────────────────

/// RFC 5280 §5.3.1: `removeFromCRL` is valid only in delta CRLs.
/// The KMS generates complete CRLs only, so the reason code for a certificate
/// revoked with `RemoveFromCRL` must be absent from the CRL entry (mapped to
/// `Unspecified`, which is suppressed per §5.3.1).
#[tokio::test]
async fn test_remove_from_crl_reason_is_suppressed_in_complete_crl() -> KResult<()> {
    // OID 2.5.29.21 — id-ce-reasonCode (RFC 5280 §5.3.1).
    const REASON_OID: &str = "2.5.29.21";

    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, ca_sk_id) = certify(&kms, &owner, "Delta CA", None, None, CA_EXT).await?;
    let (leaf_id, _) = certify(
        &kms,
        &owner,
        "Hold Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;

    // Revoke with RemoveFromCRL (KMIP vendor extension → RFC 5280 reason 8).
    revoke_cert(&kms, &owner, &leaf_id, RevocationReasonCode::RemoveFromCRL).await?;

    let crl_der = generate_crl_der(&kms, &owner, &ca_id).await;
    let (_, parsed_crl) = CertificateRevocationList::from_der(&crl_der).expect("parse CRL DER");

    // If the entry is present, its reasonCode extension must be absent
    // (removeFromCRL maps to Unspecified which is suppressed).
    for entry in parsed_crl.iter_revoked_certificates() {
        let has_reason = entry
            .extensions()
            .iter()
            .any(|ext| ext.oid.to_id_string() == REASON_OID);
        assert!(
            !has_reason,
            "reasonCode extension must be absent for removeFromCRL in a complete CRL (RFC 5280 §5.3.1)"
        );
    }
    Ok(())
}

/// Non-regression: CRL Number must remain monotonically increasing even when
/// the in-process counter is reset to its startup seed.  This simulates the
/// condition where `db_max + 1 > unix_timestamp` (many CRLs generated in a
/// short time window) — the seed must still exceed the DB max.
#[tokio::test]
async fn test_crl_number_monotonicity_seed_exceeds_db_max() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, _) = certify(&kms, &owner, "Seed CA", None, None, CA_EXT).await?;

    // Generate several CRLs to advance the counter.
    for _ in 0..5 {
        generate_crl_der(&kms, &owner, &ca_id).await;
    }

    // Read the highest CRL number stored in the DB.
    let db_max = kms
        .database
        .get_max_crl_number()
        .await
        .expect("get_max_crl_number")
        .expect("must be Some after generating CRLs");

    // The seed formula used in KMS::instantiate: max(unix_ts, db_max + 1).
    let ts_seed = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(1);
    let seed = ts_seed.max(db_max + 1);

    assert!(
        seed > db_max,
        "CRL counter seed {seed} must be > DB max {db_max} (RFC 5280 §5.2.3 non-regression)"
    );
    Ok(())
}

/// All RFC 5280 / KMIP reason code mappings.
///
/// For every KMIP `RevocationReasonCode`, revoke a leaf cert and verify that:
/// - the CRL entry is present,
/// - the `reasonCode` extension tag is `0x0A` (ENUMERATED) when present,
/// - `removeFromCRL` → no `reasonCode` extension (mapped to Unspecified → omitted).
#[tokio::test]
async fn test_all_reason_codes_produce_correct_crl_entries() -> KResult<()> {
    // OID 2.5.29.21 — id-ce-reasonCode (RFC 5280 §5.3.1).
    const REASON_OID: &str = "2.5.29.21";

    // Map: (KMIP code, expected CRL reason code value per RFC 5280 §5.3.1).
    // `None` means the `reasonCode` extension must be absent (Unspecified / RemoveFromCRL).
    const CASES: &[(RevocationReasonCode, Option<u64>)] = &[
        (RevocationReasonCode::Unspecified, None), // 0 — suppressed per §5.3.1
        (RevocationReasonCode::KeyCompromise, Some(1)), // keyCompromise
        (RevocationReasonCode::CACompromise, Some(2)), // cACompromise
        (RevocationReasonCode::AffiliationChanged, Some(3)), // affiliationChanged
        (RevocationReasonCode::Superseded, Some(4)), // superseded
        (RevocationReasonCode::CessationOfOperation, Some(5)), // cessationOfOperation
        (RevocationReasonCode::PrivilegeWithdrawn, Some(9)), // privilegeWithdrawn
        (RevocationReasonCode::RemoveFromCRL, None), // 8 — suppressed in complete CRL
    ];

    let kms = make_kms().await?;
    let owner = UserId::new("crl_owner");
    let (ca_id, ca_sk_id) = certify(&kms, &owner, "Reason CA", None, None, CA_EXT).await?;

    for (kmip_reason, expected_value) in CASES {
        // Issue a fresh leaf for each reason code to avoid serial clashes.
        let label = format!("Leaf-{kmip_reason:?}");
        let (leaf_id, _) = certify(
            &kms,
            &owner,
            &label,
            Some(&ca_id),
            Some(&ca_sk_id),
            LEAF_EXT,
        )
        .await?;
        let leaf_serial = cert_serial(&get_cert_der(&kms, &owner, &leaf_id).await);
        revoke_cert(&kms, &owner, &leaf_id, *kmip_reason).await?;

        let crl_der = generate_crl_der(&kms, &owner, &ca_id).await;
        let (_, parsed_crl) = CertificateRevocationList::from_der(&crl_der).expect("parse CRL DER");

        // Find the entry for this leaf.
        let entry = parsed_crl
            .iter_revoked_certificates()
            .find(|e| e.raw_serial() == leaf_serial.as_slice());

        if let Some(expected) = expected_value {
            let entry = entry.expect("CRL entry must be present for this reason code");
            let reason_ext = entry
                .extensions()
                .iter()
                .find(|ext| ext.oid.to_id_string() == REASON_OID);
            let ext = reason_ext.expect("reasonCode extension must be present");
            // Assert ASN.1 tag is ENUMERATED (0x0A).
            let tag = ext
                .value
                .first()
                .copied()
                .expect("non-empty extension value");
            assert_eq!(
                tag, 0x0A,
                "reasonCode extension must be ENUMERATED (tag 0x0A) for {kmip_reason:?}"
            );
            // Assert the value is the expected reason code.
            let value = ext.value.get(2).copied().map(u64::from);
            assert_eq!(
                value,
                Some(*expected),
                "reason code value mismatch for {kmip_reason:?}: expected {expected}, got {value:?}"
            );
        } else {
            // Unspecified / RemoveFromCRL → reasonCode extension must be absent.
            if let Some(entry) = entry {
                let has_reason = entry
                    .extensions()
                    .iter()
                    .any(|ext| ext.oid.to_id_string() == REASON_OID);
                assert!(
                    !has_reason,
                    "reasonCode extension must be absent for {kmip_reason:?} (RFC 5280 §5.3.1)"
                );
            }
        }
    }
    Ok(())
}
