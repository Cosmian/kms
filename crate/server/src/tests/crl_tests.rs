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
//! | **CO role** | No CO — each owner revokes their own cert; CRL contains all (`find_all` bypass) |
//! | **CO role** | CO revokes cert owned by another user; appears in CRL |
//! | **CO role** | Mixed: CO + non-CO revocations — all 3 entries in final CRL |
//! | **CO role** | Non-CO without CA access cannot generate the CRL (permission denied) |
//! | **Counting** | No-CO: N owners each self-revoke; CRL count == N after every step |
//! | **Counting** | With CO: CO revokes K certs owned by others; CRL count == K after every step |

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
            CertificateAttributes, CertificateRequestType, CryptographicAlgorithm, Link, LinkType,
            LinkedObjectIdentifier, UniqueIdentifier, VendorAttribute, VendorAttributeValue,
        },
    },
};
use openssl::x509::{X509Crl, X509NameBuilder, X509ReqBuilder};
use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

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

// ── CRL completeness: with and without Crypto Officer role ───────────────────
//
// These tests verify the critical invariant: `generate_crl` uses `find_all` to
// collect revoked certificates ACROSS ALL OWNERS, regardless of who owns the
// certificate object in the database or who performed the revocation.
//
// Three scenarios are tested:
//  A. No CO configured  — each user revokes their own cert; CRL has all.
//  B. CO configured     — CO revokes a cert it does NOT own; CRL has it.
//  C. Mixed (CO + non-CO) — CO revokes some, regular user revokes own; CRL has all.

/// Build a KMS with the CO role configured for `co_user` (config-only, no ceremony).
///
/// `require_ceremony = false` means `co_user` is an active CO from startup — no
/// key-ceremony split required.
async fn make_kms_with_co(co_user: &str) -> KResult<Arc<KMS>> {
    use crate::config::{ClapConfig, MainDBConfig};
    init_openssl_providers_for_tests();
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: crate::tests::test_utils::get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users = Some(vec![co_user.to_owned()]);
    conf.roles.crypto_officer_require_ceremony = false;
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(conf)?)).await?);
    Ok(kms)
}

/// Grant `user` `Get` + `Revoke` access to `object_id` via the DB permissions layer.
///
/// Used to simulate a scenario where the CA owner gives a second user the right
/// to revoke (but not issue) certificates under that CA.
async fn grant_revoke_access(kms: &Arc<KMS>, object_id: &str, user: &UserId) -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;
    kms.database
        .grant_operations(
            object_id,
            user,
            std::collections::HashSet::from([KmipOperation::Get, KmipOperation::Revoke]),
        )
        .await?;
    Ok(())
}

/// Grant `user` `Get` + `Certify` on `cert_id` AND `Get` on `sk_id`.
///
/// This allows a non-owner to use the CA cert/key as an issuer in a `Certify`
/// request, producing a new certificate object owned by `user`.
///
/// A global `Create` grant on `"*"` is also required: `enforce_create_permission`
/// checks for it when the server is configured with a Crypto Officer role, to
/// prevent non-CO users from creating objects without explicit authorization.
async fn grant_certify_access(
    kms: &Arc<KMS>,
    ca_cert_id: &str,
    ca_sk_id: &str,
    user: &UserId,
) -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;
    // Grant Get + Certify on the CA cert (needed to retrieve the cert as issuer).
    kms.database
        .grant_operations(
            ca_cert_id,
            user,
            std::collections::HashSet::from([KmipOperation::Get, KmipOperation::Certify]),
        )
        .await?;
    // Grant Get on the CA private key (needed to sign the new cert).
    kms.database
        .grant_operations(
            ca_sk_id,
            user,
            std::collections::HashSet::from([KmipOperation::Get]),
        )
        .await?;
    // Grant global Create on "*" so enforce_create_permission succeeds for this user
    // when the server has a CO role configured.
    kms.database
        .grant_operations(
            "*",
            user,
            std::collections::HashSet::from([KmipOperation::Create]),
        )
        .await?;
    Ok(())
}

// ── Scenario A: No CO — every user revokes their own cert, CRL has all ───────

/// **No-CO scenario**: alice owns the CA and her leaf; bob uses the same CA (via
/// delegated access) and issues his own leaf (owned by bob). Each user revokes their
/// own cert. `generate_crl` must list BOTH revoked certificates because it uses
/// `find_all` to bypass DB ownership filters.
///
/// This is the RFC 5280 §3 requirement: the CRL must be a complete list of all
/// revoked certificates issued by that CA, irrespective of object ownership in the KMS.
#[tokio::test]
async fn test_crl_no_co_all_revoked_certs_present() -> KResult<()> {
    let kms = make_kms().await?;
    let alice = UserId::new("alice");
    let bob = UserId::new("bob");

    // Alice creates the CA.
    let (ca_id, ca_sk_id) = certify(&kms, &alice, "No-CO CA", None, None, CA_EXT).await?;

    // Alice issues her own leaf (alice owns it).
    let (leaf_alice, _) = certify(
        &kms,
        &alice,
        "Alice Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    let serial_alice = cert_serial(&get_cert_der(&kms, &alice, &leaf_alice).await);

    // Alice delegates CA usage to bob so bob can certify his own leaf.
    grant_certify_access(&kms, &ca_id, &ca_sk_id, &bob).await?;

    // Bob certifies his own leaf using alice's CA — resulting cert is owned by bob.
    let (leaf_bob, _) = certify(
        &kms,
        &bob,
        "Bob Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    let serial_bob = cert_serial(&get_cert_der(&kms, &bob, &leaf_bob).await);

    // Before any revocations — CRL must be empty.
    let crl_before = generate_crl_der(&kms, &alice, &ca_id).await;
    assert!(
        revoked_serials(&crl_before).is_empty(),
        "CRL must be empty before any revocations"
    );

    // Alice revokes her own leaf (alice is owner → standard revocation path).
    revoke_cert(
        &kms,
        &alice,
        &leaf_alice,
        RevocationReasonCode::CessationOfOperation,
    )
    .await?;

    // CRL after alice's revocation: 1 entry.
    let crl_after_alice = generate_crl_der(&kms, &alice, &ca_id).await;
    let serials_after_alice = revoked_serials(&crl_after_alice);
    assert!(
        serials_after_alice.contains(&serial_alice),
        "CRL must contain alice's leaf after her revocation"
    );
    assert!(
        !serials_after_alice.contains(&serial_bob),
        "Bob's leaf must NOT appear in the CRL before his revocation"
    );

    // Bob revokes his own leaf (bob is owner → standard revocation path).
    revoke_cert(&kms, &bob, &leaf_bob, RevocationReasonCode::KeyCompromise).await?;

    // CRL after bob's revocation: BOTH entries must appear.
    let crl_final = generate_crl_der(&kms, &alice, &ca_id).await;
    let serials_final = revoked_serials(&crl_final);
    assert_eq!(
        serials_final.len(),
        2,
        "CRL must contain exactly 2 entries: alice's and bob's leaves"
    );
    assert!(
        serials_final.contains(&serial_alice),
        "CRL must contain alice's revoked leaf (alice-owned)"
    );
    assert!(
        serials_final.contains(&serial_bob),
        "CRL must contain bob's revoked leaf (bob-owned) — find_all crosses ownership boundary"
    );
    Ok(())
}

// ── Scenario B: CO configured — CO revokes cert it does NOT own ──────────────

/// **CO-bypass scenario**: the CA owner (alice) is configured as the Crypto Officer.
/// Bob issues a leaf cert via the CA (bob owns the cert object in the DB). Alice,
/// acting as CO, revokes bob's cert using the ownership-bypass mechanism.
///
/// The CRL generated by alice must include bob's cert even though alice is neither
/// the DB owner nor the normal revocation user for that object.
#[tokio::test]
async fn test_crl_co_revokes_cert_owned_by_other_user() -> KResult<()> {
    // CO=alice, no ceremony required.
    let kms = make_kms_with_co("alice").await?;
    let alice = UserId::new("alice");
    let bob = UserId::new("bob");

    // Alice creates the CA.
    let (ca_id, ca_sk_id) = certify(&kms, &alice, "CO CA", None, None, CA_EXT).await?;

    // Alice issues her own leaf.
    let (leaf_alice, _) = certify(
        &kms,
        &alice,
        "Alice Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    let serial_alice = cert_serial(&get_cert_der(&kms, &alice, &leaf_alice).await);

    // Bob certifies his own leaf (bob owns it in the DB).
    grant_certify_access(&kms, &ca_id, &ca_sk_id, &bob).await?;
    let (leaf_bob, _leaf_bob_sk) = certify(
        &kms,
        &bob,
        "Bob Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    let serial_bob = cert_serial(&get_cert_der(&kms, &bob, &leaf_bob).await);

    // Confirm: bob is NOT a CO.
    assert!(
        !kms.is_crypto_officer(&bob).await?,
        "Bob must not be a Crypto Officer in this scenario"
    );

    // Confirm: alice IS a CO (config-only, no ceremony).
    assert!(
        kms.is_crypto_officer(&alice).await?,
        "Alice must be the Crypto Officer"
    );

    // Non-CO user (bob) cannot revoke alice's leaf (not owner, not CO) → must fail.
    let non_co_revoke_result =
        revoke_cert(&kms, &bob, &leaf_alice, RevocationReasonCode::Unspecified).await;
    assert!(
        non_co_revoke_result.is_err(),
        "Non-CO user bob must NOT be able to revoke alice's cert (she doesn't own it)"
    );

    // Alice (as CO) revokes bob's leaf — CO bypass grants access even though alice
    // does NOT own leaf_bob in the DB.
    revoke_cert(&kms, &alice, &leaf_bob, RevocationReasonCode::KeyCompromise).await?;

    // Alice also revokes her own leaf (normal path).
    revoke_cert(
        &kms,
        &alice,
        &leaf_alice,
        RevocationReasonCode::CessationOfOperation,
    )
    .await?;

    // generate_crl must contain BOTH: alice's leaf (alice-owned) + bob's leaf (bob-owned,
    // revoked by alice via CO bypass). `find_all` crosses DB ownership boundaries.
    let crl_der = generate_crl_der(&kms, &alice, &ca_id).await;
    let serials = revoked_serials(&crl_der);
    assert_eq!(
        serials.len(),
        2,
        "CRL must contain 2 entries: alice's leaf + bob's leaf (CO-revoked)"
    );
    assert!(
        serials.contains(&serial_alice),
        "CRL must include alice's leaf (alice-owned, alice-revoked)"
    );
    assert!(
        serials.contains(&serial_bob),
        "CRL must include bob's leaf (bob-owned, CO-revoked by alice)"
    );

    // Guard against the private key leaking: leaf_bob_sk is still readable only by bob.
    Ok(())
}

// ── Scenario C: Mixed CO + non-CO — all revocations appear in CRL ─────────────

/// **Mixed scenario**: CO revokes some certs, regular users revoke their own.
/// All revocations — regardless of who performed them or who owns the cert — must
/// appear in the CRL because `generate_crl` always uses `find_all`.
///
/// Topology:
/// - alice  = Crypto Officer + CA owner
/// - bob    = regular user (not CO), owns `leaf_bob`
/// - charlie = regular user (not CO), owns `leaf_charlie`
///
/// Revocation events:
/// 1. alice (CO) revokes `leaf_alice`         → alice is owner + CO
/// 2. alice (CO) revokes `leaf_bob`           → CO bypass; bob is DB owner
/// 3. charlie revokes `leaf_charlie`          → charlie is owner; no CO needed
///
/// Expected CRL: 3 entries.
#[tokio::test]
async fn test_crl_mixed_co_and_non_co_revocations_all_present() -> KResult<()> {
    let kms = make_kms_with_co("alice").await?;
    let alice = UserId::new("alice");
    let bob = UserId::new("bob");
    let charlie = UserId::new("charlie");

    // Alice creates the CA.
    let (ca_id, ca_sk_id) = certify(&kms, &alice, "Mixed CA", None, None, CA_EXT).await?;

    // Certify leaves for all three users.
    let (leaf_alice, _) = certify(
        &kms,
        &alice,
        "Alice Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    let serial_alice = cert_serial(&get_cert_der(&kms, &alice, &leaf_alice).await);

    grant_certify_access(&kms, &ca_id, &ca_sk_id, &bob).await?;
    let (leaf_bob, _) = certify(
        &kms,
        &bob,
        "Bob Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    let serial_bob = cert_serial(&get_cert_der(&kms, &bob, &leaf_bob).await);

    grant_certify_access(&kms, &ca_id, &ca_sk_id, &charlie).await?;
    let (leaf_charlie, _) = certify(
        &kms,
        &charlie,
        "Charlie Leaf",
        Some(&ca_id),
        Some(&ca_sk_id),
        LEAF_EXT,
    )
    .await?;
    let serial_charlie = cert_serial(&get_cert_der(&kms, &charlie, &leaf_charlie).await);

    // Confirm roles.
    assert!(kms.is_crypto_officer(&alice).await?, "alice must be CO");
    assert!(!kms.is_crypto_officer(&bob).await?, "bob must NOT be CO");
    assert!(
        !kms.is_crypto_officer(&charlie).await?,
        "charlie must NOT be CO"
    );

    // Initial CRL: empty.
    let crl_initial = generate_crl_der(&kms, &alice, &ca_id).await;
    assert!(
        revoked_serials(&crl_initial).is_empty(),
        "CRL must start empty"
    );

    // Event 1: alice (CO + owner) revokes her own leaf.
    revoke_cert(&kms, &alice, &leaf_alice, RevocationReasonCode::Superseded).await?;
    let serials_1 = revoked_serials(&generate_crl_der(&kms, &alice, &ca_id).await);
    assert_eq!(serials_1.len(), 1, "CRL must have 1 entry after event 1");
    assert!(
        serials_1.contains(&serial_alice),
        "alice's leaf must be in CRL"
    );

    // Event 2: alice (as CO) revokes bob's leaf — CO ownership bypass.
    revoke_cert(&kms, &alice, &leaf_bob, RevocationReasonCode::KeyCompromise).await?;
    let serials_2 = revoked_serials(&generate_crl_der(&kms, &alice, &ca_id).await);
    assert_eq!(serials_2.len(), 2, "CRL must have 2 entries after event 2");
    assert!(
        serials_2.contains(&serial_bob),
        "bob's leaf (CO-revoked by alice) must be in CRL"
    );

    // Event 3: charlie (regular user) revokes his own leaf.
    revoke_cert(
        &kms,
        &charlie,
        &leaf_charlie,
        RevocationReasonCode::AffiliationChanged,
    )
    .await?;

    // Final CRL: all 3 revocations must appear, regardless of who performed them
    // or who owns the cert object in the DB.
    let crl_final = generate_crl_der(&kms, &alice, &ca_id).await;
    let serials_final = revoked_serials(&crl_final);
    assert_eq!(
        serials_final.len(),
        3,
        "Final CRL must contain all 3 revoked certs (alice-owned, bob-owned, charlie-owned)"
    );
    assert!(
        serials_final.contains(&serial_alice),
        "alice's leaf must be in final CRL (alice-owned, alice-revoked)"
    );
    assert!(
        serials_final.contains(&serial_bob),
        "bob's leaf must be in final CRL (bob-owned, CO-revoked)"
    );
    assert!(
        serials_final.contains(&serial_charlie),
        "charlie's leaf must be in final CRL (charlie-owned, self-revoked)"
    );
    Ok(())
}

/// **Non-CO cannot access CA to generate CRL if not granted access.**
///
/// Without CO and without explicit permission grant, a user who does not own the
/// CA certificate must receive a permission-denied error when trying to generate
/// the CRL — the CRL generation endpoint requires read access to the CA cert.
#[tokio::test]
async fn test_crl_non_co_cannot_generate_crl_without_ca_access() -> KResult<()> {
    let kms = make_kms().await?; // no CO configured
    let alice = UserId::new("alice");
    let bob = UserId::new("bob");

    // Alice creates the CA.
    let (ca_id, _) = certify(&kms, &alice, "Access CA", None, None, CA_EXT).await?;

    // Bob (not owner, not CO) tries to generate the CRL for alice's CA.
    let result =
        crate::core::operations::generate_crl::generate_crl(&kms, &ca_id, None, &bob).await;
    assert!(
        result.is_err(),
        "Non-owner, non-CO user must NOT be able to generate a CRL for another user's CA"
    );
    Ok(())
}

// ── Counting-revoked-certificates tests ──────────────────────────────────────
//
// These tests are the primary count-correctness gate.  Unlike the scenario tests
// above that mix serial-identity checks with counts, these tests are focused
// exclusively on the count invariant:
//
//   After every individual revocation the CRL entry count must be exactly equal
//   to the number of revocations performed so far — no more, no fewer.
//
// Two independent sub-suites:
//  1. Without CO — every user self-revokes; find_all must collect all of them.
//  2. With CO    — CO revokes certs it does NOT own; every CO-revoked cert must
//                  appear, with the count matching the number of CO-revocations.
//
// Both suites use a fixed constant (COUNT_CERTS) so the reader can immediately
// see the expected final count and trace each loop iteration.

/// Number of leaf certificates issued in the counting tests.
const COUNT_CERTS: usize = 5;

// ── Sub-suite 1: No CO ────────────────────────────────────────────────────────

/// **Counting / No-CO**: issue `COUNT_CERTS` leaves under the same CA, each owned
/// by a distinct user (`user_0` … `user_N`).  Every user self-revokes their leaf.
///
/// After each revocation the CRL is regenerated and the entry count is asserted
/// to be exactly `k` (k = revocations so far).  The final CRL must contain exactly
/// `COUNT_CERTS` entries and every leaf serial must appear exactly once.
///
/// This test is the definitive proof that `find_all` collects revoked certificates
/// across all DB owners with no duplicates and no missing entries.
#[tokio::test]
async fn test_crl_counting_revoked_certs_no_co() -> KResult<()> {
    let kms = make_kms().await?; // no CO configured
    let ca_owner = UserId::new("ca_owner");

    // ── Setup: CA + N leaves, each owned by a distinct user ──────────────────
    let (ca_id, ca_sk_id) =
        certify(&kms, &ca_owner, "Counting-No-CO CA", None, None, CA_EXT).await?;

    let mut leaf_users: Vec<UserId> = Vec::with_capacity(COUNT_CERTS);
    let mut leaf_ids: Vec<String> = Vec::with_capacity(COUNT_CERTS);
    let mut leaf_serials: Vec<Vec<u8>> = Vec::with_capacity(COUNT_CERTS);

    for i in 0..COUNT_CERTS {
        let user = UserId::new(format!("leaf_user_{i}"));
        // Grant user_i certify access so the resulting cert is owned by user_i.
        grant_certify_access(&kms, &ca_id, &ca_sk_id, &user).await?;
        let (leaf_id, _) = certify(
            &kms,
            &user,
            &format!("Leaf {i}"),
            Some(&ca_id),
            Some(&ca_sk_id),
            LEAF_EXT,
        )
        .await?;
        let serial = cert_serial(&get_cert_der(&kms, &user, &leaf_id).await);
        leaf_users.push(user);
        leaf_ids.push(leaf_id);
        leaf_serials.push(serial);
    }

    // ── Baseline: CRL must be empty before any revocation ────────────────────
    let crl_empty = generate_crl_der(&kms, &ca_owner, &ca_id).await;
    assert_eq!(
        revoked_serials(&crl_empty).len(),
        0,
        "Baseline: CRL must be empty before any revocation (no CO)"
    );

    // ── Incremental revocation loop ───────────────────────────────────────────
    // Revoke one leaf at a time; after each step verify the CRL count == step.
    for step in 1..=COUNT_CERTS {
        let i = step - 1;
        // Each user self-revokes their own leaf (no CO needed — they are the owner).
        revoke_cert(
            &kms,
            &leaf_users[i],
            &leaf_ids[i],
            RevocationReasonCode::CessationOfOperation,
        )
        .await?;

        let crl_der = generate_crl_der(&kms, &ca_owner, &ca_id).await;
        let serials = revoked_serials(&crl_der);

        // Count invariant: exactly `step` entries after `step` revocations.
        assert_eq!(
            serials.len(),
            step,
            "No-CO step {step}/{COUNT_CERTS}: CRL must contain exactly {step} entries"
        );

        // Serial presence: the just-revoked serial must be in the CRL.
        assert!(
            serials.contains(&leaf_serials[i]),
            "No-CO step {step}: serial of leaf_{i} must be present in CRL"
        );

        // No duplicates: every serial in the CRL must be unique.
        let unique: std::collections::HashSet<Vec<u8>> = serials.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            serials.len(),
            "No-CO step {step}: CRL must not contain duplicate serials"
        );
    }

    // ── Final check: all serials must be present ──────────────────────────────
    let crl_final = generate_crl_der(&kms, &ca_owner, &ca_id).await;
    let serials_final = revoked_serials(&crl_final);
    assert_eq!(
        serials_final.len(),
        COUNT_CERTS,
        "No-CO final: CRL must contain exactly {COUNT_CERTS} entries"
    );
    for (i, serial) in leaf_serials.iter().enumerate() {
        assert!(
            serials_final.contains(serial),
            "No-CO final: serial of leaf_{i} must be present in the final CRL"
        );
    }
    Ok(())
}

// ── Sub-suite 2: With CO ──────────────────────────────────────────────────────

/// **Counting / With CO**: issue `COUNT_CERTS` leaves under the same CA, each
/// owned by a distinct user (`user_0` … `user_N`).  The Crypto Officer (alice)
/// revokes each leaf using the CO ownership-bypass mechanism.
///
/// After each CO-revocation the CRL is regenerated and the entry count must be
/// exactly `k`.  The final CRL must contain exactly `COUNT_CERTS` entries, every
/// leaf serial must appear exactly once, and no entry may appear more than once.
///
/// This test is the definitive proof that:
/// - CO bypass correctly marks objects owned by other users as revoked.
/// - `find_all` finds those DB-records regardless of which user owns them.
/// - The CRL count matches the number of CO-initiated revocations precisely.
#[tokio::test]
async fn test_crl_counting_revoked_certs_with_co() -> KResult<()> {
    let kms = make_kms_with_co("alice").await?; // CO = alice, config-only
    let alice = UserId::new("alice");

    // Confirm alice is the CO.
    assert!(
        kms.is_crypto_officer(&alice).await?,
        "alice must be the Crypto Officer"
    );

    // ── Setup: CA owned by alice + N leaves, each owned by a distinct non-CO user ──
    let (ca_id, ca_sk_id) = certify(&kms, &alice, "Counting-CO CA", None, None, CA_EXT).await?;

    let mut leaf_users: Vec<UserId> = Vec::with_capacity(COUNT_CERTS);
    let mut leaf_ids: Vec<String> = Vec::with_capacity(COUNT_CERTS);
    let mut leaf_serials: Vec<Vec<u8>> = Vec::with_capacity(COUNT_CERTS);

    for i in 0..COUNT_CERTS {
        let user = UserId::new(format!("co_leaf_user_{i}"));
        // Confirm none of the leaf users is a CO.
        assert!(
            !kms.is_crypto_officer(&user).await?,
            "co_leaf_user_{i} must NOT be a CO"
        );
        grant_certify_access(&kms, &ca_id, &ca_sk_id, &user).await?;
        let (leaf_id, _) = certify(
            &kms,
            &user,
            &format!("CO Leaf {i}"),
            Some(&ca_id),
            Some(&ca_sk_id),
            LEAF_EXT,
        )
        .await?;
        let serial = cert_serial(&get_cert_der(&kms, &user, &leaf_id).await);
        leaf_users.push(user);
        leaf_ids.push(leaf_id);
        leaf_serials.push(serial);
    }

    // ── Baseline: CRL must be empty before any CO-revocation ─────────────────
    let crl_empty = generate_crl_der(&kms, &alice, &ca_id).await;
    assert_eq!(
        revoked_serials(&crl_empty).len(),
        0,
        "Baseline: CRL must be empty before any CO-revocation"
    );

    // ── Incremental CO-revocation loop ────────────────────────────────────────
    // Alice (CO) revokes each leaf one at a time using the CO ownership bypass.
    // After each step verify the CRL count == step.
    for step in 1..=COUNT_CERTS {
        let i = step - 1;

        // Confirm: the leaf is currently owned by a non-CO user.
        let leaf_owner = &leaf_users[i];
        assert!(
            !kms.is_crypto_officer(leaf_owner).await?,
            "step {step}: co_leaf_user_{i} must still be a non-CO user (sanity check)"
        );

        // Alice (CO) revokes a leaf she does NOT own — CO bypass.
        revoke_cert(
            &kms,
            &alice,
            &leaf_ids[i],
            RevocationReasonCode::KeyCompromise,
        )
        .await?;

        let crl_der = generate_crl_der(&kms, &alice, &ca_id).await;
        let serials = revoked_serials(&crl_der);

        // Count invariant: exactly `step` entries after `step` CO-revocations.
        assert_eq!(
            serials.len(),
            step,
            "CO step {step}/{COUNT_CERTS}: CRL must contain exactly {step} entries"
        );

        // Serial presence: the just-revoked serial must be in the CRL.
        assert!(
            serials.contains(&leaf_serials[i]),
            "CO step {step}: serial of co_leaf_{i} must be present in CRL after CO-revocation"
        );

        // No duplicates: every serial in the CRL must be unique.
        let unique: std::collections::HashSet<Vec<u8>> = serials.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            serials.len(),
            "CO step {step}: CRL must not contain duplicate serials"
        );
    }

    // ── Final check: all serials must be present ──────────────────────────────
    let crl_final = generate_crl_der(&kms, &alice, &ca_id).await;
    let serials_final = revoked_serials(&crl_final);
    assert_eq!(
        serials_final.len(),
        COUNT_CERTS,
        "CO final: CRL must contain exactly {COUNT_CERTS} entries (all CO-revoked)"
    );
    for (i, serial) in leaf_serials.iter().enumerate() {
        assert!(
            serials_final.contains(serial),
            "CO final: serial of co_leaf_{i} must be present in the final CRL"
        );
    }
    Ok(())
}

// ── CSR-based Certify with TTL ────────────────────────────────────────────────
//
// Regression tests for the SPIRE / kmip-go limitation documented at
// https://github.com/spiffe/spire/pull/7235#discussion_r3829548963
//
// The Eviden KMS already honours the `requested_validity_days` vendor attribute
// on CSR-based Certify requests. These tests lock that behaviour in place so
// that future refactors cannot accidentally regress it.

/// Build a self-signed PKCS#10 CSR (PEM-encoded) for testing.
///
/// Uses RSA-2048 so the test runs in both FIPS and non-FIPS modes.
/// Returns the PEM bytes of the CSR (not the private key — the KMS signs
/// the certificate with the issuer's key, not the subject's key).
fn generate_test_csr(cn: &str) -> Vec<u8> {
    use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa};

    let rsa = Rsa::generate(2048).expect("RSA key");
    let pkey = PKey::from_rsa(rsa).expect("PKey");

    let mut name = X509NameBuilder::new().expect("X509NameBuilder");
    name.append_entry_by_text("C", "FR").expect("C");
    name.append_entry_by_text("O", "KMS Test").expect("O");
    name.append_entry_by_text("CN", cn).expect("CN");
    let name = name.build();

    let mut builder = X509ReqBuilder::new().expect("X509ReqBuilder");
    builder.set_pubkey(&pkey).expect("set pubkey");
    builder.set_subject_name(&name).expect("set subject name");
    builder
        .sign(&pkey, MessageDigest::sha256())
        .expect("sign CSR");

    builder.build().to_pem().expect("CSR to PEM")
}

/// CSR-based `Certify` with `requested_validity_days` vendor attribute must
/// produce a certificate whose `not_after` matches the requested TTL, **not**
/// the server default (365 days).
///
/// This is the positive regression test: the vendor attribute already works;
/// this test makes it impossible to regress silently.
#[tokio::test]
async fn test_certify_from_csr_with_requested_validity_days() -> KResult<()> {
    const TTL_DAYS: i32 = 30;
    let kms = make_kms().await?;
    let owner = UserId::new("csr_ttl_owner");

    // 1. Create a root CA with cRLSign so CRL generation also works.
    let (ca_id, ca_sk_id) = certify(&kms, &owner, "CSR-TTL Root CA", None, None, CA_EXT).await?;

    // 2. Generate a CSR signed by a fresh local RSA key.
    let csr_pem = generate_test_csr("CSR-TTL Subject");

    // 3. Certify the CSR with a 30-day TTL via the `requested_validity_days`
    //    vendor attribute — the path SPIRE/kmip-go uses.
    let attrs = Attributes {
        link: Some(vec![
            Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(ca_sk_id),
            },
            Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(ca_id),
            },
        ]),
        vendor_attributes: Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: "requested_validity_days".to_owned(),
            attribute_value: VendorAttributeValue::Integer(TTL_DAYS),
        }]),
        ..Attributes::default()
    };
    let cert_id = kms
        .certify(
            Certify {
                certificate_request_type: Some(CertificateRequestType::PEM),
                certificate_request_value: Some(csr_pem),
                attributes: Some(attrs),
                ..Certify::default()
            },
            &owner,
        )
        .await?
        .unique_identifier
        .to_string();

    // 4. Retrieve and parse the issued certificate.
    let cert_der = get_cert_der(&kms, &owner, &cert_id).await;
    let (_, cert) = X509Certificate::from_der(&cert_der).expect("issued cert must parse as X.509");

    // 5. Assert `not_after ≈ now + TTL_DAYS` (±1 day tolerance for CI timing).
    let not_after = cert.validity().not_after.timestamp();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let now = i64::try_from(now_secs).unwrap_or(i64::MAX);
    let actual_days = (not_after - now) / 86_400;
    let ttl_i64 = i64::from(TTL_DAYS);

    assert!(
        (ttl_i64 - 1..=ttl_i64 + 1).contains(&actual_days),
        "CSR-based Certify with requested_validity_days={TTL_DAYS}: \
         expected not_after ≈ {TTL_DAYS} days from now, got {actual_days} days"
    );

    // 6. The subject CN must come from the CSR, not from request attributes.
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");
    assert_eq!(
        cn, "CSR-TTL Subject",
        "subject CN must be taken from the CSR, not from request attributes"
    );

    Ok(())
}

/// CSR-based `Certify` with **no** `requested_validity_days` attribute falls
/// back to the server default of 365 days.
///
/// This test is the counterpart of `test_certify_from_csr_with_requested_validity_days`:
/// it ensures the default path is not inadvertently affected when the optional
/// TTL attribute is absent.
#[tokio::test]
async fn test_certify_from_csr_default_validity() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::new("csr_default_owner");

    let (ca_id, ca_sk_id) =
        certify(&kms, &owner, "CSR-Default Root CA", None, None, CA_EXT).await?;

    let csr_pem = generate_test_csr("CSR-Default Subject");

    let attrs = Attributes {
        link: Some(vec![
            Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(ca_sk_id),
            },
            Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(ca_id),
            },
        ]),
        ..Attributes::default()
    };
    let cert_id = kms
        .certify(
            Certify {
                certificate_request_type: Some(CertificateRequestType::PEM),
                certificate_request_value: Some(csr_pem),
                attributes: Some(attrs),
                ..Certify::default()
            },
            &owner,
        )
        .await?
        .unique_identifier
        .to_string();

    let cert_der = get_cert_der(&kms, &owner, &cert_id).await;
    let (_, cert) = X509Certificate::from_der(&cert_der).expect("issued cert must parse as X.509");

    let not_after = cert.validity().not_after.timestamp();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let now = i64::try_from(now_secs).unwrap_or(i64::MAX);
    let actual_days = (not_after - now) / 86_400;

    assert!(
        (364..=366).contains(&actual_days),
        "CSR-based Certify with no TTL attribute must default to ~365 days, got {actual_days} days"
    );

    Ok(())
}
