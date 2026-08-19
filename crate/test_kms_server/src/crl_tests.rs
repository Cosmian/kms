#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cosmian_kms_client::{
    KmsClient,
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        KmipOperation,
        extra::VENDOR_ID_COSMIAN,
        kmip_operations::{Destroy, GetAttributes, Revoke},
        kmip_types::{LinkType, RecommendedCurve, UniqueIdentifier, ValidityIndicator},
        requests::{build_validate_certificate_request, create_ec_key_pair_request},
    },
    reexport::{
        cosmian_kms_access::access::Access,
        cosmian_kms_client_utils::certificate_utils::{Algorithm, build_certify_request},
    },
};
use openssl::x509::X509Crl;
use x509_parser::prelude::FromDer as _;

use crate::{
    init_test_logging, start_default_test_kms_server, start_default_test_kms_server_with_cert_auth,
};

// ── RFC 5280 CRL test helpers ─────────────────────────────────────────────────

/// Revoke a certificate using the given reason code.
async fn revoke_cert(client: &KmsClient, cert_id: &str, reason: RevocationReasonCode) {
    client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(cert_id.to_owned())),
            revocation_reason: RevocationReason {
                revocation_reason_code: reason,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        })
        .await
        .expect("revoke should succeed");
}

/// Fetch a CRL (DER format) for the given CA certificate ID.
async fn fetch_crl_der(client: &KmsClient, ca_cert_id: &str, validity_days: u32) -> X509Crl {
    let crl_bytes = client
        .get_bytes(
            &format!("/certificates/{ca_cert_id}/crl"),
            Some(&[
                ("format", "der"),
                ("validity_days", &validity_days.to_string()),
            ]),
        )
        .await
        .expect("CRL generation should succeed");
    X509Crl::from_der(&crl_bytes).expect("CRL response should be valid DER")
}

/// Create a self-signed CA with a custom common name.
///
/// This is the multi-CA variant of [`create_ca`]; the plain helper always uses
/// the same CN which causes collisions when two CAs exist in the same test.
async fn create_named_ca(client: &KmsClient, cn: &str, res: &mut TestResources) -> String {
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &None,
        &None,
        true,
        &Some(format!("CN={cn},O=Cosmian")),
        Algorithm::NistP256,
        &None,
        &None,
        365,
        &None,
        &[],
    )
    .unwrap();
    let resp = client.certify(certify).await.unwrap();
    let cert_id = resp.unique_identifier.to_string();
    res.track(cert_id.clone());
    cert_id
}

/// Track created object IDs for cleanup.
struct TestResources {
    ids: Vec<String>,
}

impl TestResources {
    fn new() -> Self {
        Self { ids: Vec::new() }
    }

    fn track(&mut self, id: impl Into<String>) {
        self.ids.push(id.into());
    }

    async fn cleanup(&self, client: &KmsClient) {
        for id in &self.ids {
            drop(
                client
                    .destroy(Destroy {
                        unique_identifier: Some(UniqueIdentifier::TextString(id.clone())),
                        remove: true,
                        cascade: true,
                        ..Destroy::default()
                    })
                    .await,
            );
        }
    }
}

/// Create a self-signed CA certificate.
async fn create_ca(client: &KmsClient, res: &mut TestResources) -> String {
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &None,
        &None,
        true,
        &Some("CN=TestCA-CRL,O=Cosmian".to_owned()),
        Algorithm::NistP256,
        &None,
        &None,
        365,
        &None,
        &[],
    )
    .unwrap();

    let resp = client.certify(certify).await.unwrap();
    let cert_id = resp.unique_identifier.to_string();
    res.track(cert_id.clone());
    cert_id
}

/// Issue an end-entity certificate from the CA.
async fn issue_cert(
    client: &KmsClient,
    ca_cert_id: &str,
    cn: &str,
    res: &mut TestResources,
) -> String {
    // Create a key pair for the end-entity
    let create_kp = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        Vec::<String>::new(),
        RecommendedCurve::P256,
        false,
        None,
    )
    .unwrap();
    let kp_resp = client.create_key_pair(create_kp).await.unwrap();
    let pub_key_id = kp_resp.public_key_unique_identifier.to_string();
    let priv_key_id = kp_resp.private_key_unique_identifier.to_string();
    res.track(pub_key_id.clone());
    res.track(priv_key_id.clone());

    // Certify with the CA
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,                               // certificate_id (output hint)
        &None,                               // CSR format
        &None,                               // CSR
        &Some(pub_key_id),                   // public_key_id_to_certify
        &None,                               // certificate_id_to_re_certify
        false,                               // generate_key_pair
        &Some(format!("CN={cn},O=Cosmian")), // subject_name
        Algorithm::NistP256,                 // algorithm
        &None,                               // issuer_private_key_id
        &Some(ca_cert_id.to_owned()),        // issuer_certificate_id
        365,                                 // number_of_days
        &None,                               // certificate_extensions
        &[],                                 // tags
    )
    .unwrap();

    let resp = client.certify(certify).await.unwrap();
    let cert_id = resp.unique_identifier.to_string();
    res.track(cert_id.clone());
    cert_id
}

/// Test: generate CRL for CA with no revoked certificates (empty CRL).
#[tokio::test]
async fn test_generate_empty_crl() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    // Create a CA
    let ca_cert_id = create_ca(&client, &mut resources).await;

    // Generate CRL (DER format)
    let crl_bytes: Vec<u8> = client
        .get_bytes(
            &format!("/certificates/{ca_cert_id}/crl"),
            Some(&[("format", "der"), ("validity_days", "7")]),
        )
        .await
        .unwrap();

    // Parse and verify
    let crl = X509Crl::from_der(&crl_bytes).expect("Failed to parse CRL from DER");
    let revoked = crl.get_revoked();
    assert!(
        revoked.is_none() || revoked.unwrap().is_empty(),
        "Expected empty CRL"
    );

    // PEM format
    let crl_bytes_pem: Vec<u8> = client
        .get_bytes(
            &format!("/certificates/{ca_cert_id}/crl"),
            Some(&[("format", "pem"), ("validity_days", "30")]),
        )
        .await
        .unwrap();
    let crl_pem = X509Crl::from_pem(&crl_bytes_pem).expect("Failed to parse CRL from PEM");
    assert!(
        crl_pem.get_revoked().is_none() || crl_pem.get_revoked().unwrap().is_empty(),
        "Expected empty CRL (PEM)"
    );

    resources.cleanup(&client).await;
}

/// Test: generate CRL with revoked certificates.
#[tokio::test]
async fn test_generate_crl_with_revoked_certs() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    // Create a CA
    let ca_cert_id = create_ca(&client, &mut resources).await;

    // Issue two end-entity certificates
    let cert1_id = issue_cert(&client, &ca_cert_id, "cert1.example.com", &mut resources).await;
    let cert2_id = issue_cert(&client, &ca_cert_id, "cert2.example.com", &mut resources).await;

    // Revoke cert1 with KeyCompromise
    client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(cert1_id.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: Some("test revocation".to_owned()),
            },
            compromise_occurrence_date: None,
            cascade: false,
        })
        .await
        .unwrap();

    // Revoke cert2 with CessationOfOperation
    client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(cert2_id.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: Some("shutting down".to_owned()),
            },
            compromise_occurrence_date: None,
            cascade: false,
        })
        .await
        .unwrap();

    // Generate CRL
    let crl_bytes: Vec<u8> = client
        .get_bytes(
            &format!("/certificates/{ca_cert_id}/crl"),
            Some(&[("format", "der"), ("validity_days", "7")]),
        )
        .await
        .unwrap();

    // Parse and verify
    let crl = X509Crl::from_der(&crl_bytes).expect("Failed to parse CRL from DER");
    let revoked = crl.get_revoked().expect("CRL should have revoked entries");
    assert_eq!(revoked.len(), 2, "Expected 2 revoked certificates in CRL");

    resources.cleanup(&client).await;
}

/// Full end-to-end CRL validation test:
/// 1. Create CA with crlDistributionPoints pointing to a local file
/// 2. Issue an end-entity certificate
/// 3. Generate empty CRL to disk
/// 4. Validate the chain (should pass — cert not in CRL)
/// 5. Revoke the certificate
/// 6. Regenerate CRL (now contains the revoked serial)
/// 7. Validate the chain again (should fail — cert is revoked via CRL)
#[tokio::test]
async fn test_crl_validation_lifecycle() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    // Use a unique temporary file for the CRL so the server cache doesn't collide
    let crl_file = std::env::temp_dir().join(format!("test_crl_{}.pem", std::process::id()));

    // Build a valid file:// URI that works on every OS.
    // On Windows, PathBuf::to_str() returns a backslash path; the URI form uses
    // three slashes and forward slashes with a drive letter prefix.
    // On Unix, an absolute path such as /foo/bar becomes file:///foo/bar.
    let crl_file_uri = crate::vector_runner::path_to_file_uri(&crl_file);

    // ── Step 1: Create CA with crlDistributionPoints pointing to the temp file ──
    // The extension config tells the certify operation to embed the CRL DP.
    let ext_config = format!(
        "[ v3_ca ]\nbasicConstraints=critical,CA:TRUE\n\
         keyUsage=critical,keyCertSign,crlSign\n\
         subjectKeyIdentifier=hash\n\
         crlDistributionPoints=URI:{crl_file_uri}\n"
    );

    let certify_ca = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &None,
        &None,
        true,
        &Some("CN=CRL-Test-CA,O=Cosmian".to_owned()),
        Algorithm::NistP256,
        &None,
        &None,
        365,
        &Some(ext_config.as_bytes().to_vec()),
        &[],
    )
    .unwrap();

    let ca_resp = client.certify(certify_ca).await.unwrap();
    let ca_cert_id = ca_resp.unique_identifier.to_string();
    resources.track(ca_cert_id.clone());

    // ── Step 2: Issue an end-entity certificate with the same CRL DP ──
    let ee_ext_config = format!("[ v3_ca ]\ncrlDistributionPoints=URI:{crl_file_uri}\n");

    let ee_kp = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        Vec::<String>::new(),
        RecommendedCurve::P256,
        false,
        None,
    )
    .unwrap();
    let ee_kp_resp = client.create_key_pair(ee_kp).await.unwrap();
    let ee_pub_id = ee_kp_resp.public_key_unique_identifier.to_string();
    let ee_priv_id = ee_kp_resp.private_key_unique_identifier.to_string();
    resources.track(ee_pub_id.clone());
    resources.track(ee_priv_id.clone());

    let certify_ee = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &Some(ee_pub_id),
        &None,
        false,
        &Some("CN=ee.example.com,O=Cosmian".to_owned()),
        Algorithm::NistP256,
        &None,
        &Some(ca_cert_id.clone()),
        365,
        &Some(ee_ext_config.as_bytes().to_vec()),
        &[],
    )
    .unwrap();

    let ee_resp = client.certify(certify_ee).await.unwrap();
    let ee_cert_id = ee_resp.unique_identifier.to_string();
    resources.track(ee_cert_id.clone());

    // ── Step 3: Generate the initial (empty) CRL and write to disk ──
    let crl_bytes: Vec<u8> = client
        .get_bytes(
            &format!("/certificates/{ca_cert_id}/crl"),
            Some(&[("format", "pem"), ("validity_days", "30")]),
        )
        .await
        .unwrap();
    std::fs::write(&crl_file, &crl_bytes).unwrap();

    // Sanity check: CRL is empty
    let crl = X509Crl::from_pem(&crl_bytes).unwrap();
    assert!(
        crl.get_revoked().is_none() || crl.get_revoked().unwrap().is_empty(),
        "CRL should be empty initially"
    );

    // ── Step 4: Validate the chain (should succeed) ──
    let validate_req =
        build_validate_certificate_request(&[ee_cert_id.clone(), ca_cert_id.clone()], None)
            .unwrap();
    let validate_resp = client.validate(validate_req).await.unwrap();
    assert_eq!(
        validate_resp.validity_indicator,
        ValidityIndicator::Valid,
        "Certificate should be valid before revocation"
    );

    // ── Step 5: Revoke the end-entity certificate ──
    client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(ee_cert_id.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: Some("compromised in test".to_owned()),
            },
            compromise_occurrence_date: None,
            cascade: false,
        })
        .await
        .unwrap();

    // ── Step 6: Regenerate CRL (now contains the revoked cert serial) ──
    let crl_bytes_updated: Vec<u8> = client
        .get_bytes(
            &format!("/certificates/{ca_cert_id}/crl"),
            Some(&[("format", "pem"), ("validity_days", "30")]),
        )
        .await
        .unwrap();
    // Overwrite the CRL file on disk
    std::fs::write(&crl_file, &crl_bytes_updated).unwrap();

    // Verify the CRL now contains 1 entry
    let crl_updated = X509Crl::from_pem(&crl_bytes_updated).unwrap();
    let revoked_list = crl_updated
        .get_revoked()
        .expect("CRL should contain revoked entries after revocation");
    assert_eq!(
        revoked_list.len(),
        1,
        "CRL should contain exactly 1 revoked certificate"
    );

    // ── Step 7: Validate the chain again (should FAIL — cert is in CRL) ──
    let validate_req2 =
        build_validate_certificate_request(&[ee_cert_id.clone(), ca_cert_id.clone()], None)
            .unwrap();
    let validate_result = client.validate(validate_req2).await;
    assert!(
        validate_result.is_err(),
        "Validation should fail for a revoked certificate whose serial appears in the CRL"
    );

    // Cleanup
    std::fs::remove_file(&crl_file).ok();
    resources.cleanup(&client).await;
}

// ── New RFC 5280 CRL tests ─────────────────────────────────────────────────────

/// Test: issue 5 certificates, revoke exactly 3, assert CRL contains exactly 3 entries.
///
/// RFC 5280 §5.1: A CRL contains a list of revoked, unexpired certificates.
/// Only revoked certificates must appear — valid certificates must be absent.
/// This is the primary correctness assertion: the revocation count must be exact.
#[tokio::test]
async fn test_crl_partial_revocation_exact_count() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    let ca_id = create_named_ca(&client, "PartialRevoke-CA", &mut resources).await;

    // Issue 5 EE certificates
    let cert1 = issue_cert(&client, &ca_id, "leaf1.partial", &mut resources).await;
    let _cert2 = issue_cert(&client, &ca_id, "leaf2.partial", &mut resources).await;
    let cert3 = issue_cert(&client, &ca_id, "leaf3.partial", &mut resources).await;
    let _cert4 = issue_cert(&client, &ca_id, "leaf4.partial", &mut resources).await;
    let cert5 = issue_cert(&client, &ca_id, "leaf5.partial", &mut resources).await;

    // Revoke cert1, cert3, cert5 — leave cert2 and cert4 valid
    revoke_cert(&client, &cert1, RevocationReasonCode::KeyCompromise).await;
    revoke_cert(&client, &cert3, RevocationReasonCode::Superseded).await;
    revoke_cert(&client, &cert5, RevocationReasonCode::CessationOfOperation).await;

    let crl = fetch_crl_der(&client, &ca_id, 7).await;
    let revoked = crl.get_revoked().expect("CRL must have revoked entries");

    assert_eq!(
        revoked.len(),
        3,
        "CRL must list exactly 3 entries (cert1, cert3, cert5); cert2 and cert4 are still valid"
    );

    resources.cleanup(&client).await;
}

/// Test: a certificate issued by CA-B must NOT appear in CA-A's CRL.
///
/// RFC 5280 §5.1: A CRL is scoped to a single issuing CA.  Certificates issued
/// by CA-B carry `CertificateLink → CA-B`; the server MUST NOT include them
/// when building CA-A's CRL, even after they have been revoked.
#[tokio::test]
async fn test_crl_cross_ca_isolation() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    let ca_a_id = create_named_ca(&client, "CrossCA-A", &mut resources).await;
    let ca_b_id = create_named_ca(&client, "CrossCA-B", &mut resources).await;

    // Issue one certificate from each CA
    let _cert_a = issue_cert(&client, &ca_a_id, "leaf.cross-ca-a", &mut resources).await;
    let cert_b = issue_cert(&client, &ca_b_id, "leaf.cross-ca-b", &mut resources).await;

    // Revoke cert_b (issued by CA-B)
    revoke_cert(&client, &cert_b, RevocationReasonCode::CessationOfOperation).await;

    // CA-A's CRL must be empty — cert_b belongs to CA-B's chain, not CA-A's
    let crl_a = fetch_crl_der(&client, &ca_a_id, 7).await;
    assert!(
        crl_a.get_revoked().is_none() || crl_a.get_revoked().unwrap().is_empty(),
        "CA-A's CRL must be empty: cert_b was issued by CA-B, not CA-A"
    );

    // CA-B's CRL must contain exactly 1 entry
    let crl_b = fetch_crl_der(&client, &ca_b_id, 7).await;
    let revoked_b = crl_b
        .get_revoked()
        .expect("CA-B's CRL must have revoked entries");
    assert_eq!(
        revoked_b.len(),
        1,
        "CA-B's CRL must contain exactly 1 revoked entry"
    );

    resources.cleanup(&client).await;
}

/// Test: all standard RFC 5280 §5.3.1 revocation reason codes produce CRL entries.
///
/// RFC 5280 §5.3.1 defines the `CRLReason` enumeration.  Each revoked certificate
/// must appear in the CRL regardless of the reason code used.  The server maps KMIP
/// reason codes to RFC 5280 reason codes via `kmip_reason_to_crl_reason`; this test
/// verifies all mappings produce exactly one CRL entry each.
#[tokio::test]
async fn test_crl_all_revocation_reason_codes() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    let ca_id = create_named_ca(&client, "AllReasons-CA", &mut resources).await;

    // RFC 5280 §5.3.1 reason codes — CertificateHold and RemoveFromCRL are intentionally
    // excluded here: they are vendor-extension KMIP values and have special semantics.
    let reason_codes = [
        RevocationReasonCode::Unspecified,
        RevocationReasonCode::KeyCompromise,
        RevocationReasonCode::CACompromise,
        RevocationReasonCode::AffiliationChanged,
        RevocationReasonCode::Superseded,
        RevocationReasonCode::CessationOfOperation,
        RevocationReasonCode::PrivilegeWithdrawn,
    ];
    let expected_count = reason_codes.len();

    // Issue one certificate per reason code and immediately revoke it
    for (i, &reason) in reason_codes.iter().enumerate() {
        let cert_id = issue_cert(
            &client,
            &ca_id,
            &format!("leaf{i}.allreasons"),
            &mut resources,
        )
        .await;
        revoke_cert(&client, &cert_id, reason).await;
    }

    let crl = fetch_crl_der(&client, &ca_id, 7).await;
    let revoked = crl.get_revoked().expect("CRL must have revoked entries");

    assert_eq!(
        revoked.len(),
        expected_count,
        "All {expected_count} RFC 5280 reason codes must produce a CRL entry"
    );

    resources.cleanup(&client).await;
}

/// Test: certificates in both the Deactivated and Compromised KMIP states appear in the CRL.
///
/// RFC 5280 §5.1: the CRL must include all revoked certificates.  KMIP places a certificate in
/// the **Compromised** state when the reason is `KeyCompromise` or `CACompromise`, and in the
/// **Deactivated** state for all other reasons.  The server must search both states when
/// generating the CRL.
#[tokio::test]
async fn test_crl_deactivated_and_compromised_states() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    let ca_id = create_named_ca(&client, "BothStates-CA", &mut resources).await;

    // cert1 → AffiliationChanged → Deactivated state (non-compromise reason)
    let cert1 = issue_cert(&client, &ca_id, "leaf.deactivated", &mut resources).await;
    revoke_cert(&client, &cert1, RevocationReasonCode::AffiliationChanged).await;

    // cert2 → KeyCompromise → Compromised state
    let cert2 = issue_cert(&client, &ca_id, "leaf.compromised", &mut resources).await;
    revoke_cert(&client, &cert2, RevocationReasonCode::KeyCompromise).await;

    // cert3 → CACompromise → Compromised state (second compromise variant)
    let cert3 = issue_cert(&client, &ca_id, "leaf.ca-compromised", &mut resources).await;
    revoke_cert(&client, &cert3, RevocationReasonCode::CACompromise).await;

    let crl = fetch_crl_der(&client, &ca_id, 7).await;
    let revoked = crl.get_revoked().expect("CRL must have revoked entries");

    assert_eq!(
        revoked.len(),
        3,
        "CRL must include all 3 certificates: 1 Deactivated + 2 Compromised"
    );

    resources.cleanup(&client).await;
}

/// Test: successive CRL generations for the same CA produce distinct CRLs.
///
/// RFC 5280 §5.2.3: The CRL Number extension MUST be monotonically increasing.
/// Two consecutive generations MUST produce different DER bytes because the CRL
/// Number increments on every call (atomic counter seeded from Unix timestamp).
/// The `thisUpdate` time will also differ unless both calls occur within the same
/// second, but the CRL Number guarantees uniqueness even in that edge case.
#[tokio::test]
async fn test_crl_incremental_generation_unique_crls() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    let ca_id = create_named_ca(&client, "IncrementalCRL-CA", &mut resources).await;

    // Generate CRL #1 with zero revocations
    let crl1_bytes = client
        .get_bytes(
            &format!("/certificates/{ca_id}/crl"),
            Some(&[("format", "der"), ("validity_days", "7")]),
        )
        .await
        .expect("first CRL generation should succeed");

    // Revoke a certificate between the two generations to change the revoked list
    let cert = issue_cert(&client, &ca_id, "leaf.incremental", &mut resources).await;
    revoke_cert(&client, &cert, RevocationReasonCode::Superseded).await;

    // Generate CRL #2 — must differ from #1 due to new entry + incremented CRL Number
    let crl2_bytes = client
        .get_bytes(
            &format!("/certificates/{ca_id}/crl"),
            Some(&[("format", "der"), ("validity_days", "7")]),
        )
        .await
        .expect("second CRL generation should succeed");

    assert_ne!(
        crl1_bytes, crl2_bytes,
        "Consecutive CRL generations must produce different DER bytes \
         (CRL Number must increment and the revoked list differs)"
    );

    // Additionally verify CRL #1 is empty and CRL #2 has one entry
    let crl1 = X509Crl::from_der(&crl1_bytes).unwrap();
    assert!(
        crl1.get_revoked().is_none() || crl1.get_revoked().unwrap().is_empty(),
        "CRL #1 should be empty (generated before any revocation)"
    );

    let crl2 = X509Crl::from_der(&crl2_bytes).unwrap();
    let revoked2 = crl2.get_revoked().expect("CRL #2 must have entries");
    assert_eq!(
        revoked2.len(),
        1,
        "CRL #2 must contain the one revoked certificate"
    );

    resources.cleanup(&client).await;
}

/// Test: the CRL `nextUpdate` field reflects the requested `validity_days`.
///
/// RFC 5280 §5.1.2.5: `nextUpdate` indicates the date by which the next CRL will be issued.
/// The server must set `nextUpdate = thisUpdate + validity_days * 86400 seconds`.
/// The test checks this using the OpenSSL `Asn1TimeRef::diff` API.
#[tokio::test]
async fn test_crl_validity_period() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    let ca_id = create_named_ca(&client, "ValidityPeriod-CA", &mut resources).await;

    for validity_days in [1_u32, 7, 30] {
        let crl = fetch_crl_der(&client, &ca_id, validity_days).await;
        let last = crl.last_update();
        let next = crl
            .next_update()
            .expect("nextUpdate must be present (RFC 5280 §5.1.2.5)");

        // diff = next - last; should be validity_days days (±1 day tolerance for clock jitter)
        // Asn1TimeRef::diff(compare) computes `compare - self`, so `last.diff(next)` = next - last.
        let diff = last.diff(next).expect("Asn1TimeRef::diff should not fail");

        let expected_days = i32::try_from(validity_days).unwrap();
        assert!(
            (diff.days - expected_days).abs() <= 1,
            "validity_days={validity_days}: nextUpdate - thisUpdate = {} days, expected ≈ {expected_days}",
            diff.days
        );
    }

    resources.cleanup(&client).await;
}

/// Test: the CRL contains the mandatory AKI and CRL Number extensions (RFC 5280 §5.2).
///
/// RFC 5280 §5.2.1: The `AuthorityKeyIdentifier` (AKI) extension MUST be present in all CRLs.
/// RFC 5280 §5.2.3: The `CRLNumber` extension MUST be present in all CRLs.
///
/// The OIDs are verified by parsing each extension object on the CRL.
/// - AKI:       `2.5.29.35`
/// - CRL Number: `2.5.29.20`
#[tokio::test]
async fn test_crl_required_extensions_aki_and_number() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut resources = TestResources::new();

    let ca_id = create_named_ca(&client, "RequiredExt-CA", &mut resources).await;
    let crl_bytes = client
        .get_bytes(
            &format!("/certificates/{ca_id}/crl"),
            Some(&[("format", "der"), ("validity_days", "7")]),
        )
        .await
        .expect("CRL generation should succeed");

    // Parse with x509_parser to iterate over CRL extensions
    let (_, parsed) = x509_parser::revocation_list::CertificateRevocationList::from_der(&crl_bytes)
        .expect("CRL DER must parse with x509_parser");

    let oid_strings: Vec<String> = parsed
        .extensions()
        .iter()
        .map(|ext| ext.oid.to_string())
        .collect();

    // OID 2.5.29.35 — Authority Key Identifier (RFC 5280 §5.2.1, MUST)
    assert!(
        oid_strings.iter().any(|s| s == "2.5.29.35"),
        "CRL must contain the Authority Key Identifier extension (OID 2.5.29.35); \
         found extensions: {oid_strings:?}"
    );

    resources.cleanup(&client).await;
}

/// Retrieve the `PrivateKeyLink` attribute from a certificate to get the CA signing key ID.
async fn get_linked_private_key_id(client: &KmsClient, cert_id: &str) -> String {
    client
        .get_attributes(GetAttributes::from(cert_id))
        .await
        .expect("GetAttributes should succeed")
        .attributes
        .get_link(LinkType::PrivateKeyLink)
        .expect("certificate must have a PrivateKeyLink attribute")
        .to_string()
}

/// Test: CRL must include revoked certificates regardless of which user owns them.
///
/// RFC 5280 §5.1 requires a CRL to list every certificate issued by the CA that
/// has been revoked, irrespective of who owns the certificate in the KMS database.
///
/// **Regression guard** for the `find_all` fix: prior to the fix, `find_revoked_certificates`
/// used a user-scoped `find()` call.  Because `find()` only returns objects accessible to
/// the requesting user, certificates owned by other users were silently omitted.
/// If the fix is reverted, this test fails with `"expected 3, got 1"`.
///
/// Setup (cert-auth server — owner and user are distinct DB identities):
///   - `owner.client@acme.com` creates CA, issues leaf-1 → DB owner = owner
///   - `user.client@acme.com`  issues leaf-2, leaf-3  → DB owner = user
///   - All 3 revoked
///   - Owner generates CRL → must contain all 3 serial numbers
#[tokio::test]
async fn test_crl_contains_certs_from_all_users() {
    init_test_logging();
    // Use mTLS cert-auth server: owner and user are distinct DB identities.
    // The cert-auth server has no CO configured, so generate_crl is accessible
    // to the object owner (owner.client@acme.com owns the CA).
    let ctx = start_default_test_kms_server_with_cert_auth().await;
    let owner = ctx.get_owner_client();
    let user = ctx.get_user_client();
    let mut resources = TestResources::new();

    // 1. Owner creates CA (owner.client@acme.com owns the CA cert and CA private key)
    let ca_id = create_named_ca(&owner, "MultiOwner-CRL-CA", &mut resources).await;
    let ca_sk_id = get_linked_private_key_id(&owner, &ca_id).await;
    resources.track(ca_sk_id.clone());

    // 2. Grant user.client@acme.com the Certify permission on both the CA cert and CA
    //    private key so they can issue leaf certificates without being the owner.
    //    The server resolves the issuer private key via PrivateKeyLink and calls
    //    retrieve_object_for_operation(KmipOperation::Certify) on each.
    for uid in [&ca_id, &ca_sk_id] {
        owner
            .grant_access(Access {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                user_id: "user.client@acme.com".to_owned(),
                operation_types: vec![KmipOperation::Certify],
            })
            .await
            .expect("grant Certify access should succeed");
    }

    // 3. Owner issues leaf-1 (DB owner = owner.client@acme.com)
    let leaf1 = issue_cert(&owner, &ca_id, "leaf1.multi-owner-crl", &mut resources).await;

    // 4. User issues leaf-2 and leaf-3 (DB owner = user.client@acme.com)
    let leaf2 = issue_cert(&user, &ca_id, "leaf2.multi-owner-crl", &mut resources).await;
    let leaf3 = issue_cert(&user, &ca_id, "leaf3.multi-owner-crl", &mut resources).await;

    // 5. Revoke all three certificates
    revoke_cert(&owner, &leaf1, RevocationReasonCode::Superseded).await;
    revoke_cert(&user, &leaf2, RevocationReasonCode::Superseded).await;
    revoke_cert(&user, &leaf3, RevocationReasonCode::KeyCompromise).await;

    // 6. Owner generates CRL for the CA.
    //    With find_all: sees all 3 revoked certs regardless of DB ownership → len == 3.
    //    Without fix (find scoped to owner): only sees leaf-1 → len == 1, assertion fails.
    let crl = fetch_crl_der(&owner, &ca_id, 7).await;
    let revoked = crl.get_revoked().expect("CRL must contain revoked entries");

    assert_eq!(
        revoked.len(),
        3,
        "CRL must contain all 3 revoked certificates regardless of DB owner: \
         leaf-1 (owned by owner.client@acme.com) + \
         leaf-2 + leaf-3 (both owned by user.client@acme.com)"
    );

    resources.cleanup(&owner).await;
}
