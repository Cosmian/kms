#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(feature = "non-fips")]
use cosmian_kms_client::kmip_2_1::requests::create_pqc_key_pair_request;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_objects::{Certificate, Object},
        kmip_operations::{Destroy, Get},
        kmip_types::{RecommendedCurve, UniqueIdentifier},
        requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
    },
    reexport::cosmian_kms_client_utils::certificate_utils::{Algorithm, build_certify_request},
};
use openssl::x509::X509;

use crate::{init_test_logging, start_default_test_kms_server};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Retrieve DER bytes of a certificate object.
async fn get_certificate_der(client: &KmsClient, cert_id: &str) -> Vec<u8> {
    let resp = client.get(Get::from(cert_id)).await.unwrap();
    match resp.object {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => certificate_value,
        other => panic!("Expected Object::Certificate, got {other:?}"),
    }
}

/// Create a self-signed CA keypair + certificate using `build_certify_request`
/// with `generate_key_pair = true` and no issuer.
async fn create_ca(
    client: &KmsClient,
    algorithm: Algorithm,
    cn: &str,
    res: &mut TestResources,
) -> (String, String) {
    let subject = format!("CN={cn},O=TestCA");
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &None,
        &None,
        true,
        &Some(subject),
        algorithm,
        &None,
        &None,
        365,
        &None,
        &[],
    )
    .unwrap();

    let resp = client.certify(certify).await.unwrap();
    let cert_id = resp.unique_identifier.to_string();

    // Retrieve the private key link from the certificate attributes
    let attrs = client
        .get_attributes(
            cosmian_kms_client::kmip_2_1::kmip_operations::GetAttributes::from(cert_id.as_str()),
        )
        .await
        .unwrap()
        .attributes;
    let sk_id = attrs
        .get_link(cosmian_kms_client::kmip_2_1::kmip_types::LinkType::PrivateKeyLink)
        .unwrap()
        .to_string();

    res.track(cert_id.clone());
    res.track(sk_id.clone());
    (sk_id, cert_id)
}

/// Assert common certificate properties: subject CN, issuer CN, validity,
/// and serial number ≤ 20 bytes.
fn assert_baseline(x509: &X509, expected_subject_cn: &str, expected_issuer_cn: &str) {
    // Subject CN
    let subject = x509.subject_name();
    let cn_entry = subject
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("Certificate must have a subject CN");
    let cn = cn_entry.data().as_utf8().unwrap();
    assert_eq!(cn.to_string(), expected_subject_cn, "Subject CN mismatch");

    // Issuer CN
    let issuer = x509.issuer_name();
    let issuer_cn_entry = issuer
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("Certificate must have an issuer CN");
    let issuer_cn = issuer_cn_entry.data().as_utf8().unwrap();
    assert_eq!(
        issuer_cn.to_string(),
        expected_issuer_cn,
        "Issuer CN mismatch"
    );

    // Validity: not_before ≤ now ≤ not_after
    let not_before = x509.not_before();
    let not_after = x509.not_after();
    let now = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
    assert!(
        not_before.compare(now.as_ref()).unwrap() != std::cmp::Ordering::Greater,
        "not_before is in the future"
    );
    assert!(
        not_after.compare(now.as_ref()).unwrap() != std::cmp::Ordering::Less,
        "not_after is in the past"
    );

    // Serial number ≤ 20 bytes (RFC 5280 §4.1.2.2)
    let serial_bn = x509.serial_number().to_bn().unwrap();
    let serial_bytes = serial_bn.to_vec();
    assert!(
        serial_bytes.len() <= 20,
        "Serial number is {} bytes, expected ≤ 20",
        serial_bytes.len()
    );
}

/// Extract the X.509 text representation and check for key usage bits.
/// The `openssl` crate with `default-features = false` does not expose
/// `X509::key_usage()`, so we parse the text output instead.
#[cfg(feature = "non-fips")]
fn cert_text(x509: &X509) -> String {
    String::from_utf8_lossy(&x509.to_text().unwrap()).to_string()
}

/// Assert that the certificate's keyUsage extension contains the given usage string.
#[cfg(feature = "non-fips")]
fn assert_key_usage_contains(x509: &X509, usage: &str) {
    let text = cert_text(x509);
    // Look in the X509v3 Key Usage section
    let ku_section = text
        .lines()
        .skip_while(|l| !l.contains("X509v3 Key Usage"))
        .nth(1) // the line after the header contains the values
        .unwrap_or("");
    assert!(
        ku_section.contains(usage),
        "Expected keyUsage to contain '{usage}', got: '{ku_section}'\nFull text:\n{text}"
    );
}

/// Assert that the certificate's keyUsage extension does NOT contain the given usage string.
#[cfg(feature = "non-fips")]
fn assert_key_usage_not_contains(x509: &X509, usage: &str) {
    let text = cert_text(x509);
    let ku_section = text
        .lines()
        .skip_while(|l| !l.contains("X509v3 Key Usage"))
        .nth(1)
        .unwrap_or("");
    assert!(
        !ku_section.contains(usage),
        "Expected keyUsage to NOT contain '{usage}', got: '{ku_section}'"
    );
}

// ===========================================================================
// Phase 3 — KeypairAndSubjectName tests
// ===========================================================================

/// Helper: certify with `generate_key_pair=true`, optionally CA-signed.
async fn certify_keypair(
    client: &KmsClient,
    algorithm: Algorithm,
    subject_cn: &str,
    issuer_sk_id: Option<&str>,
    issuer_cert_id: Option<&str>,
    res: &mut TestResources,
) -> String {
    let subject = format!("CN={subject_cn},O=Test");
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &None,
        &None,
        true,
        &Some(subject),
        algorithm,
        &issuer_sk_id.map(String::from),
        &issuer_cert_id.map(String::from),
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

// --- Self-signed KeypairAndSubjectName tests (RSA, EC, Ed25519 run in both modes) ---

#[tokio::test]
async fn test_certify_keypair_self_signed_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id =
        certify_keypair(&client, Algorithm::RSA2048, "RSA-SS", None, None, &mut res).await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "RSA-SS", "RSA-SS"); // self-signed → subject == issuer

    res.cleanup(&client).await;
}

#[tokio::test]
async fn test_certify_keypair_self_signed_ec() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id =
        certify_keypair(&client, Algorithm::NistP256, "EC-SS", None, None, &mut res).await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "EC-SS", "EC-SS");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_keypair_self_signed_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_keypair(
        &client,
        Algorithm::Ed25519,
        "Ed25519-SS",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Ed25519-SS", "Ed25519-SS");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_keypair_self_signed_mldsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_keypair(
        &client,
        Algorithm::MlDsa65,
        "MLDSA-SS",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "MLDSA-SS", "MLDSA-SS");

    // ML-DSA is a signing algorithm → expect digitalSignature in keyUsage
    assert_key_usage_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_keypair_self_signed_slhdsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_keypair(
        &client,
        Algorithm::SlhDsaSha2128s,
        "SLHDSA-SS",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "SLHDSA-SS", "SLHDSA-SS");

    assert_key_usage_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

// --- CA-signed KeypairAndSubjectName tests ---

#[tokio::test]
async fn test_certify_keypair_ca_signed_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::RSA2048, "RSA-CA", &mut res).await;
    let cert_id = certify_keypair(
        &client,
        Algorithm::RSA2048,
        "RSA-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "RSA-EE", "RSA-CA");

    res.cleanup(&client).await;
}

#[tokio::test]
async fn test_certify_keypair_ca_signed_ec() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::NistP256, "EC-CA", &mut res).await;
    let cert_id = certify_keypair(
        &client,
        Algorithm::NistP256,
        "EC-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "EC-EE", "EC-CA");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_keypair_ca_signed_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::Ed25519, "Ed25519-CA", &mut res).await;
    let cert_id = certify_keypair(
        &client,
        Algorithm::Ed25519,
        "Ed25519-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Ed25519-EE", "Ed25519-CA");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_keypair_ca_signed_mldsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::MlDsa65, "MLDSA-CA", &mut res).await;
    let cert_id = certify_keypair(
        &client,
        Algorithm::MlDsa65,
        "MLDSA-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "MLDSA-EE", "MLDSA-CA");

    assert_key_usage_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_keypair_ca_signed_slhdsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) =
        create_ca(&client, Algorithm::SlhDsaSha2128s, "SLHDSA-CA", &mut res).await;
    let cert_id = certify_keypair(
        &client,
        Algorithm::SlhDsaSha2128s,
        "SLHDSA-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "SLHDSA-EE", "SLHDSA-CA");

    assert_key_usage_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_keypair_ca_signed_mlkem() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    // ML-KEM subject needs a signing CA
    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::MlDsa65, "KEM-CA", &mut res).await;
    let cert_id = certify_keypair(
        &client,
        Algorithm::MlKem768,
        "MLKEM-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "MLKEM-EE", "KEM-CA");

    // ML-KEM → keyEncipherment only (RFC 9935 §5)
    assert_key_usage_contains(&x509, "Key Encipherment");
    assert_key_usage_not_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

// ===========================================================================
// Phase 4 — PublicKeyAndSubjectName tests
// ===========================================================================

/// Helper: create a keypair, then certify the public key with a subject name.
async fn certify_pubkey(
    client: &KmsClient,
    algorithm: Algorithm,
    subject_cn: &str,
    issuer_sk_id: Option<&str>,
    issuer_cert_id: Option<&str>,
    res: &mut TestResources,
) -> String {
    // First, create a key pair via CreateKeyPair
    let create_req = match algorithm {
        Algorithm::RSA2048 => create_rsa_key_pair_request(
            VENDOR_ID_COSMIAN,
            None,
            Vec::<String>::new(),
            2048,
            false,
            None,
        )
        .unwrap(),
        Algorithm::NistP256 => create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            None,
            Vec::<String>::new(),
            RecommendedCurve::P256,
            false,
            None,
        )
        .unwrap(),
        #[cfg(feature = "non-fips")]
        Algorithm::Ed25519 => create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            None,
            Vec::<String>::new(),
            RecommendedCurve::CURVEED25519,
            false,
            None,
        )
        .unwrap(),
        _ => panic!("Unsupported algorithm for pubkey certify test: {algorithm:?}"),
    };

    let kp_resp = client.create_key_pair(create_req).await.unwrap();
    let pub_key_id = kp_resp.public_key_unique_identifier.to_string();
    let priv_key_id = kp_resp.private_key_unique_identifier.to_string();
    res.track(pub_key_id.clone());
    res.track(priv_key_id.clone());

    // Certify the public key
    let subject = format!("CN={subject_cn},O=Test");
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &Some(pub_key_id),
        &None,
        false,
        &Some(subject),
        algorithm,
        &issuer_sk_id.map(String::from),
        &issuer_cert_id.map(String::from),
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

// --- Self-signed PublicKeyAndSubjectName tests ---

#[tokio::test]
async fn test_certify_pubkey_self_signed_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_pubkey(
        &client,
        Algorithm::RSA2048,
        "RSA-PK-SS",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "RSA-PK-SS", "RSA-PK-SS");

    res.cleanup(&client).await;
}

#[tokio::test]
async fn test_certify_pubkey_self_signed_ec() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_pubkey(
        &client,
        Algorithm::NistP256,
        "EC-PK-SS",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "EC-PK-SS", "EC-PK-SS");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pubkey_self_signed_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_pubkey(
        &client,
        Algorithm::Ed25519,
        "Ed25519-PK-SS",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Ed25519-PK-SS", "Ed25519-PK-SS");

    res.cleanup(&client).await;
}

// --- CA-signed PublicKeyAndSubjectName tests ---

#[tokio::test]
async fn test_certify_pubkey_ca_signed_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::RSA2048, "RSA-CA2", &mut res).await;
    let cert_id = certify_pubkey(
        &client,
        Algorithm::RSA2048,
        "RSA-PK-CA",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "RSA-PK-CA", "RSA-CA2");

    res.cleanup(&client).await;
}

#[tokio::test]
async fn test_certify_pubkey_ca_signed_ec() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::NistP256, "EC-CA2", &mut res).await;
    let cert_id = certify_pubkey(
        &client,
        Algorithm::NistP256,
        "EC-PK-CA",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "EC-PK-CA", "EC-CA2");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pubkey_ca_signed_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::Ed25519, "Ed25519-CA2", &mut res).await;
    let cert_id = certify_pubkey(
        &client,
        Algorithm::Ed25519,
        "Ed25519-PK-CA",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Ed25519-PK-CA", "Ed25519-CA2");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pubkey_ca_signed_mldsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::MlDsa65, "MLDSA-CA2", &mut res).await;

    // Create ML-DSA keypair separately
    let create_req = create_pqc_key_pair_request(
        VENDOR_ID_COSMIAN,
        Vec::<String>::new(),
        cosmian_kms_client::kmip_2_1::kmip_types::CryptographicAlgorithm::MLDSA_65,
        false,
    )
    .unwrap();
    let kp_resp = client.create_key_pair(create_req).await.unwrap();
    let pub_key_id = kp_resp.public_key_unique_identifier.to_string();
    let priv_key_id = kp_resp.private_key_unique_identifier.to_string();
    res.track(pub_key_id.clone());
    res.track(priv_key_id.clone());

    let subject = "CN=MLDSA-PK-CA,O=Test".to_owned();
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &Some(pub_key_id),
        &None,
        false,
        &Some(subject),
        Algorithm::MlDsa65,
        &Some(ca_sk),
        &Some(ca_cert),
        365,
        &None,
        &[],
    )
    .unwrap();

    let resp = client.certify(certify).await.unwrap();
    let cert_id = resp.unique_identifier.to_string();
    res.track(cert_id.clone());

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "MLDSA-PK-CA", "MLDSA-CA2");

    assert_key_usage_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pubkey_ca_signed_slhdsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) =
        create_ca(&client, Algorithm::SlhDsaSha2128s, "SLHDSA-CA2", &mut res).await;

    let create_req = create_pqc_key_pair_request(
        VENDOR_ID_COSMIAN,
        Vec::<String>::new(),
        cosmian_kms_client::kmip_2_1::kmip_types::CryptographicAlgorithm::SLHDSA_SHA2_128s,
        false,
    )
    .unwrap();
    let kp_resp = client.create_key_pair(create_req).await.unwrap();
    let pub_key_id = kp_resp.public_key_unique_identifier.to_string();
    let priv_key_id = kp_resp.private_key_unique_identifier.to_string();
    res.track(pub_key_id.clone());
    res.track(priv_key_id.clone());

    let subject = "CN=SLHDSA-PK-CA,O=Test".to_owned();
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &Some(pub_key_id),
        &None,
        false,
        &Some(subject),
        Algorithm::SlhDsaSha2128s,
        &Some(ca_sk),
        &Some(ca_cert),
        365,
        &None,
        &[],
    )
    .unwrap();

    let resp = client.certify(certify).await.unwrap();
    let cert_id = resp.unique_identifier.to_string();
    res.track(cert_id.clone());

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "SLHDSA-PK-CA", "SLHDSA-CA2");

    assert_key_usage_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pubkey_ca_signed_mlkem() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::MlDsa65, "KEM-CA2", &mut res).await;

    let create_req = create_pqc_key_pair_request(
        VENDOR_ID_COSMIAN,
        Vec::<String>::new(),
        cosmian_kms_client::kmip_2_1::kmip_types::CryptographicAlgorithm::MLKEM_768,
        false,
    )
    .unwrap();
    let kp_resp = client.create_key_pair(create_req).await.unwrap();
    let pub_key_id = kp_resp.public_key_unique_identifier.to_string();
    let priv_key_id = kp_resp.private_key_unique_identifier.to_string();
    res.track(pub_key_id.clone());
    res.track(priv_key_id.clone());

    let subject = "CN=MLKEM-PK-CA,O=Test".to_owned();
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &Some(pub_key_id),
        &None,
        false,
        &Some(subject),
        Algorithm::MlKem768,
        &Some(ca_sk),
        &Some(ca_cert),
        365,
        &None,
        &[],
    )
    .unwrap();

    let resp = client.certify(certify).await.unwrap();
    let cert_id = resp.unique_identifier.to_string();
    res.track(cert_id.clone());

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "MLKEM-PK-CA", "KEM-CA2");

    assert_key_usage_contains(&x509, "Key Encipherment");
    assert_key_usage_not_contains(&x509, "Digital Signature");

    res.cleanup(&client).await;
}

// ===========================================================================
// Phase 5 — Certificate renewal tests
// ===========================================================================

/// Helper: create a certificate (self-signed or CA-signed), then re-certify it.
async fn certify_renewal(
    client: &KmsClient,
    algorithm: Algorithm,
    subject_cn: &str,
    issuer_sk_id: Option<&str>,
    issuer_cert_id: Option<&str>,
    res: &mut TestResources,
) -> String {
    // First create a certificate to renew
    let original_cert_id = certify_keypair(
        client,
        algorithm,
        subject_cn,
        issuer_sk_id,
        issuer_cert_id,
        res,
    )
    .await;

    // Now re-certify
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &None,
        &Some(original_cert_id),
        false,
        &None,
        algorithm,
        &issuer_sk_id.map(String::from),
        &issuer_cert_id.map(String::from),
        730,
        &None,
        &[],
    )
    .unwrap();

    let resp = client.certify(certify).await.unwrap();
    let renewed_cert_id = resp.unique_identifier.to_string();
    res.track(renewed_cert_id.clone());
    renewed_cert_id
}

// --- Self-signed renewal tests ---

#[tokio::test]
async fn test_certify_renewal_self_signed_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_renewal(
        &client,
        Algorithm::RSA2048,
        "RSA-RENEW",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "RSA-RENEW", "RSA-RENEW");

    res.cleanup(&client).await;
}

#[tokio::test]
async fn test_certify_renewal_self_signed_ec() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_renewal(
        &client,
        Algorithm::NistP256,
        "EC-RENEW",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "EC-RENEW", "EC-RENEW");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_renewal_self_signed_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let cert_id = certify_renewal(
        &client,
        Algorithm::Ed25519,
        "Ed25519-RENEW",
        None,
        None,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Ed25519-RENEW", "Ed25519-RENEW");

    res.cleanup(&client).await;
}

// --- CA-signed renewal tests ---

#[tokio::test]
async fn test_certify_renewal_ca_signed_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::RSA2048, "RSA-CA-REN", &mut res).await;
    let cert_id = certify_renewal(
        &client,
        Algorithm::RSA2048,
        "RSA-REN-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "RSA-REN-EE", "RSA-CA-REN");

    res.cleanup(&client).await;
}

#[tokio::test]
async fn test_certify_renewal_ca_signed_ec() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::NistP256, "EC-CA-REN", &mut res).await;
    let cert_id = certify_renewal(
        &client,
        Algorithm::NistP256,
        "EC-REN-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "EC-REN-EE", "EC-CA-REN");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_renewal_ca_signed_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::Ed25519, "Ed25519-CA-REN", &mut res).await;
    let cert_id = certify_renewal(
        &client,
        Algorithm::Ed25519,
        "Ed25519-REN-EE",
        Some(&ca_sk),
        Some(&ca_cert),
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Ed25519-REN-EE", "Ed25519-CA-REN");

    res.cleanup(&client).await;
}

// ===========================================================================
// Phase 6 — CSR tests
// ===========================================================================

/// Helper: certify a PEM CSR with a CA.
async fn certify_csr(
    client: &KmsClient,
    csr_pem: &[u8],
    ca_sk_id: &str,
    ca_cert_id: &str,
    algorithm: Algorithm,
    res: &mut TestResources,
) -> String {
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &Some("pem".to_owned()),
        &Some(csr_pem.to_vec()),
        &None,
        &None,
        false,
        &None,
        algorithm,
        &Some(ca_sk_id.to_owned()),
        &Some(ca_cert_id.to_owned()),
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

#[tokio::test]
async fn test_certify_csr_ca_signed_rsa() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::RSA2048, "RSA-CA-CSR", &mut res).await;

    let csr_pem = include_bytes!("../../../test_data/certificates/csr/test_rsa2048.csr.pem");

    let cert_id = certify_csr(
        &client,
        csr_pem,
        &ca_sk,
        &ca_cert,
        Algorithm::RSA2048,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    // CSR subject is "CN=Test CSR RSA-2048"
    assert_baseline(&x509, "Test CSR RSA-2048", "RSA-CA-CSR");

    res.cleanup(&client).await;
}

#[tokio::test]
async fn test_certify_csr_ca_signed_ec() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::NistP256, "EC-CA-CSR", &mut res).await;

    let csr_pem = include_bytes!("../../../test_data/certificates/csr/test_ec_p256.csr.pem");

    let cert_id = certify_csr(
        &client,
        csr_pem,
        &ca_sk,
        &ca_cert,
        Algorithm::NistP256,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Test CSR EC-P256", "EC-CA-CSR");

    res.cleanup(&client).await;
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_csr_ca_signed_ed25519() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let mut res = TestResources::new();

    let (ca_sk, ca_cert) = create_ca(&client, Algorithm::Ed25519, "Ed25519-CA-CSR", &mut res).await;

    let csr_pem = include_bytes!("../../../test_data/certificates/csr/test_ed25519.csr.pem");

    let cert_id = certify_csr(
        &client,
        csr_pem,
        &ca_sk,
        &ca_cert,
        Algorithm::Ed25519,
        &mut res,
    )
    .await;

    let der = get_certificate_der(&client, &cert_id).await;
    let x509 = X509::from_der(&der).unwrap();
    assert_baseline(&x509, "Test CSR Ed25519", "Ed25519-CA-CSR");

    res.cleanup(&client).await;
}

// ===========================================================================
// Phase 7 — Negative tests
// ===========================================================================

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_negative_kem_self_sign_rejected() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let subject = "CN=KEM-SELF,O=Test".to_owned();
    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &None,
        &None,
        &None,
        &None,
        true,
        &Some(subject),
        Algorithm::MlKem768,
        &None,
        &None,
        365,
        &None,
        &[],
    )
    .unwrap();

    let result = client.certify(certify).await;
    assert!(result.is_err(), "ML-KEM self-sign should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("signing"),
        "Error should mention signing capability, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_negative_csr_without_issuer() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let csr_pem = include_bytes!("../../../test_data/certificates/csr/test_rsa2048.csr.pem");

    let certify = build_certify_request(
        VENDOR_ID_COSMIAN,
        &None,
        &Some("pem".to_owned()),
        &Some(csr_pem.to_vec()),
        &None,
        &None,
        false,
        &None,
        Algorithm::RSA2048,
        &None, // no issuer private key
        &None, // no issuer certificate
        365,
        &None,
        &[],
    )
    .unwrap();

    let result = client.certify(certify).await;
    assert!(result.is_err(), "CSR without issuer should be rejected");
}
