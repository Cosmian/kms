//! PQC (Post-Quantum Cryptography) certificate tests — ported from clap action-level tests.
//!
//! Tests ML-DSA, SLH-DSA, ML-KEM certificate creation and X.509 compliance
//! (RFC 9881, RFC 9935, RFC 9608).

use cosmian_kms_cli_actions::reexport::{
    cosmian_kmip::ttlv::{TTLV, from_ttlv},
    cosmian_kms_client::{
        cosmian_kmip::kmip_2_1::{kmip_objects::Object, kmip_types::LinkType},
        kmip_2_1::{kmip_attributes::Attributes, kmip_objects::Certificate},
        read_from_json_file, read_object_from_json_ttlv_file,
        reexport::cosmian_kms_client_utils::{
            certificate_utils::Algorithm, export_utils::CertificateExportFormat,
        },
    },
};
use openssl::x509::X509;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;
use x509_parser::{der_parser::oid, prelude::*};

use crate::{
    error::result::CosmianResult,
    tests::{
        certificates::{
            certify::{CertifyOp, certify},
            export::export_certificate,
            validate::validate_certificate,
        },
        utils::{owner_config, run_ckms_expect_error},
    },
};

/// Export a PQC certificate and parse it with `x509_parser`.
/// Returns (Object, Attributes, DER bytes).
fn fetch_pqc_certificate(
    cli_conf_path: &str,
    certificate_id: &str,
    expected_cn: &str,
) -> (Object, Attributes, Vec<u8>) {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    let exported_cert_file = tmp_path.join("pqc_cert.json");

    export_certificate(
        cli_conf_path,
        certificate_id,
        exported_cert_file.to_str().unwrap(),
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true,
    )
    .unwrap();

    let cert = read_object_from_json_ttlv_file(&exported_cert_file).unwrap();
    let cert_x509_der = match &cert {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => certificate_value,
        _ => panic!("wrong object type"),
    }
    .clone();

    let (_, parsed) =
        X509Certificate::from_der(&cert_x509_der).expect("failed to parse PQC certificate DER");
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .expect("certificate has no Common Name")
        .as_str()
        .expect("CN is not valid UTF-8");
    assert_eq!(cn, expected_cn);

    let ttlv: TTLV = read_from_json_file(&tmp_path.join("pqc_cert.attributes.json")).unwrap();
    let cert_attributes: Attributes = from_ttlv(ttlv).unwrap();
    (cert, cert_attributes, cert_x509_der)
}

/// Self-signed PQC certificate creation + basic link verification.
fn certify_pqc_self_signed(
    cli_conf_path: &str,
    algorithm: Algorithm,
    alg_label: &str,
) -> CosmianResult<()> {
    let cn = format!("Test PQC {alg_label}");
    let subject_name = format!("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = {cn}");

    let certificate_id = certify(
        cli_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(algorithm),
            subject_name: Some(subject_name),
            tags: Some(vec![format!(
                "pqc_{}_cert",
                alg_label.to_lowercase().replace(['-', ' '], "_")
            )]),
            ..CertifyOp::default()
        },
    )?;

    let (_, attributes, _) = fetch_pqc_certificate(cli_conf_path, &certificate_id, &cn);
    let certificate_link = attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);
    let public_key_id = attributes.get_link(LinkType::PublicKeyLink).unwrap();
    assert!(!public_key_id.to_string().is_empty());

    // Validate certificate
    let output = validate_certificate(cli_conf_path, "certificates", vec![certificate_id], None)?;
    assert!(
        output.contains("Valid"),
        "certificate must validate as Valid"
    );

    Ok(())
}

/// Create an ML-DSA-44 CA and return (`cert_id`, `private_key_id`).
fn create_ml_dsa_ca(cli_conf_path: &str) -> CosmianResult<(String, String)> {
    let ca_cert_id = certify(
        cli_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-KEM Test CA".to_owned(),
            ),
            tags: Some(vec!["mlkem_ca_cert".to_owned()]),
            ..CertifyOp::default()
        },
    )?;
    let (_, ca_attrs, _) = fetch_pqc_certificate(cli_conf_path, &ca_cert_id, "ML-KEM Test CA");
    let ca_sk_id = ca_attrs.get_link(LinkType::PrivateKeyLink).unwrap();
    Ok((ca_cert_id, ca_sk_id.to_string()))
}

/// Issue a certificate with a KEM algorithm using the given CA.
fn certify_ml_kem_ca_issued(
    cli_conf_path: &str,
    algorithm: Algorithm,
    cn: &str,
    tag: &str,
    ca_cert_id: &str,
    ca_sk_id: &str,
) -> CosmianResult<String> {
    certify(
        cli_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(algorithm),
            subject_name: Some(format!(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = {cn}"
            )),
            issuer_private_key_id: Some(ca_sk_id.to_owned()),
            issuer_certificate_id: Some(ca_cert_id.to_owned()),
            tags: Some(vec![tag.to_owned()]),
            ..CertifyOp::default()
        },
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQC TLS server connectivity test
// ═══════════════════════════════════════════════════════════════════════════════

/// Prove the KMS server correctly serves HTTPS with an ML-DSA-44 TLS certificate
/// and that `ckms` (using OpenSSL 3.6.2) can natively perform KMIP operations
/// over the PQC TLS connection — no special client needed.
#[tokio::test]
async fn test_server_with_pqc_tls_cert() -> CosmianResult<()> {
    use test_kms_server::start_test_kms_server_with_pqc_tls;

    use crate::tests::utils::{load_client_config, run_ckms};

    let ctx = start_test_kms_server_with_pqc_tls().await;
    let conf = load_client_config("pqc_tls_owner.toml", ctx);

    // 1. Verify basic connectivity over PQC TLS: ckms server version
    let version_output = run_ckms(&conf, &["server", "version"])?;
    assert!(
        !version_output.is_empty(),
        "Expected non-empty version output over PQC TLS"
    );

    // 2. Perform a KMIP Create (SymmetricKey) over PQC TLS via ckms
    let create_output = run_ckms(
        &conf,
        &[
            "sym",
            "keys",
            "create",
            "--algorithm",
            "aes",
            "--number-of-bits",
            "256",
        ],
    )?;
    // Output should contain a UUID-style unique identifier
    assert!(
        create_output.contains('-'),
        "KMIP Create over PQC TLS should return a unique ID: {create_output}"
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA self-signed tests
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_pqc_ml_dsa_44_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::MlDsa44, "ML-DSA-44")
}

#[tokio::test]
async fn test_certify_pqc_ml_dsa_65_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::MlDsa65, "ML-DSA-65")
}

#[tokio::test]
async fn test_certify_pqc_ml_dsa_87_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::MlDsa87, "ML-DSA-87")
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA CA-signed tests
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_pqc_ml_dsa_signed_by_pqc_ca() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    // Step 1: Create self-signed ML-DSA-44 root CA
    let ca_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = PQC Test CA".to_owned(),
            ),
            tags: Some(vec!["pqc_ca_cert".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let (_, ca_attributes, _) = fetch_pqc_certificate(&owner_conf, &ca_cert_id, "PQC Test CA");
    let ca_private_key_id = ca_attributes.get_link(LinkType::PrivateKeyLink).unwrap();

    // Step 2: Issue ML-DSA-65 leaf signed by the ML-DSA-44 CA
    let leaf_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa65),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = PQC Test Leaf".to_owned(),
            ),
            issuer_private_key_id: Some(ca_private_key_id.to_string()),
            issuer_certificate_id: Some(ca_cert_id.clone()),
            tags: Some(vec!["pqc_leaf_cert".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let (_, leaf_attributes, _) =
        fetch_pqc_certificate(&owner_conf, &leaf_cert_id, "PQC Test Leaf");
    let cert_link = leaf_attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(cert_link.to_string(), ca_cert_id);
    let _leaf_pub_key_id = leaf_attributes.get_link(LinkType::PublicKeyLink).unwrap();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM CA-issued tests
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_ml_kem_512_ca_issued() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf)?;

    let cert_id = certify_ml_kem_ca_issued(
        &owner_conf,
        Algorithm::MlKem512,
        "ML-KEM-512 Subject",
        "ml_kem_512_cert",
        &ca_cert_id,
        &ca_sk_id,
    )?;

    let (_, attrs, _) = fetch_pqc_certificate(&owner_conf, &cert_id, "ML-KEM-512 Subject");
    let issuer_link = attrs.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(issuer_link.to_string(), ca_cert_id);
    assert!(
        !attrs
            .get_link(LinkType::PublicKeyLink)
            .unwrap()
            .to_string()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn test_certify_ml_kem_768_ca_issued() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf)?;

    let cert_id = certify_ml_kem_ca_issued(
        &owner_conf,
        Algorithm::MlKem768,
        "ML-KEM-768 Subject",
        "ml_kem_768_cert",
        &ca_cert_id,
        &ca_sk_id,
    )?;

    let (_, attrs, _) = fetch_pqc_certificate(&owner_conf, &cert_id, "ML-KEM-768 Subject");
    let issuer_link = attrs.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(issuer_link.to_string(), ca_cert_id);
    Ok(())
}

#[tokio::test]
async fn test_certify_ml_kem_1024_ca_issued() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf)?;

    let cert_id = certify_ml_kem_ca_issued(
        &owner_conf,
        Algorithm::MlKem1024,
        "ML-KEM-1024 Subject",
        "ml_kem_1024_cert",
        &ca_cert_id,
        &ca_sk_id,
    )?;

    let (_, attrs, _) = fetch_pqc_certificate(&owner_conf, &cert_id, "ML-KEM-1024 Subject");
    let issuer_link = attrs.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(issuer_link.to_string(), ca_cert_id);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Negative tests: ML-KEM self-sign + unsupported formats
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_ml_kem_self_signed_is_rejected() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let err = run_ckms_expect_error(
        &owner_conf,
        &[
            "certificates",
            "certify",
            "--generate-key-pair",
            "--algorithm",
            "ml-kem-512",
            "--subject-name",
            "C = FR, CN = Self-Signed KEM",
        ],
    )?;

    let msg = err.to_lowercase();
    assert!(
        msg.contains("kem") || msg.contains("sign"),
        "expected a KEM/signing error, got: {err}"
    );
    Ok(())
}

/// Helper: test that a KEM/hybrid algorithm cert creation fails with unsupported format error.
fn assert_certify_format_unsupported(
    cli_conf_path: &str,
    algorithm: Algorithm,
    cn: &str,
    ca_cert_id: &str,
    ca_sk_id: &str,
) {
    use clap::ValueEnum;
    let algo_name = algorithm
        .to_possible_value()
        .expect("valid Algorithm")
        .get_name()
        .to_string();

    let err = run_ckms_expect_error(
        cli_conf_path,
        &[
            "certificates",
            "certify",
            "--generate-key-pair",
            "--algorithm",
            &algo_name,
            "--subject-name",
            &format!("C = FR, CN = {cn}"),
            "--issuer-private-key-id",
            ca_sk_id,
            "--issuer-certificate-id",
            ca_cert_id,
        ],
    )
    .expect("command should run");

    assert!(
        !err.is_empty(),
        "{cn} subject key should not be encodable as X.509 SPKI"
    );
}

#[tokio::test]
async fn test_certify_x25519_ml_kem_768_format_unsupported() {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf).unwrap();
    assert_certify_format_unsupported(
        &owner_conf,
        Algorithm::X25519MlKem768,
        "X25519MLKEM768 Subject",
        &ca_cert_id,
        &ca_sk_id,
    );
}

#[tokio::test]
async fn test_certify_x448_ml_kem_1024_format_unsupported() {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf).unwrap();
    assert_certify_format_unsupported(
        &owner_conf,
        Algorithm::X448MlKem1024,
        "X448MLKEM1024 Subject",
        &ca_cert_id,
        &ca_sk_id,
    );
}

#[tokio::test]
async fn test_certify_ml_kem_512_p256_format_unsupported() {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf).unwrap();
    assert_certify_format_unsupported(
        &owner_conf,
        Algorithm::MlKem512P256,
        "MlKem512P256 Subject",
        &ca_cert_id,
        &ca_sk_id,
    );
}

#[tokio::test]
async fn test_certify_ml_kem_768_p256_format_unsupported() {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf).unwrap();
    assert_certify_format_unsupported(
        &owner_conf,
        Algorithm::MlKem768P256,
        "MlKem768P256 Subject",
        &ca_cert_id,
        &ca_sk_id,
    );
}

#[tokio::test]
async fn test_certify_ml_kem_512_curve25519_format_unsupported() {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf).unwrap();
    assert_certify_format_unsupported(
        &owner_conf,
        Algorithm::MlKem512Curve25519,
        "MlKem512Curve25519 Subject",
        &ca_cert_id,
        &ca_sk_id,
    );
}

#[tokio::test]
async fn test_certify_ml_kem_768_curve25519_format_unsupported() {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf).unwrap();
    assert_certify_format_unsupported(
        &owner_conf,
        Algorithm::MlKem768Curve25519,
        "MlKem768Curve25519 Subject",
        &ca_cert_id,
        &ca_sk_id,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLH-DSA self-signed tests
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_128s_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::SlhDsaSha2128s, "SLH-DSA-SHA2-128s")
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_128f_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::SlhDsaSha2128f, "SLH-DSA-SHA2-128f")
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_192s_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::SlhDsaSha2192s, "SLH-DSA-SHA2-192s")
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_192f_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::SlhDsaSha2192f, "SLH-DSA-SHA2-192f")
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_256s_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::SlhDsaSha2256s, "SLH-DSA-SHA2-256s")
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_256f_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(&owner_conf, Algorithm::SlhDsaSha2256f, "SLH-DSA-SHA2-256f")
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_128s_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(
        &owner_conf,
        Algorithm::SlhDsaShake128s,
        "SLH-DSA-SHAKE-128s",
    )
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_128f_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(
        &owner_conf,
        Algorithm::SlhDsaShake128f,
        "SLH-DSA-SHAKE-128f",
    )
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_192s_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(
        &owner_conf,
        Algorithm::SlhDsaShake192s,
        "SLH-DSA-SHAKE-192s",
    )
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_192f_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(
        &owner_conf,
        Algorithm::SlhDsaShake192f,
        "SLH-DSA-SHAKE-192f",
    )
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_256s_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(
        &owner_conf,
        Algorithm::SlhDsaShake256s,
        "SLH-DSA-SHAKE-256s",
    )
}

#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_256f_self_signed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    certify_pqc_self_signed(
        &owner_conf,
        Algorithm::SlhDsaShake256f,
        "SLH-DSA-SHAKE-256f",
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-algorithm: SLH-DSA CA signs ML-DSA leaf
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_pqc_slh_dsa_ca_signs_ml_dsa_leaf() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let ca_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::SlhDsaSha2128s),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = SLH-DSA Test CA".to_owned(),
            ),
            tags: Some(vec!["slh_dsa_ca_cert".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let (_, ca_attributes, _) = fetch_pqc_certificate(&owner_conf, &ca_cert_id, "SLH-DSA Test CA");
    let ca_private_key_id = ca_attributes.get_link(LinkType::PrivateKeyLink).unwrap();

    let leaf_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-DSA Leaf".to_owned(),
            ),
            issuer_private_key_id: Some(ca_private_key_id.to_string()),
            issuer_certificate_id: Some(ca_cert_id.clone()),
            tags: Some(vec!["ml_dsa_leaf_cert".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let (_, leaf_attributes, _) = fetch_pqc_certificate(&owner_conf, &leaf_cert_id, "ML-DSA Leaf");
    let cert_link = leaf_attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(cert_link.to_string(), ca_cert_id);
    assert!(
        !leaf_attributes
            .get_link(LinkType::PublicKeyLink)
            .unwrap()
            .to_string()
            .is_empty()
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// X.509 structural compliance tests
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_pqc_x509_structural_compliance() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = PQC X509 Compliance Test"
                    .to_owned(),
            ),
            tags: Some(vec!["pqc_x509_compliance".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let (_, _, der) = fetch_pqc_certificate(&owner_conf, &cert_id, "PQC X509 Compliance Test");
    let (_, cert) = X509Certificate::from_der(&der).expect("failed to parse DER as X.509");

    assert_eq!(cert.tbs_certificate.version, X509Version::V3);

    let ml_dsa_44 = oid!(2.16.840.1.101.3.4.3.17);
    assert_eq!(cert.signature_algorithm.algorithm, ml_dsa_44);
    assert_eq!(cert.tbs_certificate.signature.algorithm, ml_dsa_44);
    assert_eq!(
        cert.tbs_certificate.subject_pki.algorithm.algorithm,
        ml_dsa_44
    );

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(cn, "PQC X509 Compliance Test");

    assert_eq!(
        cert.tbs_certificate.issuer.to_string(),
        cert.tbs_certificate.subject.to_string()
    );
    assert!(cert.tbs_certificate.validity.not_before < cert.tbs_certificate.validity.not_after);

    Ok(())
}

#[tokio::test]
async fn test_pqc_ca_signature_verification() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let ca_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-DSA-44 PQC Root CA".to_owned(),
            ),
            tags: Some(vec!["pqc_sig_verify_ca".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let (_, ca_attrs, ca_der) =
        fetch_pqc_certificate(&owner_conf, &ca_cert_id, "ML-DSA-44 PQC Root CA");
    let ca_private_key_id = ca_attrs.get_link(LinkType::PrivateKeyLink).unwrap();

    let leaf_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa65),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-DSA-65 PQC Leaf".to_owned(),
            ),
            issuer_private_key_id: Some(ca_private_key_id.to_string()),
            issuer_certificate_id: Some(ca_cert_id.clone()),
            tags: Some(vec!["pqc_sig_verify_leaf".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let (_, leaf_attrs, leaf_der) =
        fetch_pqc_certificate(&owner_conf, &leaf_cert_id, "ML-DSA-65 PQC Leaf");

    let issuer_link = leaf_attrs.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(issuer_link.to_string(), ca_cert_id);

    let (_, ca_x509p) = X509Certificate::from_der(&ca_der).unwrap();
    let (_, leaf_x509p) = X509Certificate::from_der(&leaf_der).unwrap();
    assert_eq!(
        leaf_x509p.tbs_certificate.issuer.to_string(),
        ca_x509p.tbs_certificate.subject.to_string()
    );

    // OpenSSL cryptographic signature verification
    let ca_x509 = X509::from_der(&ca_der).unwrap();
    let leaf_x509 = X509::from_der(&leaf_der).unwrap();
    let ca_pub_key = ca_x509.public_key().unwrap();
    let signature_valid = leaf_x509.verify(&ca_pub_key).unwrap();
    assert!(signature_valid);

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 9881 (ML-DSA) and RFC 9935 (ML-KEM) key usage compliance
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_rfc9881_ml_dsa_key_usage_critical_digital_signature() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = RFC9881 KU Test".to_owned(),
            ),
            ..CertifyOp::default()
        },
    )?;

    let (_, _, der) = fetch_pqc_certificate(&owner_conf, &cert_id, "RFC9881 KU Test");
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    let ku_ext = cert
        .tbs_certificate
        .extensions()
        .iter()
        .find(|e| e.oid == oid!(2.5.29.15))
        .expect("keyUsage extension must be present");

    assert!(ku_ext.critical, "RFC 9881: keyUsage must be critical");
    if let ParsedExtension::KeyUsage(ku) = ku_ext.parsed_extension() {
        assert!(
            ku.flags & 1 != 0,
            "digitalSignature bit must be set, got flags={}",
            ku.flags
        );
    } else {
        panic!("Expected ParsedExtension::KeyUsage");
    }
    Ok(())
}

#[tokio::test]
async fn test_rfc9935_ml_kem_key_usage_critical_key_encipherment_only() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf)?;

    let cert_id = certify_ml_kem_ca_issued(
        &owner_conf,
        Algorithm::MlKem512,
        "RFC9935 KU Test",
        "rfc9935_ku_test",
        &ca_cert_id,
        &ca_sk_id,
    )?;

    let (_, _, der) = fetch_pqc_certificate(&owner_conf, &cert_id, "RFC9935 KU Test");
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    let ku_ext = cert
        .tbs_certificate
        .extensions()
        .iter()
        .find(|e| e.oid == oid!(2.5.29.15))
        .expect("keyUsage extension must be present");

    assert!(ku_ext.critical, "RFC 9935: keyUsage must be critical");
    if let ParsedExtension::KeyUsage(ku) = ku_ext.parsed_extension() {
        assert!(
            ku.flags & 4 != 0,
            "keyEncipherment bit must be set, got flags={}",
            ku.flags
        );
        assert_eq!(
            ku.flags, 4,
            "RFC 9935: ONLY keyEncipherment must be set, got flags={}",
            ku.flags
        );
    } else {
        panic!("Expected ParsedExtension::KeyUsage");
    }
    Ok(())
}

#[tokio::test]
async fn test_rfc9935_ml_kem_spki_oid() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(&owner_conf)?;

    let cert_id = certify_ml_kem_ca_issued(
        &owner_conf,
        Algorithm::MlKem512,
        "RFC9935 SPKI OID Test",
        "rfc9935_spki_test",
        &ca_cert_id,
        &ca_sk_id,
    )?;

    let (_, _, der) = fetch_pqc_certificate(&owner_conf, &cert_id, "RFC9935 SPKI OID Test");
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    let ml_kem_512_oid = oid!(2.16.840.1.101.3.4.4.1);
    assert_eq!(
        cert.tbs_certificate.subject_pki.algorithm.algorithm,
        ml_kem_512_oid
    );
    Ok(())
}

#[tokio::test]
async fn test_rfc9881_ml_dsa_87_key_usage() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa87),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = RFC9881 ML-DSA-87 KU".to_owned(),
            ),
            ..CertifyOp::default()
        },
    )?;

    let (_, _, der) = fetch_pqc_certificate(&owner_conf, &cert_id, "RFC9881 ML-DSA-87 KU");
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    let ku_ext = cert
        .tbs_certificate
        .extensions()
        .iter()
        .find(|e| e.oid == oid!(2.5.29.15))
        .expect("keyUsage must be present");

    assert!(ku_ext.critical);
    if let ParsedExtension::KeyUsage(ku) = ku_ext.parsed_extension() {
        assert!(
            ku.flags & 1 != 0,
            "digitalSignature must be set, got flags={}",
            ku.flags
        );
    } else {
        panic!("Expected ParsedExtension::KeyUsage");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 9608: noRevAvail extension tests
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_pqc_self_signed_no_rev_avail() -> CosmianResult<()> {
    const NO_REV_AVAIL: &[u8] = &[0x55, 0x1d, 0x38]; // OID 2.5.29.56
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = noRevAvail Test".to_owned(),
            ),
            ..CertifyOp::default()
        },
    )?;

    let (_, _, der) = fetch_pqc_certificate(&owner_conf, &cert_id, "noRevAvail Test");
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    let has_no_rev_avail = cert
        .extensions()
        .iter()
        .any(|ext| ext.oid.as_bytes() == NO_REV_AVAIL);
    assert!(
        has_no_rev_avail,
        "RFC 9608: id-ce-noRevAvail (OID 2.5.29.56) must be present"
    );
    Ok(())
}

#[cfg(not(windows))]
#[tokio::test]
async fn test_certify_no_rev_avail_openssl_compat() -> CosmianResult<()> {
    use cosmian_logger::info;

    let ver_out = tokio::process::Command::new("openssl")
        .arg("version")
        .output()
        .await;
    let Ok(ver_out) = ver_out else {
        info!("openssl CLI not found, skipping");
        return Ok(());
    };
    if !ver_out.status.success() {
        info!("openssl version failed, skipping");
        return Ok(());
    }
    let ver_str = String::from_utf8_lossy(&ver_out.stdout);
    if !ver_str.to_lowercase().contains("openssl 3") {
        info!("not OpenSSL 3 ({ver_str}), skipping");
        return Ok(());
    }

    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some("C = FR, CN = noRevAvail OpenSSL compat test".to_owned()),
            ..CertifyOp::default()
        },
    )?;

    let (_, _, der) =
        fetch_pqc_certificate(&owner_conf, &cert_id, "noRevAvail OpenSSL compat test");

    let tmp_dir = TempDir::new()?;
    let cert_file = tmp_dir.path().join("cert.der");
    std::fs::write(&cert_file, &der)?;

    let output = tokio::process::Command::new("openssl")
        .args(["x509", "-noout", "-text", "-inform", "DER", "-in"])
        .arg(&cert_file)
        .output()
        .await?;

    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(
        text.contains("No Revocation") || text.contains("2.5.29.56"),
        "Expected noRevAvail in openssl output"
    );
    assert!(
        !text.contains("1.3.6.1.5.5.7.1.56"),
        "Wrong OID in openssl output"
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// AIA extension test
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_certify_with_aia_extension() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    let ca_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa44),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = AIA Test CA".to_owned(),
            ),
            ..CertifyOp::default()
        },
    )?;
    let (_, ca_attrs, _) = fetch_pqc_certificate(&owner_conf, &ca_cert_id, "AIA Test CA");
    let ca_sk_id = ca_attrs.get_link(LinkType::PrivateKeyLink).unwrap();

    // Write extension config with AIA
    let tmp_dir = TempDir::new().unwrap();
    let ext_file = tmp_dir.path().join("aia_ext.cnf");
    std::fs::write(
        &ext_file,
        b"[v3_ca]\nauthorityInfoAccess=OCSP;URI:http://ocsp.example.com/\n",
    )
    .unwrap();

    let leaf_cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::MlDsa65),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = AIA Test Leaf".to_owned(),
            ),
            issuer_private_key_id: Some(ca_sk_id.to_string()),
            issuer_certificate_id: Some(ca_cert_id),
            certificate_extensions: Some(ext_file),
            ..CertifyOp::default()
        },
    )?;

    let (_, _, der) = fetch_pqc_certificate(&owner_conf, &leaf_cert_id, "AIA Test Leaf");
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    let has_aia = cert
        .extensions()
        .iter()
        .any(|ext| ext.oid == oid!(1.3.6.1.5.5.7.1.1));
    assert!(has_aia, "authorityInfoAccess extension must be present");
    Ok(())
}
