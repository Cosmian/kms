//! Lifecycle test for auto-rotation of a self-signed X.509 certificate.
//!
//! ## Scenario
//!
//! 1. Start a dedicated KMS server with `auto_rotation_check_interval_secs = 2`.
//! 2. Create an RSA-2048 key pair via `create_rsa_key_pair`.
//! 3. Issue a self-signed certificate for the public key via `certify`.
//! 4. Export the original certificate in PEM format and parse X.509 fields.
//! 5. Arm auto-rotation: `SetAttribute(RotateInterval = 4)`.
//! 6. Wait 10 s — the cron fires at least twice and triggers certificate renewal.
//! 7. Inspect `ReplacementObjectLink` on the old certificate.
//! 8. Export the new certificate in PEM format and compare X.509 fields using
//!    `compare_cert_rotation_x509()`:
//!    - DER bytes must differ.
//!    - Serial numbers must differ (fresh cert, new serial).
//!    - Subject CN must be preserved (same as the original).
//!    - Public key must differ (fresh key pair was generated).
//! 9. Verify KMIP rotation metadata on both old and new certs.

use std::time::Duration;

use cosmian_kms_cli_actions::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_operations::{GetAttributes, SetAttribute},
        kmip_types::{LinkType, UniqueIdentifier},
    },
    cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::CertificateExportFormat,
};
use openssl::{nid::Nid, x509::X509};
use tempfile::TempDir;
use test_kms_server::{
    AuthenticationOptions, BuildServerParamsOptions, ClientAuthOptions, MainDBConfig,
    ServerJwtAuth, ServerTlsMode, TestsContext, build_server_params_full, resolve_test_port,
    start_test_server_with_options,
};
use time::OffsetDateTime;

use super::{
    certify::{CertifyOp, certify},
    export::export_certificate,
};
use crate::{
    error::result::CosmianResult,
    tests::{
        rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
        save_kms_cli_config,
    },
};

// ─── Server helpers ───────────────────────────────────────────────────────────

/// Start a disposable KMS server with fast auto-rotation (`check_interval = 2 s`).
///
/// `preferred_port` is a hint; if the port is already in use (e.g. by a lingering
/// server from a previous failed test run), `resolve_test_port` falls back to an
/// OS-assigned free port, avoiding the "channel is empty and sending half is closed"
/// server-startup failure.
///
/// Port 10200 is chosen so that neither it nor its socket-server shadow
/// (`port + 100 = 10300`) conflict with any of the shared test servers
/// (`DEFAULT_KMS_SERVER_PORT` range 9998–10005, socket-server range 10098–10105).
async fn start_auto_rotation_server(preferred_port: u16) -> CosmianResult<TestsContext> {
    let port = resolve_test_port(preferred_port)?;
    let server_params = build_server_params_full(BuildServerParamsOptions {
        db_config: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            clear_database: true,
            ..MainDBConfig::default()
        },
        port,
        tls: ServerTlsMode::PlainHttp,
        jwt: ServerJwtAuth::Disabled,
        auto_rotation_check_interval_secs: 2,
        ..BuildServerParamsOptions::default()
    })?;

    Ok(start_test_server_with_options(
        MainDBConfig::default(),
        port,
        AuthenticationOptions {
            server_params: Some(server_params),
            client: ClientAuthOptions::default(),
        },
        None,
        None,
    )
    .await?)
}

// ─── X.509 field comparison helper ───────────────────────────────────────────

/// Compare two X.509 certificates produced by auto-rotation.
///
/// Asserts:
/// - DER bytes differ (the certificates are not identical).
/// - Serial numbers differ (fresh serial assigned by the server).
/// - Subject CN is preserved (same value, same structural length).
/// - Public key material differs (a new key pair was generated).
///
/// # Panics
///
/// Panics with a descriptive message if any assertion fails.
fn compare_cert_rotation_x509(old_pem: &[u8], new_pem: &[u8]) {
    let old_cert = X509::from_pem(old_pem).expect("old cert must parse as PEM");
    let new_cert = X509::from_pem(new_pem).expect("new cert must parse as PEM");

    let old_der = old_cert.to_der().expect("old cert to DER");
    let new_der = new_cert.to_der().expect("new cert to DER");

    // ── Bytes must differ ─────────────────────────────────────────────────────
    assert_ne!(
        old_der, new_der,
        "DER bytes of old and new certificate must differ"
    );

    // ── Serial numbers must differ ────────────────────────────────────────────
    let old_serial = old_cert
        .serial_number()
        .to_bn()
        .expect("old serial to BN")
        .to_dec_str()
        .expect("BN to dec string")
        .to_string();
    let new_serial = new_cert
        .serial_number()
        .to_bn()
        .expect("new serial to BN")
        .to_dec_str()
        .expect("BN to dec string")
        .to_string();
    assert_ne!(
        old_serial, new_serial,
        "serial number must change on certificate renewal"
    );

    // ── Subject CN must be preserved ──────────────────────────────────────────
    let get_cn = |cert: &X509| -> Option<String> {
        cert.subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
    };
    let old_cn = get_cn(&old_cert);
    let new_cn = get_cn(&new_cert);
    assert_eq!(
        old_cn, new_cn,
        "subject CN must be preserved across rotation (old={old_cn:?}, new={new_cn:?})"
    );

    // ── Subject entry count must be preserved ─────────────────────────────────
    assert_eq!(
        old_cert.subject_name().entries().count(),
        new_cert.subject_name().entries().count(),
        "subject name must have the same number of entries after rotation"
    );

    // ── Public key must differ ────────────────────────────────────────────────
    let old_pubkey = old_cert
        .public_key()
        .expect("old cert must have a public key")
        .public_key_to_der()
        .expect("old public key to DER");
    let new_pubkey = new_cert
        .public_key()
        .expect("new cert must have a public key")
        .public_key_to_der()
        .expect("new public key to DER");
    assert_ne!(
        old_pubkey, new_pubkey,
        "public key must change after certificate rotation (a new key pair is generated)"
    );
}

// ─── Lifecycle test ───────────────────────────────────────────────────────────

/// Full certificate auto-rotation lifecycle:
///
/// 1. Create RSA key pair + self-signed cert.
/// 2. Reset `initial_date` to now to control the rotation-timer origin.
/// 3. Arm auto-rotation with a 20 s interval.
/// 4. Poll for `ReplacementObjectLink` (every 2 s, 60 s timeout).
/// 5. Assert immediately upon detection — before any second rotation can fire.
/// 6. Verify KMIP links and X.509 field invariants.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certificate_auto_rotation_lifecycle() -> CosmianResult<()> {
    const PORT: u16 = 10_200;
    // Timing rationale:
    //   ROTATE_INTERVAL = 20 s, cron_tick = 2 s → first rotation fires at t_arm + 20-22 s.
    //   We detect it within the next 2 s poll → assertion runs at t_arm + 22-24 s.
    //   Second rotation fires at t_arm + 40 s → 16+ s margin. Safe under heavy load.
    const ROTATE_INTERVAL_SECS: i32 = 20;
    const POLL_INTERVAL: Duration = Duration::from_secs(2);
    const POLL_TIMEOUT: Duration = Duration::from_secs(60);
    const SUBJECT: &str = "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = RotationTest";

    let ctx = start_auto_rotation_server(PORT).await?;
    let (owner_conf_path, _) = save_kms_cli_config(&ctx);
    let client = ctx.get_owner_client();

    // ── Step 1: Create RSA key pair and self-signed certificate ───────────────
    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &owner_conf_path,
        &RsaKeyPairOptions {
            number_of_bits: Some(2048),
            ..Default::default()
        },
    )?;

    let old_cert_id = certify(
        &owner_conf_path,
        CertifyOp {
            public_key_id_to_certify: Some(public_key_id),
            subject_name: Some(SUBJECT.to_owned()),
            ..Default::default()
        },
    )?;

    // ── Step 2: Export the original certificate as PEM ────────────────────────
    let tmp_dir = TempDir::new()?;
    let old_pem_path = tmp_dir
        .path()
        .join("old_cert.pem")
        .to_string_lossy()
        .to_string();
    export_certificate(
        &owner_conf_path,
        &old_cert_id,
        &old_pem_path,
        Some(CertificateExportFormat::Pem),
        None,
        false,
    )?;
    let old_pem = std::fs::read(&old_pem_path)?;

    // ── Step 3: Reset initial_date to now, then arm auto-rotation ─────────────
    // Resetting initial_date ensures the rotation-timer origin is the moment we
    // arm rotation, regardless of when cert creation occurred.  This prevents
    // spurious double-rotation when the system is under heavy load during CI.
    let now = OffsetDateTime::now_utc();
    client
        .set_attribute(SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(old_cert_id.clone())),
            new_attribute: Attribute::InitialDate(now),
        })
        .await?;
    client
        .set_attribute(SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(old_cert_id.clone())),
            new_attribute: Attribute::RotateInterval(ROTATE_INTERVAL_SECS),
        })
        .await?;

    // ── Step 4: Poll for ReplacementObjectLink ────────────────────────────────
    // Poll every 2 s instead of a fixed sleep so we assert immediately when the
    // first rotation fires — well before any second rotation can occur.
    let poll_start = std::time::Instant::now();
    let (old_attrs_resp, new_cert_id) = loop {
        assert!(
            poll_start.elapsed() < POLL_TIMEOUT,
            "ReplacementObjectLink not set on the old certificate after {} s",
            POLL_TIMEOUT.as_secs()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
        let attrs_resp = client
            .get_attributes(GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(old_cert_id.clone())),
                attribute_reference: None,
            })
            .await?;
        if let Some(link) = attrs_resp
            .attributes
            .get_link(LinkType::ReplacementObjectLink)
        {
            let id = link.to_string();
            break (attrs_resp, id);
        }
    };

    // ── Step 5: Old cert assertions ───────────────────────────────────────────
    assert_ne!(
        new_cert_id, old_cert_id,
        "new certificate must have a different UID"
    );
    assert_eq!(
        old_attrs_resp.attributes.rotate_interval,
        Some(0),
        "old certificate must have rotate_interval = 0 after rotation"
    );

    // ── Step 6: New cert – links and metadata ─────────────────────────────────
    let new_attrs_resp = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(new_cert_id.clone())),
            attribute_reference: None,
        })
        .await?;
    let replaced_link = new_attrs_resp
        .attributes
        .get_link(LinkType::ReplacedObjectLink)
        .unwrap_or_else(|| {
            panic!(
                "ReplacedObjectLink must be set on the new certificate; \
                 attributes: {:?}",
                new_attrs_resp.attributes
            )
        });
    assert_eq!(
        replaced_link.to_string(),
        old_cert_id,
        "new certificate's ReplacedObjectLink must point back to the original"
    );
    // The auto-rotation cron transfers rotate_interval to the new cert.
    assert_eq!(
        new_attrs_resp.attributes.rotate_interval,
        Some(ROTATE_INTERVAL_SECS),
        "new certificate must inherit rotate_interval from the old one"
    );

    // ── Step 7: Export new certificate as PEM and compare X.509 fields ────────
    let new_pem_path = tmp_dir
        .path()
        .join("new_cert.pem")
        .to_string_lossy()
        .to_string();
    export_certificate(
        &owner_conf_path,
        &new_cert_id,
        &new_pem_path,
        Some(CertificateExportFormat::Pem),
        None,
        false,
    )?;
    let new_pem = std::fs::read(&new_pem_path)?;

    compare_cert_rotation_x509(&old_pem, &new_pem);

    Ok(())
}
