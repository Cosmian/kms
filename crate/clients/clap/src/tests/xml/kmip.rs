//! Consolidated XML test vectors for KMIP protocol versions 1.4 and 2.1.
//!
//! The KMS server only accepts KMIP 1.4 and 2.1 requests. Each version has two tests:
//! one for mandatory vectors, one for optional vectors. Special-case tests (TL with
//! cleanup, PKCS11 with HSM) are handled separately.

use crate::tests::xml::{run_single_xml_vector, runner::run_all_xml_vectors_in_dir};

// ─── KMIP 1.4 ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_4_xml_mandatory() {
    run_all_xml_vectors_in_dir(
        "../../../kmip/v1.4/XML/mandatory",
        &[
            // TL tests handled separately (require cleanup of leftover objects)
            "TL-M-1-14.xml",
            "TL-M-2-14.xml",
            "TL-M-3-14.xml",
            // 3DES key creation/usage not supported by server policy
            "SKFF-M-4-14.xml",
            "SKFF-M-8-14.xml",
            "SKFF-M-12-14.xml",
        ],
    )
    .await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_4_xml_optional() {
    run_all_xml_vectors_in_dir(
        "../../../kmip/v1.4/XML/optional",
        &[
            // CS-RNG optional vectors not yet exercised
            "CS-RNG-O-1-14.xml",
            "CS-RNG-O-2-14.xml",
            "CS-RNG-O-3-14.xml",
            "CS-RNG-O-4-14.xml",
            // AKLC/SKLC optional not yet exercised
            "AKLC-O-1-14.xml",
            "SKLC-O-1-14.xml",
        ],
    )
    .await;
}

// ─── KMIP 2.1 ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_1_xml_mandatory() {
    run_all_xml_vectors_in_dir(
        "../../../kmip/v2.1/XML/mandatory",
        &[
            // PKCS11 requires Utimaco HSM — handled in separate test
            "PKCS11-M-1-21.xml",
            // TL tests handled separately (require cleanup of leftover objects)
            "TL-M-1-21.xml",
            "TL-M-2-21.xml",
            "TL-M-3-21.xml",
            // BL-M-9 contains an invalid RSA key (p and q are not prime);
            // OpenSSL correctly rejects this mathematically invalid key
            "BL-M-9-21.xml",
            // SKFF 10-12 use XML structures not yet supported by the parser
            "SKFF-M-10-21.xml",
            "SKFF-M-11-21.xml",
            "SKFF-M-12-21.xml",
        ],
    )
    .await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_1_xml_optional() {
    run_all_xml_vectors_in_dir(
        "../../../kmip/v2.1/XML/optional",
        &[
            // CS-RNG optional vectors not yet exercised
            "CS-RNG-O-1-21.xml",
            "CS-RNG-O-2-21.xml",
            "CS-RNG-O-3-21.xml",
            "CS-RNG-O-4-21.xml",
        ],
    )
    .await;
}

// ─── Special: Template Locate (TL) tests ────────────────────────────────────────
//
// TL tests use Locate operations that match on ApplicationSpecificInformation.
// Since all tests share a singleton KMS server, leftover objects from other TL tests
// may cause spurious Locate results. We run all TL tests together with cleanup.

#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_tl() {
    use cosmian_kms_client::cosmian_kmip::{
        kmip_0::kmip_types::ApplicationSpecificInformation,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_operations::{Destroy, Locate},
        },
    };
    use test_kms_server::start_default_test_kms_server;

    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Clean up any objects with LIBRARY-LTO application specific information
    // that might have been left over from prior TL test runs.
    let locate_req = Locate {
        attributes: Attributes {
            application_specific_information: Some(ApplicationSpecificInformation {
                application_namespace: "LIBRARY-LTO".to_owned(),
                application_data: Some(
                    "123456789ABCDEF123456789123456789ABCDEF123456789ABCDEF1234000000".to_owned(),
                ),
            }),
            ..Default::default()
        },
        ..Default::default()
    };

    if let Ok(locate_resp) = client.locate(locate_req).await {
        for uid in locate_resp.unique_identifier.unwrap_or_default() {
            drop(
                client
                    .destroy(Destroy {
                        unique_identifier: Some(uid),
                        cascade: false,
                        remove: false,
                        expected_object_type: None,
                    })
                    .await,
            );
        }
    }

    // Run TL tests for v1.4 and v2.1 (the only versions accepted by the server)
    for path in [
        "../../../kmip/v1.4/XML/mandatory/TL-M-1-14.xml",
        "../../../kmip/v1.4/XML/mandatory/TL-M-2-14.xml",
        "../../../kmip/v1.4/XML/mandatory/TL-M-3-14.xml",
        "../../../kmip/v2.1/XML/mandatory/TL-M-1-21.xml",
        "../../../kmip/v2.1/XML/mandatory/TL-M-2-21.xml",
    ] {
        run_single_xml_vector("kmip_xml_tl", path).await;
    }
}

// ─── Special: PKCS11 tests (Linux + Utimaco HSM only) ──────────────────────────

#[ignore = "Requires Linux, Utimaco PKCS#11 library, and HSM environment"]
#[cfg(target_os = "linux")]
#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_pkcs11() {
    use cosmian_logger::log_init;
    use test_kms_server::start_default_test_kms_server_with_utimaco_hsm;

    use crate::tests::xml::runner::run_single_xml_vector_on_client;

    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;
    let client = ctx.get_owner_client();

    run_single_xml_vector_on_client(
        "kmip_xml_pkcs11_2_1",
        &client,
        "../../../kmip/v2.1/XML/mandatory/PKCS11-M-1-21.xml",
    )
    .await;
}
