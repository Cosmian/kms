//! Regression tests for Veeam Backup & Replication KMIP 1.4 integration.
//!
//! ## Bug description
//!
//! Veeam Backup & Replication uses KMIP 1.4 (binary TTLV) for encryption key
//! management.  When Veeam called `Get` for a public key it received the
//! following exception from its own KMIP decoder:
//!
//! ```text
//! Unexpected Tag 66, expected Attribute (KmipUnexpectedTagException)
//!   at …DecodeAttributeStructure(List`1 al)
//!   at …DecodeKeyValue(List`1 al, KeyBlock keyBlock)
//! ```
//!
//! ## Root cause
//!
//! The Cosmian KMS was embedding *all* object-metadata attributes
//! (`State`, `UniqueIdentifier`, `Link`, `Name`, `CryptographicAlgorithm`, …)
//! as `Attribute` elements inside the `KeyValue` structure when converting a
//! KMIP-2.1 internal object to a KMIP-1.4 wire response.
//!
//! Veeam's `PublicKey`/`PrivateKey` `KeyValue` decoder accepts `KeyMaterial`
//! only — the moment it encounters the first `Attribute` (tag 0x420008) it
//! reports the unexpected tag and aborts the decode.
//!
//! ## Expert hypotheses — verdict
//!
//! A Cosmian KMS expert suggested two possible culprits ("Tag 66"):
//!
//! | Hypothesis | Tag | Verdict |
//! |---|---|---|
//! | H1 — `KeyFormatType` (decimal 66 = 0x42 → `0x420042`) | `0x420042` | **Wrong** — `KeyFormatType` is converted to the custom attribute `"y-unsupported-2_1-attribute"` during KMIP 2.1→1.4 conversion and then filtered out because its name starts with `"y-"`. It never reaches the wire. |
//! | H2 — `PrivateKeyUniqueIdentifier` (hex 0x66 → `0x420066`) | `0x420066` | **Wrong** — This tag never appears in a `GetResponse`. The private-key back-reference is encoded as a `Link` attribute wrapped in a standard `Attribute` (0x420008) structure; the link target tag is `LinkedObjectIdentifier` (0x42004C), not `PrivateKeyUniqueIdentifier` (0x420066). |
//!
//! The actual issue is that Veeam does not tolerate *any* `Attribute` element
//! inside `KeyValue` for asymmetric keys.  "Tag 66" is Veeam's internal enum
//! value for whatever tag it found after exhausting the fields it expected in
//! `KeyValue`.
//!
//! ## Fix
//!
//! `perform_response_tweaks()` in `crate/server/src/routes/kmip.rs` now sets
//! `KeyValue::Structure.attribute = None` for `PublicKey` and `PrivateKey`
//! objects whenever the KMIP major version is 1.

use cosmian_kms_logger::{info, log_init};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{CryptographicUsageMask, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_attributes::{Attribute, CryptographicAlgorithm},
        kmip_data_structures::{KeyValue, TemplateAttribute},
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::Object,
        kmip_operations::{CreateKeyPair, Destroy, Get, Operation},
        kmip_types::OperationEnumeration,
    },
    ttlv::{KmipFlavor, TTLV, from_ttlv, to_ttlv},
};

use crate::tests::ttlv_tests::{get_client, socket_client::SocketClient};

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Create a 2048-bit RSA key pair via KMIP 1.4 and return
/// `(private_key_id, public_key_id)`.
fn create_rsa_key_pair(client: &SocketClient) -> (String, String) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::CreateKeyPair,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::CreateKeyPair(CreateKeyPair {
                    common_template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                            Attribute::CryptographicLength(2048),
                        ]),
                    }),
                    private_key_template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![Attribute::CryptographicUsageMask(
                            CryptographicUsageMask::Sign,
                        )]),
                    }),
                    public_key_template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![Attribute::CryptographicUsageMask(
                            CryptographicUsageMask::Verify,
                        )]),
                    }),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("CreateKeyPair: request failed");

    assert_eq!(
        response.response_header.batch_count, 1,
        "CreateKeyPair: expected 1 batch item"
    );

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("CreateKeyPair: expected V14 response");
    };

    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "CreateKeyPair: unexpected status"
    );

    let Some(Operation::CreateKeyPairResponse(ckpr)) = &batch_item.response_payload else {
        panic!("CreateKeyPair: expected CreateKeyPairResponse payload");
    };

    (
        ckpr.private_key_unique_identifier.clone(),
        ckpr.public_key_unique_identifier.clone(),
    )
}

/// Send a KMIP 1.4 `Get` for `key_id` and return the response.
fn get_key(client: &SocketClient, key_id: &str) -> ResponseMessage {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Get,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Get(Get {
                    unique_identifier: Some(key_id.to_owned()),
                    key_format_type: None,
                    key_compression_type: None,
                    key_wrapping_specification: None,
                }),
                message_extension: None,
            },
        )],
    };

    client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Get: request failed")
}

/// Destroy a key by `key_id` via KMIP 1.4.
fn destroy_key(client: &SocketClient, key_id: &str) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Destroy,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Destroy(Destroy {
                    unique_identifier: key_id.to_owned(),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Destroy: request failed");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Destroy: expected V14 response");
    };

    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "Destroy key {key_id}: unexpected status"
    );
}

// ─── assertions ──────────────────────────────────────────────────────────────

/// Assert that a `GetResponse` for a KMIP-1.4 `PublicKey` or `PrivateKey`
/// contains **no** attributes inside `KeyValue` (Veeam compatibility).
///
/// Also verifies that:
/// - The `PrivateKeyUniqueIdentifier` tag bytes (`0x42 0x00 0x66`) are absent
///   from the entire wire-level response (refutes expert hypothesis H2).
/// - The TTLV byte stream can be fully round-tripped through decode → encode.
fn assert_no_key_value_attributes(response: &ResponseMessage, label: &str) {
    // ── raw-wire checks ───────────────────────────────────────────────────

    let response_ttlv: TTLV =
        to_ttlv(response).unwrap_or_else(|e| panic!("{label}: to_ttlv failed: {e}"));
    let response_bytes = response_ttlv
        .to_bytes(KmipFlavor::Kmip1)
        .unwrap_or_else(|e| panic!("{label}: to_bytes failed: {e}"));

    // H2 refutation: PrivateKeyUniqueIdentifier (0x420066) must not appear.
    assert!(
        !response_bytes.windows(3).any(|w| w == [0x42, 0x00, 0x66]),
        "{label}: Get response MUST NOT contain `PrivateKeyUniqueIdentifier` \
         tag bytes (0x42 0x00 0x66). Expert hypothesis H2 is refuted: this tag \
         never appears on the wire; the private-key back-reference uses a \
         `Link` attribute (tag 0x42004A) wrapped inside an `Attribute` (0x420008)."
    );

    // TTLV round-trip sanity: the bytes must be decodable without error.
    let decoded_ttlv = TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip1)
        .unwrap_or_else(|e| panic!("{label}: from_bytes round-trip failed: {e}"));
    drop(
        from_ttlv::<ResponseMessage>(decoded_ttlv)
            .unwrap_or_else(|e| panic!("{label}: from_ttlv failed: {e}")),
    );

    // ── structural checks ─────────────────────────────────────────────────

    assert_eq!(
        response.response_header.batch_count, 1,
        "{label}: expected 1 batch item"
    );

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("{label}: expected V14 batch item");
    };

    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "{label}: Get failed"
    );

    let Some(Operation::GetResponse(get_response)) = &batch_item.response_payload else {
        panic!("{label}: expected GetResponse payload");
    };

    // ── key-material checks ───────────────────────────────────────────────

    let key_value = match &get_response.object {
        Object::PublicKey(k) => k.key_block.key_value.as_ref(),
        Object::PrivateKey(k) => k.key_block.key_value.as_ref(),
        other => panic!("{label}: expected PublicKey or PrivateKey, got {other:?}"),
    };

    let Some(KeyValue::Structure { attribute, .. }) = key_value else {
        panic!("{label}: expected KeyValue::Structure");
    };

    // ── THE CORE REGRESSION ASSERTION ─────────────────────────────────────
    //
    // Pre-fix: `attribute` was `Some([ActivationDate, CryptographicAlgorithm,
    //   CryptographicLength, CryptographicUsageMask, Fresh, InitialDate,
    //   Link(PrivateKeyLink/PublicKeyLink), Name, ObjectType, State,
    //   UniqueIdentifier])`.
    // This caused Veeam's KMIP decoder to emit "Unexpected Tag 66, expected
    // Attribute" and abort the `GetResponse` decode.
    //
    // Post-fix: `attribute` must be `None`.
    assert!(
        attribute.is_none(),
        "{label}: KMIP 1.4 Get response for an asymmetric key MUST NOT include \
         attributes inside KeyValue (Veeam Backup & Replication compatibility). \
         Attributes found: {attribute:?}"
    );
}

// ─── test ────────────────────────────────────────────────────────────────────

/// **Regression test — Veeam KMIP 1.4 integration.**
///
/// Verifies that a KMIP 1.4 `GetResponse` for an RSA `PublicKey` (and
/// `PrivateKey`) contains **no** attributes inside the `KeyValue` structure,
/// which is required for Veeam Backup & Replication to decode the response
/// successfully.
#[test]
fn test_veeam_get_asymmetric_key_no_attributes_in_key_value() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();

    // Create a fresh RSA-2048 key pair via KMIP 1.4.
    let (private_key_id, public_key_id) = create_rsa_key_pair(&client);
    info!("Created RSA key pair: private={private_key_id}, public={public_key_id}");

    // Get the public key and assert no attributes appear in KeyValue.
    let pub_key_response = get_key(&client, &public_key_id);
    assert_no_key_value_attributes(&pub_key_response, "PublicKey");

    // Get the private key and assert no attributes appear in KeyValue.
    let priv_key_response = get_key(&client, &private_key_id);
    assert_no_key_value_attributes(&priv_key_response, "PrivateKey");

    // Clean up.
    destroy_key(&client, &private_key_id);
    destroy_key(&client, &public_key_id);

    info!("Veeam regression test passed: no attributes in KeyValue for asymmetric keys");
}
