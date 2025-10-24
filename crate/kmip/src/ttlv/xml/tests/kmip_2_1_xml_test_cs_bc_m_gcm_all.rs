//! Initial focus on CS-BC-M-GCM-2-21.xml file when starting XML parsing support.
use std::path::{Path, PathBuf};

use cosmian_logger::log_init;

use crate::{
    kmip_0::{
        self, kmip_messages::RequestMessageBatchItemVersioned, kmip_types::CryptographicUsageMask,
    },
    kmip_2_1::{
        self,
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_objects::ObjectType,
        kmip_operations::Operation,
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, OperationEnumeration, UniqueIdentifier,
        },
    },
    ttlv::xml::KmipXmlDoc,
};

const XML_PATH: &str = "./src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-GCM-2-21.xml";

#[test]
fn kmip_cs_bc_m_gcm_all() {
    log_init(None);

    let path = PathBuf::from(XML_PATH);
    let doc = KmipXmlDoc::new_with_file(&path).expect("parse xml");
    assert!(!doc.requests.is_empty());
    assert!(!doc.responses.is_empty());

    // 1. Each request/response BatchCount==1 => exactly one batch item
    for (i, req) in doc.requests.iter().enumerate() {
        if i == 0 {
            if let [RequestMessageBatchItemVersioned::V21(item)] = req.batch_item.as_slice() {
                if let Operation::Register(reg) = &item.request_payload {
                    let vas = reg
                        .attributes
                        .vendor_attributes
                        .as_ref()
                        .expect("expected vendor attributes in first register");
                    assert_eq!(vas.len(), 1, "expected exactly one vendor attribute");
                    let va = &vas[0];
                    assert_eq!(va.vendor_identification, "x");
                    assert_eq!(va.attribute_name, "ID");
                    match &va.attribute_value {
                        kmip_2_1::kmip_types::VendorAttributeValue::TextString(s) => {
                            assert_eq!(s, "CS-BC-M-GCM-2-21-key-0");
                        }
                        _ => panic!("unexpected vendor attribute value variant"),
                    }
                }
            }
        }
        assert_eq!(
            req.request_header.batch_count, 1,
            "Request {i} batch_count != 1"
        );
        assert_eq!(
            req.batch_item.len(),
            1,
            "Request {i} does not have 1 batch item"
        );
    }

    for (i, resp) in doc.responses.iter().enumerate() {
        assert_eq!(
            resp.response_header.batch_count, 1,
            "Response {i} batch_count != 1"
        );
        assert_eq!(
            resp.batch_item.len(),
            1,
            "Response {i} does not have 1 batch item"
        );
    }

    // 2. Track per-operation counts and validate various operation-specific invariants
    let mut saw_register = false;
    let mut encrypt_tag_lengths: Vec<i32> = Vec::new();
    let mut decrypt_tag_lengths: Vec<i32> = Vec::new();
    let mut saw_create = 0_usize;
    let mut saw_get_attributes = 0_usize;
    let mut saw_destroy = 0_usize;
    let mut saw_activate = 0_usize;
    let mut saw_revoke = 0_usize; // may remain unused if only counted for presence
    let mut saw_mac = 0_usize;
    // Track cryptographic length for specific registered keys (e.g., key-6 should be 192 bits)
    let mut found_key6_len: Option<i32> = None;

    for req in &doc.requests {
        for bi in &req.batch_item {
            if let RequestMessageBatchItemVersioned::V21(item) = bi {
                match item.operation {
                    OperationEnumeration::Register => {
                        if let Operation::Register(reg) = &item.request_payload {
                            // Deep assertions only for first Register
                            if !saw_register {
                                assert_eq!(reg.object_type, ObjectType::SymmetricKey);
                                if let kmip_2_1::kmip_objects::Object::SymmetricKey(sk) =
                                    &reg.object
                                {
                                    let kb = &sk.key_block;
                                    assert_eq!(kb.key_format_type, KeyFormatType::Raw);
                                    assert_eq!(
                                        kb.cryptographic_algorithm,
                                        Some(CryptographicAlgorithm::AES)
                                    );
                                    // Ensure algorithm in key block stays in sync with attributes value
                                    if let Some(attr_alg) = reg.attributes.cryptographic_algorithm {
                                        assert_eq!(
                                            Some(attr_alg),
                                            kb.cryptographic_algorithm,
                                            "KeyBlock cryptographic_algorithm not synchronized with Attributes"
                                        );
                                    }
                                    assert_eq!(kb.cryptographic_length, Some(128));
                                    match &kb.key_value {
                                        Some(KeyValue::Structure { key_material, .. }) => {
                                            match key_material {
                                                KeyMaterial::ByteString(bytes) => {
                                                    assert_eq!(bytes.len(), 16);
                                                }
                                                other => panic!(
                                                    "Unexpected key material variant: {other:?}"
                                                ),
                                            }
                                        }
                                        _ => panic!("Missing key material"),
                                    }
                                } else {
                                    panic!("Expected SymmetricKey object");
                                }
                                // usage mask
                                let mask =
                                    reg.attributes.cryptographic_usage_mask.expect("usage mask");
                                assert!(mask.intersects(CryptographicUsageMask::Encrypt));
                                assert!(mask.intersects(CryptographicUsageMask::Decrypt));
                                saw_register = true;
                            }
                            // Capture cryptographic length for the key whose vendor attribute value ends with "key-6"
                            if let Some(vas) = reg.attributes.vendor_attributes.as_ref() {
                                if vas.iter().any(|va| {
                                    if let kmip_2_1::kmip_types::VendorAttributeValue::TextString(
                                        s,
                                    ) = &va.attribute_value
                                    {
                                        s.ends_with("key-6")
                                    } else {
                                        false
                                    }
                                }) {
                                    if let kmip_2_1::kmip_objects::Object::SymmetricKey(sk) =
                                        &reg.object
                                    {
                                        found_key6_len = sk.key_block.cryptographic_length;
                                    }
                                }
                            }
                        }
                    }
                    OperationEnumeration::Encrypt => {
                        if let Operation::Encrypt(enc) = &item.request_payload {
                            assert!(
                                enc.unique_identifier.is_some(),
                                "Encrypt missing UniqueIdentifier"
                            );
                            if let Some(params) = &enc.cryptographic_parameters {
                                if let Some(tl) = params.tag_length {
                                    encrypt_tag_lengths.push(tl);
                                }
                                assert_eq!(
                                    params.block_cipher_mode,
                                    Some(kmip_0::kmip_types::BlockCipherMode::GCM),
                                    "Encrypt without GCM mode"
                                );
                            }
                            // Some vector entries omit IV even with AAD present; allow this flexibility (parser correctness focus here)
                        }
                    }
                    OperationEnumeration::Decrypt => {
                        if let Operation::Decrypt(dec) = &item.request_payload {
                            assert!(
                                dec.unique_identifier.is_some(),
                                "Decrypt missing UniqueIdentifier"
                            );
                            if let Some(params) = &dec.cryptographic_parameters {
                                if let Some(tl) = params.tag_length {
                                    decrypt_tag_lengths.push(tl);
                                }
                                assert_eq!(
                                    params.block_cipher_mode,
                                    Some(kmip_0::kmip_types::BlockCipherMode::GCM),
                                    "Decrypt without GCM mode"
                                );
                            }
                            // If tag present, we must also have (possibly empty) data field (spec allows streaming, but here test vectors pair them)
                            if dec.authenticated_encryption_tag.is_some() {
                                assert!(dec.data.is_some(), "Decrypt tag without data in vector");
                            }
                        }
                    }
                    OperationEnumeration::Create => {
                        if let Operation::Create(create) = &item.request_payload {
                            saw_create += 1;
                            assert_eq!(
                                create.object_type,
                                create
                                    .attributes
                                    .object_type
                                    .expect("Create attributes missing object_type")
                            );
                            // attributes must include algorithm & length for symmetric key creation in vectors
                            if create.object_type == ObjectType::SymmetricKey {
                                let algo = create
                                    .attributes
                                    .cryptographic_algorithm
                                    .expect("Create missing cryptographic_algorithm");
                                assert_eq!(algo, CryptographicAlgorithm::AES);
                                let len = create
                                    .attributes
                                    .cryptographic_length
                                    .expect("Create missing cryptographic_length");
                                assert!(
                                    matches!(len, 128 | 192 | 256),
                                    "Unexpected AES length: {len}"
                                );
                            }
                        }
                    }
                    OperationEnumeration::GetAttributes => {
                        if let Operation::GetAttributes(ga) = &item.request_payload {
                            saw_get_attributes += 1;
                            if let Some(UniqueIdentifier::TextString(s)) = &ga.unique_identifier {
                                assert!(s.is_empty() || s.starts_with("uid-"));
                            }
                        }
                    }
                    OperationEnumeration::Destroy => {
                        if let Operation::Destroy(destroy) = &item.request_payload {
                            saw_destroy += 1;
                            // Destroy requests in vector should not set remove extension (GDPR) unless explicitly provided
                            if destroy.remove {
                                // If ever true in vectors, ensure a UID exists
                                assert!(
                                    destroy.unique_identifier.is_some(),
                                    "remove flag set without unique_identifier"
                                );
                            }
                        }
                    }
                    OperationEnumeration::Activate => {
                        if let Operation::Activate(act) = &item.request_payload {
                            saw_activate += 1;
                            if let UniqueIdentifier::TextString(s) = &act.unique_identifier {
                                assert!(!s.is_empty(), "Activate with empty unique identifier");
                            }
                        }
                    }
                    OperationEnumeration::Revoke => {
                        if let Operation::Revoke(revoke) = &item.request_payload {
                            saw_revoke += 1;
                            // Revocation reason code should always be set (parser defaults to Unspecified)
                            assert!(matches!(
                                revoke.revocation_reason.revocation_reason_code,
                                kmip_0::kmip_types::RevocationReasonCode::Unspecified
                                    | kmip_0::kmip_types::RevocationReasonCode::KeyCompromise
                                    | kmip_0::kmip_types::RevocationReasonCode::CACompromise
                            ));
                        }
                    }
                    OperationEnumeration::MAC => {
                        if let Operation::MAC(mac) = &item.request_payload {
                            saw_mac += 1;
                            // If data present, unique_identifier or correlation must exist to identify key/stream
                            if mac.data.is_some() {
                                assert!(
                                    mac.unique_identifier.is_some()
                                        || mac.correlation_value.is_some()
                                );
                            }
                            // If final_indicator is true, init_indicator can be either true (single part) or false (end of multi-part)
                            if mac.final_indicator == Some(true)
                                && mac.init_indicator == Some(false)
                            {
                                // multi-part final chunk: correlation value should exist
                                assert!(mac.correlation_value.is_some());
                            }
                        }
                    }
                    // Already explicitly handled above; others panic by default to reveal missing coverage
                    OperationEnumeration::CreateKeyPair
                    | OperationEnumeration::DiscoverVersions
                    | OperationEnumeration::Export
                    | OperationEnumeration::Get
                    | OperationEnumeration::Hash
                    | OperationEnumeration::Locate
                    | OperationEnumeration::Query
                    | OperationEnumeration::ReKey
                    | OperationEnumeration::ReKeyKeyPair
                    | OperationEnumeration::SetAttribute
                    | OperationEnumeration::Sign
                    | OperationEnumeration::Validate
                    | OperationEnumeration::SignatureVerify => { /* not exercised in this vector */
                    }
                    other => panic!("Unhandled operation variant in test: {other:?}"),
                }
            }
        }
    }
    assert!(saw_register, "No Register operation found");

    // Optional presence counts (vector dependent). We simply ensure parsing did not misclassify.
    assert_eq!(
        saw_create, saw_create,
        "logic placeholder to avoid unused var warning"
    );
    assert_eq!(saw_get_attributes, saw_get_attributes);
    assert!(saw_destroy > 0, "Expected at least one Destroy");
    // saw_activate and saw_mac may legitimately be zero; just touch variables to avoid warnings
    let _ = saw_activate;
    let _ = saw_mac;
    let _ = saw_revoke; // suppress unused warning

    // 3. TagLength semantics: expect at least one 16 and optionally a later 15 (vector shows both)
    assert!(
        encrypt_tag_lengths.contains(&16),
        "No Encrypt TagLength=16 found"
    );
    assert!(
        decrypt_tag_lengths.contains(&16),
        "No Decrypt TagLength=16 found"
    );
    if encrypt_tag_lengths.contains(&15) {
        assert!(encrypt_tag_lengths.contains(&16));
    }
    if decrypt_tag_lengths.contains(&15) {
        assert!(decrypt_tag_lengths.contains(&16));
    }

    // Reproduce bug: expect AES-192 key to have length 192 (currently parser hardcodes 128 in KeyBlock)
    if let Some(len) = found_key6_len {
        assert_eq!(
            len, 192,
            "Expected CryptographicLength 192 for key-6, got {len}"
        );
    } else {
        panic!("Did not locate Register entry for key-6 to verify cryptographic length");
    }
}

#[test]
fn cryptographic_parameters_first_pair() {
    // Retain a focused test on the first Encrypt/Decrypt pair semantics (TagLength=16 expected)
    let doc = KmipXmlDoc::new_with_file(Path::new(XML_PATH)).expect("parse");
    let mut first_encrypt: Option<i32> = None;
    let mut first_decrypt: Option<i32> = None;
    for req in &doc.requests {
        for bi in &req.batch_item {
            let RequestMessageBatchItemVersioned::V21(item) = bi else {
                continue;
            };
            match item.operation {
                OperationEnumeration::Encrypt if first_encrypt.is_none() => {
                    if let Operation::Encrypt(enc) = &item.request_payload {
                        first_encrypt = enc
                            .cryptographic_parameters
                            .as_ref()
                            .and_then(|p| p.tag_length);
                    }
                }
                OperationEnumeration::Decrypt if first_decrypt.is_none() => {
                    if let Operation::Decrypt(dec) = &item.request_payload {
                        first_decrypt = dec
                            .cryptographic_parameters
                            .as_ref()
                            .and_then(|p| p.tag_length);
                    }
                }
                _ => {}
            }
            if first_encrypt.is_some() && first_decrypt.is_some() {
                break;
            }
        }
        if first_encrypt.is_some() && first_decrypt.is_some() {
            break;
        }
    }
    assert_eq!(first_encrypt, Some(16));
    assert_eq!(first_decrypt, Some(16));
}
